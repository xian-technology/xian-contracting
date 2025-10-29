from unittest import TestCase
import os
import hashlib
from nacl.bindings import (
    crypto_core_ristretto255_from_hash,
    crypto_core_ristretto255_scalar_reduce,
    crypto_core_ristretto255_add,
    crypto_core_ristretto255_sub,
    crypto_scalarmult_ristretto255,
    crypto_scalarmult_ristretto255_base,
)
# Import the module under test
# Adjust the import if your test runner uses a different sys.path
from contracting.stdlib.bridge import crypto as C


# === Helpers (mirror the module’s internal derivations) ======================

def _scalar_reduce_from_bytes(b: bytes) -> bytes:
    return crypto_core_ristretto255_scalar_reduce(b)

def _scalar_from_u128(v: int) -> bytes:
    return _scalar_reduce_from_bytes(v.to_bytes(64, "little"))

# Fixed H generator (must match module)
_H_HASH = hashlib.sha512(b"XIAN|crypto.pedersen|H").digest()
H_POINT = crypto_core_ristretto255_from_hash(_H_HASH)  # bytes (32)
G_POINT = crypto_scalarmult_ristretto255_base(_scalar_from_u128(1))

def _r_scalar_from_blinding_hex(blind_hex: str) -> bytes:
    seed = bytes.fromhex(blind_hex)
    r64 = hashlib.sha512(b"XIAN|crypto.pedersen|r|" + seed).digest()
    return _scalar_reduce_from_bytes(r64)

def _point_add(A: bytes, B: bytes) -> bytes:
    return crypto_core_ristretto255_add(A, B)

def _point_sub(A: bytes, B: bytes) -> bytes:
    return crypto_core_ristretto255_sub(A, B)

def _point_mul(P: bytes, s: bytes) -> bytes:
    return crypto_scalarmult_ristretto255(s, P)

def _hash_to_scalar(ctx: bytes) -> bytes:
    return _scalar_reduce_from_bytes(hashlib.sha512(ctx).digest())


# === In-test prover for the Σ-protocol range proof ===========================

def make_bit_commitment_and_proof(bit: int, r_hex: str):
    """
    Produce (C_i_hex, proof_tuple) for a single bit b∈{0,1} with blinding r.
    proof_tuple = (t0, t1, c0, s0, c1, s1) as hex strings.
    """
    assert bit in (0, 1)
    # Commitment C_i = b*G + r*H
    Ci_hex = C.pedersen_commit(str(bit), r_hex)  # 32B hex
    Ci = bytes.fromhex(Ci_hex)
    Ci_minus_G = _point_sub(Ci, G_POINT)

    r = _r_scalar_from_blinding_hex(r_hex)

    # OR-proof: either Ci = r*H (b=0) or Ci - G = r*H (b=1)
    # Construct via Fiat–Shamir with simulation of the false branch.

    # Random nonce for the true branch
    k_true = _scalar_reduce_from_bytes(os.urandom(64))
    # Random challenge for the false branch
    c_false = _scalar_reduce_from_bytes(os.urandom(64))

    if bit == 0:
        # true statement: Ci = r*H
        t0 = _point_mul(H_POINT, k_true)
        # simulate false branch on (Ci - G): choose random t1, then derive c_true
        t1 = bytes.fromhex(C.pedersen_commit("0", os.urandom(32).hex()))  # arbitrary point, fine as random
        # Compute Fiat–Shamir challenge over (Ci, Ci-G, t0, t1)
        c = _hash_to_scalar(b"XIAN|bit_or|" + Ci + Ci_minus_G + t0 + t1)
        # c = c0 + c1 -> c0 = c - c1
        # false branch is index 1 -> c1 = c_false
        # true branch c0:
        #   s0 = k_true - c0 * r
        #   s1 is random, but must satisfy equation; easiest is: pick s1 and define t1 = s1*H - c1*(Ci - G)
        c1 = c_false
        # now compute c0 = c - c1
        # scalar subtraction: reduce by reusing module’s scalar ops through nacl.bindings is cumbersome here;
        # we can re-reduce (Python XOR with group order is internal). Use helper: c0_bytes = (c - c1) mod L
        # We don't have L, but crypto_core_ristretto255_scalar_sub exists only for Scalars; we don't have direct access.
        # Workaround: reuse module's pedersen_neg/add? Simpler: call nacl.bindings scalar_sub through a tiny wrapper is unavailable here.
        # So instead: precompute s1,t1 consistent so verifier holds with arbitrary c0 computed as (c - c1) via scalar reduction trick:
        # We'll import scalar_sub via C? The module doesn't export it. We'll recompute using bindings:
        from nacl.bindings import crypto_core_ristretto255_scalar_sub as _sc_sub, crypto_core_ristretto255_scalar_add as _sc_add, crypto_core_ristretto255_scalar_mul as _sc_mul
        c0 = _sc_sub(c, c1)
        s0 = _sc_sub(k_true, _sc_mul(c0, r))
        # For the simulated branch pick s1 randomly and set t1 accordingly:
        s1 = _scalar_reduce_from_bytes(os.urandom(64))
        t1 = _point_sub(_point_mul(H_POINT, s1), _point_mul(Ci_minus_G, c1))
    else:
        # bit == 1, true statement on (Ci - G) = r*H
        t1 = _point_mul(H_POINT, k_true)
        t0 = bytes.fromhex(C.pedersen_commit("0", os.urandom(32).hex()))
        c = _hash_to_scalar(b"XIAN|bit_or|" + Ci + Ci_minus_G + t0 + t1)
        from nacl.bindings import crypto_core_ristretto255_scalar_sub as _sc_sub, crypto_core_ristretto255_scalar_mul as _sc_mul
        c0 = c_false
        c1 = _sc_sub(c, c0)
        s1 = _sc_sub(k_true, _sc_mul(c1, r))
        s0 = _scalar_reduce_from_bytes(os.urandom(64))
        t0 = _point_sub(_point_mul(H_POINT, s0), _point_mul(Ci, c0))

    proof_tuple = (t0.hex(), t1.hex(), c0.hex(), s0.hex(), c1.hex(), s1.hex())
    return Ci_hex, proof_tuple


def make_range_proof(amount_value: int, bits: int = 8):
    """
    Build:
      - amount commitment C (hex)
      - per-bit commitments Ci (hex list)
      - per-bit proofs (6-tuple hex)
      - link proof (R,c,s as 3-tuple hex)
    """
    assert 0 <= amount_value < (1 << bits)
    # Blinding for amount
    r_amt_hex = os.urandom(32).hex()
    C_amt_hex = C.pedersen_commit(str(amount_value), r_amt_hex)
    C_amt = bytes.fromhex(C_amt_hex)

    # Bit decomposition
    bit_commitments = []
    bit_proofs = []
    r_scalars = []
    for i in range(bits):
        b = (amount_value >> i) & 1
        r_i_hex = os.urandom(32).hex()
        Ci_hex, proof_i = make_bit_commitment_and_proof(b, r_i_hex)
        bit_commitments.append(Ci_hex)
        bit_proofs.append(proof_i)
        r_scalars.append(_r_scalar_from_blinding_hex(r_i_hex))

    # Compute D = C - Σ 2^i * Ci  ; and r_D = r_amt - Σ 2^i * r_i  (scalars)
    S = None
    for i, Ci_hex in enumerate(bit_commitments):
        Ci = bytes.fromhex(Ci_hex)
        two_i = _scalar_from_u128(1 << i)
        term = _point_mul(Ci, two_i)
        S = term if S is None else _point_add(S, term)
    D = _point_sub(C_amt, S)

    r_amt = _r_scalar_from_blinding_hex(r_amt_hex)
    from nacl.bindings import crypto_core_ristretto255_scalar_add as _sc_add, crypto_core_ristretto255_scalar_sub as _sc_sub, crypto_core_ristretto255_scalar_mul as _sc_mul
    r_sum = None
    for i, r_i in enumerate(r_scalars):
        two_i = _scalar_from_u128(1 << i)
        term = _sc_mul(two_i, r_i)
        r_sum = term if r_sum is None else _sc_add(r_sum, term)
    r_D = _sc_sub(r_amt, r_sum)

    # Link-H Schnorr: prove D = r_D * H
    k = _scalar_reduce_from_bytes(os.urandom(64))
    R = _point_mul(H_POINT, k)
    c = _hash_to_scalar(b"XIAN|linkH|" + D + R)
    from nacl.bindings import crypto_core_ristretto255_scalar_mul as _sc_mul
    s = _scalar_reduce_from_bytes( (int.from_bytes(k, "little") - int.from_bytes(_sc_mul(c, r_D), "little")).to_bytes(64, "little") )
    # Better: s = k - c*r_D using scalar ops:
    from nacl.bindings import crypto_core_ristretto255_scalar_sub as _sc_sub
    s = _sc_sub(k, _sc_mul(c, r_D))

    link_proof = (R.hex(), c.hex(), s.hex())
    return C_amt_hex, bit_commitments, bit_proofs, link_proof


# === Tests ===================================================================

class TestCryptoModule(TestCase):

    def test_key_is_valid(self):
        good = "00" * 32
        bad1 = "0" * 63
        bad2 = "zz" * 32
        self.assertTrue(C.key_is_valid(good))
        self.assertFalse(C.key_is_valid(bad1))
        self.assertFalse(C.key_is_valid(bad2))

    def test_verify_signatures(self):
        sk = nacl.signing.SigningKey.generate()
        vk_hex = sk.verify_key.encode().hex()
        msg = "hello-xian"
        sig_hex = sk.sign(msg.encode()).signature.hex()
        self.assertTrue(C.verify(vk_hex, msg, sig_hex))
        self.assertFalse(C.verify(vk_hex, msg + "!", sig_hex))

    def test_pedersen_commit_determinism_and_ops(self):
        v = "123456"
        r_hex = "11" * 32
        c1 = C.pedersen_commit(v, r_hex)
        c2 = C.pedersen_commit(v, r_hex)
        self.assertEqual(c1, c2)  # deterministic

        # Basic ops: C + (-C) == identity
        neg = C.pedersen_neg(c1)
        zero = C.pedersen_add(c1, neg)
        # zero should be canonical point, and equals itself
        self.assertTrue(C.ristretto_is_canonical(zero))
        self.assertTrue(C.pedersen_eq(zero, zero))

        # Add/sub roundtrip
        r2_hex = "22" * 32
        d = C.pedersen_commit("1", r2_hex)
        rtrip = C.pedersen_sub(C.pedersen_add(c1, d), d)
        self.assertTrue(C.pedersen_eq(c1, rtrip))

    def test_ristretto_is_canonical(self):
        v = "0"; r_hex = "33" * 32
        c = C.pedersen_commit(v, r_hex)
        self.assertTrue(C.ristretto_is_canonical(c))
        # Break hex length
        self.assertFalse(C.ristretto_is_canonical(c[:-2]))
        # Non-hex
        self.assertFalse(C.ristretto_is_canonical("x" * 64))

    def test_range_proof_verify_positive_8bit(self):
        # Build a valid 8-bit proof for a small value
        value = 173  # 0b10101101
        C_amt_hex, bit_cmts, bit_proofs, link_pf = make_range_proof(value, bits=8)
        ok = C.range_proof_verify(C_amt_hex, bit_cmts, bit_proofs, link_pf, 8)
        self.assertTrue(ok)

    def test_range_proof_verify_rejects_tamper(self):
        value = 77
        C_amt_hex, bit_cmts, bit_proofs, link_pf = make_range_proof(value, bits=8)
        # Tamper one bit commitment
        bad_cmts = list(bit_cmts)
        bad_cmts[3] = bad_cmts[3][:-2] + ("00" if bad_cmts[3][-2:] != "00" else "01")
        ok = C.range_proof_verify(C_amt_hex, bad_cmts, bit_proofs, link_pf, 8)
        self.assertFalse(ok)

    def test_range_proof_verify_wrong_bits_len(self):
        value = 12
        C_amt_hex, bit_cmts, bit_proofs, link_pf = make_range_proof(value, bits=8)
        # Drop a proof
        ok = C.range_proof_verify(C_amt_hex, bit_cmts[:-1], bit_proofs, link_pf, 8)
        self.assertFalse(ok)
        ok = C.range_proof_verify(C_amt_hex, bit_cmts, bit_proofs[:-1], link_pf, 8)
        self.assertFalse(ok)

    def test_range_proof_verify_wrong_bits_param(self):
        value = 5
        C_amt_hex, bit_cmts, bit_proofs, link_pf = make_range_proof(value, bits=8)
        # Claim bits=16 with only 8 provided
        ok = C.range_proof_verify(C_amt_hex, bit_cmts, bit_proofs, link_pf, 16)
        self.assertFalse(ok)
