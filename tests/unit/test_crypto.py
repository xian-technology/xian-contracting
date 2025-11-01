from unittest import TestCase
import os
import hashlib
import nacl.signing  # only for Ed25519 keygen/sign in tests
import pysodium as sodium

# module under test
from contracting.stdlib.bridge import crypto as C


# === Helpers (mirror the module’s internal derivations) ======================

def _scalar_reduce_from_bytes(b: bytes) -> bytes:
    return sodium.crypto_core_ristretto255_scalar_reduce(b)

def _scalar_from_u128(v: int) -> bytes:
    return _scalar_reduce_from_bytes(v.to_bytes(64, "little"))

# Fixed H generator (must match module)
_H_HASH = hashlib.sha512(b"XIAN|crypto.pedersen|H").digest()
H_POINT = sodium.crypto_core_ristretto255_from_hash(_H_HASH)  # bytes (32)
G_POINT = sodium.crypto_scalarmult_ristretto255_base(_scalar_from_u128(1))

def _r_scalar_from_blinding_hex(blind_hex: str) -> bytes:
    seed = bytes.fromhex(blind_hex)
    r64 = hashlib.sha512(b"XIAN|crypto.pedersen|r|" + seed).digest()
    return _scalar_reduce_from_bytes(r64)

def _point_add(A: bytes, B: bytes) -> bytes:
    return sodium.crypto_core_ristretto255_add(A, B)

def _point_sub(A: bytes, B: bytes) -> bytes:
    return sodium.crypto_core_ristretto255_sub(A, B)

def _point_mul(P: bytes, s: bytes) -> bytes:
    return sodium.crypto_scalarmult_ristretto255(s, P)

def _hash_to_scalar(ctx: bytes) -> bytes:
    return _scalar_reduce_from_bytes(hashlib.sha512(ctx).digest())


def pedersen_commit_for_tests(value_u128: str, blinding_hex: str) -> str:
    assert isinstance(value_u128, str) and value_u128.isdigit(), "value must be decimal string"
    v_int = int(value_u128, 10)
    assert 0 <= v_int <= (1 << 128) - 1, "value out of range"
    assert isinstance(blinding_hex, str) and len(blinding_hex) == 64, "blinding must be 32-byte hex"
    _ = int(blinding_hex, 16)  # raises if non-hex

    v_scalar = _scalar_from_u128(v_int)
    r_seed = bytes.fromhex(blinding_hex)
    r64 = hashlib.sha512(b"XIAN|crypto.pedersen|r|" + r_seed).digest()
    r_scalar = _scalar_reduce_from_bytes(r64)

    if v_scalar == bytes(32):
        vG = _point_sub(H_POINT, H_POINT)
    else:
        vG = sodium.crypto_scalarmult_ristretto255_base(v_scalar)
    rH = _point_mul(H_POINT, r_scalar)
    return _point_add(vG, rH).hex()


# === In-test prover for the Σ-protocol range proof ===========================

def make_bit_commitment_and_proof(bit: int, r_hex: str):
    """
    Produce (C_i_hex, proof_tuple) for a single bit b∈{0,1} with blinding r.
    proof_tuple = (t0, t1, c0, s0, c1, s1) as hex strings.
    """
    assert bit in (0, 1)
    # Commitment C_i = b*G + r*H (use module under test)
    Ci_hex = pedersen_commit_for_tests(str(bit), r_hex)  # 32B hex
    Ci = bytes.fromhex(Ci_hex)
    Ci_minus_G = _point_sub(Ci, G_POINT)

    r = _r_scalar_from_blinding_hex(r_hex)

    # Fiat–Shamir OR-proof:
    #   either Ci = r*H (b=0)  OR  (Ci - G) = r*H (b=1)

    # Random nonce for the true branch
    k_true = _scalar_reduce_from_bytes(os.urandom(64))
    # Random challenge for the simulated (false) branch
    c_false = _scalar_reduce_from_bytes(os.urandom(64))

    if bit == 0:
        # true statement: Ci = r*H
        t0 = _point_mul(H_POINT, k_true)
        # simulate false on (Ci - G): choose s1 random, set t1 = s1*H - c1*(Ci - G)
        s1 = _scalar_reduce_from_bytes(os.urandom(64))
        c1 = c_false
        t1 = _point_sub(_point_mul(H_POINT, s1), _point_mul(Ci_minus_G, c1))

        # Fiat–Shamir challenge
        c = _hash_to_scalar(b"XIAN|bit_or|" + Ci + Ci_minus_G + t0 + t1)

        # c = c0 + c1  =>  c0 = c - c1
        c0 = sodium.crypto_core_ristretto255_scalar_sub(c, c1)
        # s0 = k_true + c0*r  (verifier checks s0*H = t0 + c0*C)
        s0 = sodium.crypto_core_ristretto255_scalar_add(
            k_true,
            sodium.crypto_core_ristretto255_scalar_mul(c0, r),
        )
    else:
        # true statement: (Ci - G) = r*H
        t1 = _point_mul(H_POINT, k_true)
        # simulate false on Ci: choose s0 random, set t0 = s0*H - c0*Ci
        s0 = _scalar_reduce_from_bytes(os.urandom(64))
        c0 = c_false
        t0 = _point_sub(_point_mul(H_POINT, s0), _point_mul(Ci, c0))

        # Fiat–Shamir
        c = _hash_to_scalar(b"XIAN|bit_or|" + Ci + Ci_minus_G + t0 + t1)

        # c = c0 + c1  =>  c1 = c - c0
        c1 = sodium.crypto_core_ristretto255_scalar_sub(c, c0)
        # s1 = k_true + c1*r  (verifier checks s1*H = t1 + c1*(C - G))
        s1 = sodium.crypto_core_ristretto255_scalar_add(
            k_true,
            sodium.crypto_core_ristretto255_scalar_mul(c1, r),
        )

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
    # Amount & blinding
    r_amt_hex = os.urandom(32).hex()
    C_amt_hex = pedersen_commit_for_tests(str(amount_value), r_amt_hex)
    C_amt = bytes.fromhex(C_amt_hex)

    # Bits
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

    # D = C - Σ 2^i * Ci
    S = None
    for i, Ci_hex in enumerate(bit_commitments):
        Ci = bytes.fromhex(Ci_hex)
        two_i = _scalar_from_u128(1 << i)
        term = _point_mul(Ci, two_i)
        S = term if S is None else _point_add(S, term)
    D = _point_sub(C_amt, S)

    # r_D = r_amt - Σ 2^i * r_i
    r_amt = _r_scalar_from_blinding_hex(r_amt_hex)
    r_sum = None
    for i, r_i in enumerate(r_scalars):
        two_i = _scalar_from_u128(1 << i)
        term = sodium.crypto_core_ristretto255_scalar_mul(two_i, r_i)
        r_sum = term if r_sum is None else sodium.crypto_core_ristretto255_scalar_add(r_sum, term)
    r_D = sodium.crypto_core_ristretto255_scalar_sub(r_amt, r_sum)

    # Link-H Schnorr: D = r_D * H
    k = _scalar_reduce_from_bytes(os.urandom(64))
    R = _point_mul(H_POINT, k)
    c = _hash_to_scalar(b"XIAN|linkH|" + D + R)
    s = sodium.crypto_core_ristretto255_scalar_sub(
        k, sodium.crypto_core_ristretto255_scalar_mul(c, r_D)
    )
    link_proof = (R.hex(), c.hex(), s.hex())

    return C_amt_hex, bit_commitments, bit_proofs, link_proof


def make_same_value_proof(value: int):
    """Return (commitment_a, commitment_b, proof_list)."""
    assert isinstance(value, int) and value >= 0
    r1_hex = os.urandom(32).hex()
    r2_hex = os.urandom(32).hex()
    C1_hex = pedersen_commit_for_tests(str(value), r1_hex)
    C2_hex = pedersen_commit_for_tests(str(value), r2_hex)

    C1 = bytes.fromhex(C1_hex)
    C2 = bytes.fromhex(C2_hex)
    D = _point_sub(C1, C2)

    r1 = _r_scalar_from_blinding_hex(r1_hex)
    r2 = _r_scalar_from_blinding_hex(r2_hex)
    r_diff = sodium.crypto_core_ristretto255_scalar_sub(r1, r2)

    k = _scalar_reduce_from_bytes(os.urandom(64))
    R = _point_mul(H_POINT, k)
    domain = b"XIAN|same_value|" + C1 + C2
    c = _hash_to_scalar(domain + D + R)
    s = sodium.crypto_core_ristretto255_scalar_sub(
        k,
        sodium.crypto_core_ristretto255_scalar_mul(c, r_diff),
    )

    proof_list = [R.hex(), c.hex(), s.hex()]
    return C1_hex, C2_hex, proof_list


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

    def test_pedersen_group_ops_with_locally_built_commitments(self):
        self.assertFalse(hasattr(C, 'pedersen_commit'))

        v = "123456"
        r_hex = "11" * 32
        c1 = pedersen_commit_for_tests(v, r_hex)
        c2 = pedersen_commit_for_tests(v, r_hex)
        self.assertEqual(c1, c2)  # deterministic even when built locally

        # Zero-value path should remain deterministic as well (exercise v_scalar == 0 branch)
        zero_blind = "33" * 32
        z1 = pedersen_commit_for_tests("0", zero_blind)
        z2 = pedersen_commit_for_tests("0", zero_blind)
        self.assertEqual(z1, z2)

        # Zero-value path should remain deterministic as well (exercise v_scalar == 0 branch)
        zero_blind = "33" * 32
        z1 = C.pedersen_commit("0", zero_blind)
        z2 = C.pedersen_commit("0", zero_blind)
        self.assertEqual(z1, z2)

        # C + (-C) == identity (encoded point is canonical)
        neg = C.pedersen_neg(c1)
        zero = C.pedersen_add(c1, neg)
        self.assertTrue(C.ristretto_is_canonical(zero))
        self.assertTrue(C.pedersen_eq(zero, zero))

        # Add/sub roundtrip
        r2_hex = "22" * 32
        d = pedersen_commit_for_tests("1", r2_hex)
        rtrip = C.pedersen_sub(C.pedersen_add(c1, d), d)
        self.assertTrue(C.pedersen_eq(c1, rtrip))

    def test_ristretto_is_canonical(self):
        v = "0"; r_hex = "33" * 32
        c = pedersen_commit_for_tests(v, r_hex)
        self.assertTrue(C.ristretto_is_canonical(c))
        # Break hex length
        self.assertFalse(C.ristretto_is_canonical(c[:-2]))
        # Non-hex
        self.assertFalse(C.ristretto_is_canonical("x" * 64))

    def test_range_proof_verify_positive_8bit(self):
        # Build a valid 8-bit proof for a small value
        value = 173  # 0b10101101
        C_amt_hex, bit_cmts, bit_proofs, link_pf = make_range_proof(value, bits=8)
        ok1 = C.range_proof_verify(C_amt_hex, bit_cmts, bit_proofs, link_pf, 8)
        ok2 = C.range_proof_verify(C_amt_hex, bit_cmts, bit_proofs, link_pf, 8)
        self.assertTrue(ok1)
        self.assertTrue(ok2)

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

    def test_pedersen_same_value_proof_accepts_valid_proof(self):
        C1_hex, C2_hex, proof = make_same_value_proof(42)
        self.assertTrue(C.pedersen_same_value_proof_verify(C1_hex, C2_hex, proof))
        # Repeat to ensure deterministic verification path and tuple backwards compatibility
        self.assertTrue(C.pedersen_same_value_proof_verify(C1_hex, C2_hex, tuple(proof)))

    def test_pedersen_same_value_proof_rejects_tamper(self):
        C1_hex, C2_hex, proof = make_same_value_proof(7)
        bad_R = ("00" * 32)
        tampered = [bad_R, proof[1], proof[2]]
        self.assertFalse(C.pedersen_same_value_proof_verify(C1_hex, C2_hex, tampered))

        bad_commit = C.pedersen_add(C1_hex, C2_hex)
        self.assertFalse(C.pedersen_same_value_proof_verify(bad_commit, C2_hex, proof))
