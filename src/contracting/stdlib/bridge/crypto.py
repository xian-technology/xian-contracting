from types import ModuleType
import hashlib
import nacl  # only for Ed25519 verify
import pysodium as sodium  # Ristretto255 & scalar/point ops

# Ensure libsodium primitives are initialised once on import. Without this the
# Ristretto255 helpers will return error codes (e.g. -1) when invoked under
# Python where the extension is loaded but libsodium has not been
# initialised yet.
sodium.sodium_init()


# ============================================================
# Ed25519 verify (hex keys/sigs; msg is raw string)
# ============================================================

def verify(vk: str, msg: str, signature: str):
    vk = bytes.fromhex(vk)
    msg = msg.encode()
    signature = bytes.fromhex(signature)

    vk = nacl.signing.VerifyKey(vk)
    try:
        vk.verify(msg, signature)
    except:
        return False
    return True


def key_is_valid(key: str):
    """ Check if the given address is valid.
     Can be used with public and private keys """
    if not len(key) == 64:
        return False
    try:
        int(key, 16)
    except:
        return False
    return True


# ============================================================
# Ristretto/Pedersen commitments (hex-only API via pysodium)
# ============================================================

MAX_HEX_LEN = 64  # 32 bytes hex

def _is_hex32(s: str) -> bool:
    if not isinstance(s, str) or len(s) != MAX_HEX_LEN:
        return False
    try:
        int(s, 16)
        return True
    except Exception:
        return False

def _require_hex32(s: str, name: str):
    assert _is_hex32(s), f"{name} must be 32-byte hex"

def _require_point_hex(h: str, name: str):
    _require_hex32(h, name)
    b = bytes.fromhex(h)
    assert bool(sodium.crypto_core_ristretto255_is_valid_point(b)), f"{name} is not canonical"

def _scalar_from_u128(v: int) -> bytes:
    # libsodium expects 64B input to scalar_reduce
    return sodium.crypto_core_ristretto255_scalar_reduce(v.to_bytes(64, "little"))

def _scalar_from_hex(h: str) -> bytes:
    _require_hex32(h, "scalar_hex")
    raw = bytes.fromhex(h)
    # Reduce to the group order so downstream scalar ops receive canonical
    # encodings even if the prover supplied a non-reduced 32-byte value.
    return sodium.crypto_core_ristretto255_scalar_reduce(raw + bytes(32))

def _scalar_one() -> bytes:
    return _scalar_from_u128(1)

# Fixed second generator H via hash-to-group (deterministic & domain-separated)
_H_HASH = hashlib.sha512(b"XIAN|crypto.pedersen|H").digest()  # 64 bytes
H_POINT = sodium.crypto_core_ristretto255_from_hash(_H_HASH)  # 32B point (bytes)

def pedersen_add(a_hex: str, b_hex: str) -> str:
    _require_point_hex(a_hex, "a_hex"); _require_point_hex(b_hex, "b_hex")
    return sodium.crypto_core_ristretto255_add(bytes.fromhex(a_hex), bytes.fromhex(b_hex)).hex()

def pedersen_sub(a_hex: str, b_hex: str) -> str:
    _require_point_hex(a_hex, "a_hex"); _require_point_hex(b_hex, "b_hex")
    return sodium.crypto_core_ristretto255_sub(bytes.fromhex(a_hex), bytes.fromhex(b_hex)).hex()

def pedersen_neg(p_hex: str) -> str:
    _require_point_hex(p_hex, "p_hex")
    P = bytes.fromhex(p_hex)
    neg1 = sodium.crypto_core_ristretto255_scalar_negate(_scalar_one())
    return sodium.crypto_scalarmult_ristretto255(neg1, P).hex()

def pedersen_eq(a_hex: str, b_hex: str) -> bool:
    if not (_is_hex32(a_hex) and _is_hex32(b_hex)):
        return False
    A = bytes.fromhex(a_hex); B = bytes.fromhex(b_hex)
    if not (sodium.crypto_core_ristretto255_is_valid_point(A) and sodium.crypto_core_ristretto255_is_valid_point(B)):
        return False
    return A == B

def ristretto_is_canonical(point_hex: str) -> bool:
    if not _is_hex32(point_hex):
        return False
    return bool(sodium.crypto_core_ristretto255_is_valid_point(bytes.fromhex(point_hex)))

G_POINT = sodium.crypto_scalarmult_ristretto255_base(_scalar_one())  # bytes (basepoint)

# ============================================================
# Python-only range proof verification (Σ-protocol)
#   - Inputs: hex strings and tuple/list containers (JSON-friendly)
#   - bit_proof: sequence[str] len==6  (t0,t1,c0,s0,c1,s1)
#   - link_proof: sequence[str] len==3 (R,c,s)
# ============================================================

_ALLOWED_BITS = {8, 16, 32, 64}

def _hash_to_scalar(data: bytes) -> bytes:
    return sodium.crypto_core_ristretto255_scalar_reduce(hashlib.sha512(data).digest())

def _point_mul(point_bytes: bytes, scalar_bytes: bytes) -> bytes:
    return sodium.crypto_scalarmult_ristretto255(scalar_bytes, point_bytes)

def _point_add(A: bytes, B: bytes) -> bytes:
    return sodium.crypto_core_ristretto255_add(A, B)

def _point_sub(A: bytes, B: bytes) -> bytes:
    return sodium.crypto_core_ristretto255_sub(A, B)

def _verify_bit_or_proof(C_hex: str, proof_tuple) -> bool:
    """
    OR-proof for bit b ∈ {0,1} on commitment C:
      either C = r0*H  OR  (C - G) = r1*H
    proof_tuple = (t0, t1, c0, s0, c1, s1)  -- all 32B hex strings
    """
    try:
        _require_point_hex(C_hex, "C_hex")
        if not (isinstance(proof_tuple, (list, tuple)) and len(proof_tuple) == 6):
            return False
        t0_hex, t1_hex, c0_hex, s0_hex, c1_hex, s1_hex = tuple(proof_tuple)

        C = bytes.fromhex(C_hex)
        C_minus_G = _point_sub(C, G_POINT)

        t0 = bytes.fromhex(t0_hex); t1 = bytes.fromhex(t1_hex)
        c0 = _scalar_from_hex(c0_hex); s0 = _scalar_from_hex(s0_hex)
        c1 = _scalar_from_hex(c1_hex); s1 = _scalar_from_hex(s1_hex)

        c = _hash_to_scalar(b"XIAN|bit_or|" + C + C_minus_G + t0 + t1)
        c_sum = sodium.crypto_core_ristretto255_scalar_add(c0, c1)
        if c != c_sum:
            return False

        lhs0 = _point_mul(H_POINT, s0)
        lhs1 = _point_mul(H_POINT, s1)
        rhs0 = _point_add(t0, _point_mul(C, c0))
        rhs1 = _point_add(t1, _point_mul(C_minus_G, c1))

        if not (lhs0 == rhs0 and lhs1 == rhs1):
            return False
        return True
    except Exception:
        return False

def _verify_schnorr_H(D: bytes, proof_tuple, domain_prefix: bytes, subtract_challenge: bool = True) -> bool:
    """
    Generic Schnorr verifier over the fixed generator H.  Expects knowledge of r
    such that D = r*H.  `proof_tuple` may be a tuple or list `(R, c, s)` of hex
    strings.
    """
    try:
        if not (isinstance(proof_tuple, (list, tuple)) and len(proof_tuple) == 3):
            return False
        R_hex, c_hex, s_hex = proof_tuple
        _require_point_hex(R_hex, "R_hex")

        R = bytes.fromhex(R_hex)
        c = _scalar_from_hex(c_hex)
        s = _scalar_from_hex(s_hex)

        challenge = _hash_to_scalar(domain_prefix + D + R)
        if c != challenge:
            return False

        lhs = _point_mul(H_POINT, s)
        challenge_term = _point_mul(D, c)
        rhs = _point_sub(R, challenge_term) if subtract_challenge else _point_add(R, challenge_term)
        return lhs == rhs
    except Exception:
        return False

def _verify_linkH_proof(D_hex: str, link_tuple) -> bool:
    """
    Knowledge of r: D = r*H
    link_tuple = (R, c, s) -- hex strings
    """
    try:
        _require_point_hex(D_hex, "D_hex")
        D = bytes.fromhex(D_hex)
        return _verify_schnorr_H(D, link_tuple, b"XIAN|linkH|")
    except Exception:
        return False


def pedersen_same_value_proof_verify(commitment_a_hex: str, commitment_b_hex: str, proof_tuple) -> bool:
    """
    Verify a Schnorr proof that two commitments encode the same value.  The
    prover demonstrates knowledge of r such that (A - B) = r*H, which can only
    hold when both commitments share the same amount component.

    `proof_tuple` may be a tuple or list of three 32-byte hex strings (R, c, s).
    """
    try:
        _require_point_hex(commitment_a_hex, "commitment_a_hex")
        _require_point_hex(commitment_b_hex, "commitment_b_hex")

        A = bytes.fromhex(commitment_a_hex)
        B = bytes.fromhex(commitment_b_hex)
        D = _point_sub(A, B)
        domain = b"XIAN|same_value|" + A + B

        return _verify_schnorr_H(D, proof_tuple, domain)
    except Exception:
        return False

def range_proof_verify(amount_commitment_hex: str,
                       bit_commitments_hex: list,
                       bit_proofs: list,
                       link_proof_tuple,
                       bits: int) -> bool:
    """
    Verify v in [0, 2^bits) for commitment C.
      - amount_commitment_hex: 32B point hex (C)
      - bit_commitments_hex: list[str] length == bits (each 32B point hex)
      - bit_proofs: list[tuple] length == bits (each 6-elem tuple of hex)
      - link_proof_tuple: 3-elem tuple (R,c,s) hex
      - bits ∈ {8,16,32,64}
    """
    try:
        if bits not in _ALLOWED_BITS:
            return False
        if not (isinstance(bit_commitments_hex, list) and isinstance(bit_proofs, list)):
            return False
        if len(bit_commitments_hex) != len(bit_proofs) or len(bit_commitments_hex) != bits:
            return False

        _require_point_hex(amount_commitment_hex, "amount_commitment_hex")
        C = bytes.fromhex(amount_commitment_hex)

        # 1) verify each bit proof
        Ci_bytes = []
        for i in range(bits):
            Ci_hex = bit_commitments_hex[i]
            _require_point_hex(Ci_hex, f"bit_commitments_hex[{i}]")
            if not _verify_bit_or_proof(Ci_hex, bit_proofs[i]):
                return False
            Ci_bytes.append(bytes.fromhex(Ci_hex))

        # 2) S = Σ (2^i) * C_i
        S = None
        for i, Ci in enumerate(Ci_bytes):
            two_i = _scalar_from_u128(1 << i)
            term = _point_mul(Ci, two_i)
            S = term if S is None else _point_add(S, term)

        # 3) D = C - S
        D = _point_sub(C, S)

        # 4) prove D is H-multiple
        if not _verify_linkH_proof(D.hex(), link_proof_tuple):
            return False

        return True
    except Exception:
        return False


# ============================================================
# Exports
# ============================================================

crypto_module = ModuleType('crypto')

crypto_module.verify = verify
crypto_module.key_is_valid = key_is_valid

crypto_module.pedersen_add = pedersen_add
crypto_module.pedersen_sub = pedersen_sub
crypto_module.pedersen_neg = pedersen_neg
crypto_module.pedersen_eq = pedersen_eq
crypto_module.pedersen_same_value_proof_verify = pedersen_same_value_proof_verify
crypto_module.ristretto_is_canonical = ristretto_is_canonical

crypto_module.range_proof_verify = range_proof_verify

exports = {
    'crypto': crypto_module
}
