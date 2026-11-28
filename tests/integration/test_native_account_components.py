"""Parity with libsodium and PQClean through the exact native consensus verifier."""

from pathlib import Path

from nacl.signing import SigningKey


def test_native_verifier_requires_both_signatures_for_the_same_message():
    from xian_vm_core import verify_account_components

    vector = (Path(__file__).parents[1] / "fixtures" / "ml_dsa_65_pop.bin").read_bytes()
    pq, pq_sig = vector[:1952], vector[1952:]
    message = "xian-validator-key-v1\nlocal\n验证者".encode()
    ed = SigningKey(bytes([38]) * 32)
    public = bytes(ed.verify_key)
    ed_sig = ed.sign(message).signature
    proof = ed_sig + pq_sig

    assert verify_account_components(public, pq, message, proof)
    for key, pq_key, msg, signature in [
        (public, pq, message + b"x", proof),
        (public, pq, message, ed.sign(b"x").signature + pq_sig),
        (public, pq, message, ed_sig + bytes(3309)),
        (public, pq, message, proof[:-1]),
        (public, pq, message, proof + b"\0"),
        (public, pq[:-1], message, proof),
        (public[:-1], pq, message, proof),
    ]:
        assert not verify_account_components(key, pq_key, msg, signature)


def test_native_and_wallet_verifiers_agree_for_all_authority_roles():
    import pytest
    from xian_vm_core import verify_account_components

    hybrid = pytest.importorskip("xian_accounts.hybrid")
    pytest.importorskip("pqcrypto")
    ed = SigningKey.generate()
    public, secret = hybrid.backend().generate_keypair()
    keys = hybrid.PublicKeys(bytes(ed.verify_key), public)
    message = b'{"chain_id":"local","nonce":3}'
    for role in sorted(hybrid.ROLES):
        valid = hybrid.sign(keys, 7, message, ed_seed=bytes(ed), pq_secret=secret, role=role)
        for position in [None, 0, hybrid.HEADER_BYTES, hybrid.HEADER_BYTES + 64, -1]:
            signature = bytearray(valid)
            if position is not None:
                signature[position] ^= 0x80
            signature = bytes(signature)
            native = hybrid.verify(
                keys, 7, message, signature, role=role, verifier=verify_account_components
            )
            assert native is (position is None)
            assert hybrid.verify(keys, 7, message, signature, role=role) == native
