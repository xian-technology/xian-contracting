import nacl.signing

from contracting.stdlib.bridge.crypto import key_is_valid, verify


def test_verify_accepts_valid_ed25519_signature():
    signer = nacl.signing.SigningKey.generate()
    message = "xian-message"
    signature = signer.sign(message.encode()).signature.hex()

    assert verify(signer.verify_key.encode().hex(), message, signature) is True


def test_verify_rejects_tampered_signature():
    signer = nacl.signing.SigningKey.generate()
    signature = signer.sign(b"xian-message").signature.hex()

    assert (
        verify(signer.verify_key.encode().hex(), "other-message", signature)
        is False
    )


def test_key_is_valid_requires_64_hex_characters():
    assert key_is_valid("a" * 64) is True
    assert key_is_valid("a" * 63) is False
    assert key_is_valid("z" * 64) is False
