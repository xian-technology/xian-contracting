import pytest
from xian_accounts import (
    Ed25519Account,
    generate_private_key,
    is_canonical_hex,
    is_valid_ed25519_key,
    public_key_from_private_key,
    sign_message,
    verify_message,
)


def test_account_can_sign_and_verify_message() -> None:
    account = Ed25519Account.generate()
    signature = account.sign_message("xian")

    assert account.verify_message("xian", signature) is True
    assert verify_message(account.public_key, "xian", signature) is True
    assert verify_message(account.public_key, "other", signature) is False


def test_public_key_derivation_is_stable() -> None:
    private_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    account = Ed25519Account(private_key)

    assert public_key_from_private_key(private_key) == account.public_key


def test_key_validation_requires_32_byte_hex_values() -> None:
    assert is_valid_ed25519_key(generate_private_key()) is True
    assert is_valid_ed25519_key("not-a-key") is False
    assert is_valid_ed25519_key("abcd") is False
    assert is_valid_ed25519_key("zz" * 32) is False


def test_invalid_signature_input_returns_false() -> None:
    account = Ed25519Account.generate()
    signature = sign_message(account.private_key, "xian")

    assert verify_message(account.public_key, "xian", "zz") is False
    assert verify_message("zz", "xian", signature) is False


@pytest.mark.parametrize("key", [" " * 64, "ab" * 31 + "  ", "ab" * 15 + "\n\t" + "cd" * 16])
def test_key_validation_rejects_whitespace_which_shortens_decoded_seed(key):
    assert len(key) == 64
    assert len(bytes.fromhex(key)) < 32
    assert is_valid_ed25519_key(key) is False
    with pytest.raises(ValueError, match="32-byte hex"):
        Ed25519Account(key)


@pytest.mark.parametrize("key", [None, 12, b"a" * 64, ["a"] * 64])
def test_key_validation_rejects_non_text_inputs(key):
    assert is_valid_ed25519_key(key) is False
    with pytest.raises(ValueError, match="32-byte hex"):
        Ed25519Account(key)


@pytest.mark.parametrize("key", ["abcdef01" * 8, "ABCDEF01" * 8, "AbCdEf01" * 8])
def test_private_key_casing_preserves_signing_and_verification(key):
    account = Ed25519Account(key)
    signature = account.sign_message("case-preserving key")
    assert account.verify_message("case-preserving key", signature) is True
    assert is_valid_ed25519_key(account.public_key) is True


@pytest.mark.parametrize("key", ["ABCDEF01" * 8, "AbCdEf01" * 8, "abcdef01" * 7 + "abcdeF01"])
def test_key_validation_requires_canonical_lowercase_hex(key):
    assert is_valid_ed25519_key(key) is False


def test_verification_rejects_non_canonical_public_key_and_signature_text() -> None:
    account = Ed25519Account.generate()
    signature = account.sign_message("xian")
    spaced_key = " ".join(account.public_key[i : i + 2] for i in range(0, 64, 2))

    assert verify_message(account.public_key.upper(), "xian", signature) is False
    assert verify_message(spaced_key, "xian", signature) is False
    assert verify_message(account.public_key, "xian", signature.upper()) is False
    assert verify_message(account.public_key, "xian", signature + "\n") is False


@pytest.mark.parametrize(
    ("public_key", "message", "signature"),
    [(None, "xian", "00" * 64), ("00" * 32, None, "00" * 64), ("00" * 32, "xian", 7)],
)
def test_verification_returns_false_for_non_text_inputs(public_key, message, signature):
    assert verify_message(public_key, message, signature) is False


def test_canonical_hex_is_exact_lowercase_ascii() -> None:
    assert is_canonical_hex("0123456789abcdef", 16) is True
    assert is_canonical_hex("0123456789ABCDEF", 16) is False
    assert is_canonical_hex("0123456789abcdef\n", 16) is False
    assert is_canonical_hex("0123456789abcde", 16) is False
    assert is_canonical_hex("0123456789abcde\uff46", 16) is False
    assert is_canonical_hex(b"0123456789abcdef", 16) is False

