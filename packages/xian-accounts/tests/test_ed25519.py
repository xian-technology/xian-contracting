import pytest
from xian_accounts import (
    Ed25519Account,
    generate_private_key,
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
def test_valid_key_casing_preserves_signing_and_verification(key):
    assert is_valid_ed25519_key(key) is True
    account = Ed25519Account(key)
    signature = account.sign_message("case-preserving key")
    assert account.verify_message("case-preserving key", signature) is True
