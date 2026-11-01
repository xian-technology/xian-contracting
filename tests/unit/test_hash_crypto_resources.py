"""The Python harness admits the same bounded hash/crypto payloads as the VM."""

import hashlib

import pytest

from contracting.stdlib.bridge import crypto, hashing

TEXT_LIMIT = 1024 * 1024
HEX_LIMIT = 2 * TEXT_LIMIT


@pytest.mark.parametrize("name", ["sha256_text", "sha3_text"])
def test_text_hash_caps_utf8_bytes(name):
    function = getattr(hashing, name)
    assert len(function("é" * (TEXT_LIMIT // 2))) == 64
    with pytest.raises(ValueError, match="resource limit"):
        function("é" * (TEXT_LIMIT // 2) + "a")


@pytest.mark.parametrize("name", ["sha256_hex", "sha3_hex"])
def test_strict_hex_caps_encoded_bytes(name):
    function = getattr(hashing, name)
    assert len(function("ab" * TEXT_LIMIT)) == 64
    with pytest.raises(ValueError, match="resource limit"):
        function("ab" * TEXT_LIMIT + "00")


@pytest.mark.parametrize("name", ["sha256", "sha3"])
def test_legacy_caps_selected_payload_before_decoding(name):
    function = getattr(hashing, name)
    assert len(function("ab" * TEXT_LIMIT)) == 64
    assert len(function(" " * HEX_LIMIT)) == 64
    with pytest.raises(ValueError, match="resource limit"):
        function("ab" * (TEXT_LIMIT // 2) + "z")
    with pytest.raises(ValueError, match="resource limit"):
        function(" " * (HEX_LIMIT + 1))


@pytest.mark.parametrize("value", ["", "ab cd", "a b", "ab\vcd", "é", "ab z"])
def test_legacy_detection_keeps_historical_fallback(value):
    try:
        payload = bytes.fromhex(value)
    except ValueError:
        payload = value.encode("utf-8")
    assert hashing.sha256(value) == hashlib.sha256(payload).hexdigest()


@pytest.mark.parametrize(
    ("key", "message", "signature"),
    [
        ("ab" * 33, "", "00" * 64),
        ("ab" * 32, "", "00" * 65),
        ("ab" * 32, "é" * (TEXT_LIMIT // 2) + "a", "00" * 64),
    ],
    ids=["key", "signature", "message"],
)
def test_verify_caps_before_decoding_or_verifying(key, message, signature):
    with pytest.raises(ValueError, match="resource limit"):
        crypto.verify(key, message, signature)


def test_key_predicate_keeps_false_for_large_wrong_length():
    assert crypto.key_is_valid("a" * (TEXT_LIMIT + 1)) is False


@pytest.mark.parametrize("value", ["é", "猫", "😀", "aé猫😀", "\x80", "\u0800", "\U00010000"])
def test_utf8_admission_counts_all_widths_without_encoding(value):
    from contracting.stdlib.bridge.crypto_resources import utf8_size

    size = len(value.encode())
    assert utf8_size(value, size, "test") == size
    with pytest.raises(ValueError, match="resource limit"):
        utf8_size(value, size - 1, "test")


def test_oversized_text_is_rejected_before_encoding():
    class NeverEncode(str):
        def encode(self, *args, **kwargs):
            raise AssertionError("must reject before encoding")

    with pytest.raises(ValueError, match="resource limit"):
        hashing.sha256_text(NeverEncode("x" * (TEXT_LIMIT + 1)))


@pytest.mark.parametrize("value", ["\ud800", "\udfff"])
def test_utf8_admission_preserves_surrogate_encoding_error(value):
    from contracting.stdlib.bridge.crypto_resources import utf8_size

    with pytest.raises(UnicodeEncodeError) as error:
        utf8_size(value, 10, "test")
    assert error.value.start == 0 and error.value.end == 1


INVALID_KEY_TEXT = [
    "+" + "a" * 63,
    "-" + "a" * 63,
    " " + "a" * 63,
    "\t" + "a" * 63,
    "a" * 63 + "\n",
    "\u00a0" + "a" * 63,
    "0x" + "a" * 62,
    "a" * 31 + "_" + "a" * 32,
    "١" * 64,
    "１" * 64,
    "g" + "a" * 63,
    "a" * 63,
    "a" * 65,
]
VALID_KEY_TEXT = ["a" * 64, "A" * 64, "0123456789abcdefABCDEF0123456789" * 2]


@pytest.mark.parametrize("value", INVALID_KEY_TEXT)
def test_key_predicate_rejects_non_ascii_hex_syntax(value):
    assert crypto.key_is_valid(value) is False


@pytest.mark.parametrize("value", VALID_KEY_TEXT)
def test_key_predicate_accepts_exact_ascii_hex_shape(value):
    assert crypto.key_is_valid(value) is True


@pytest.mark.parametrize("value", [b"a" * 64, ["a"] * 64, None])
def test_key_predicate_requires_a_string_like_native(value):
    with pytest.raises(TypeError):
        crypto.key_is_valid(value)


@pytest.mark.optional_native
@pytest.mark.parametrize("value", INVALID_KEY_TEXT + VALID_KEY_TEXT)
def test_key_predicate_matches_installed_native_for_strict_shape(tmp_path, value):
    from tests.integration.test_vm_hash_crypto_resources import execute

    result = execute(tmp_path, "return crypto.key_is_valid(payload)", value, meter=False)
    assert result.status_code == 0, result.result
    assert result.result is crypto.key_is_valid(value)
