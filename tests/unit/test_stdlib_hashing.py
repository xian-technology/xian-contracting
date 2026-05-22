from unittest import TestCase

from contracting.stdlib.bridge.hashing import (
    sha256_hex,
    sha256_text,
    sha3_hex,
    sha3_text,
)


class TestHashing(TestCase):
    def test_sha3_hex(self):
        secret = '1a54390942257a70bb843c1bd94eb996'
        _hash = '6c839446b4d4fa2582af5011730c680b3ee39929f041b7bee6f376211cc710f7'

        self.assertEqual(_hash, sha3_hex(secret))

    def test_sha256_hex(self):
        secret = '842b65a7d48e3a3c3f0e9d37eaced0b2'
        _hash = 'eaf48a02d3a4bb3aeb0ecb337f6efb026ee0bbc460652510cff929de78935514'

        self.assertEqual(_hash, sha256_hex(secret))

    def test_text_mode_keeps_hex_like_text_literal(self):
        self.assertNotEqual(sha3_text("hello"), sha3_text("68656c6c6f"))
        self.assertNotEqual(sha256_text("h"), sha256_text("68"))

    def test_hex_mode_rejects_whitespace(self):
        with self.assertRaisesRegex(AssertionError, "hash hex input"):
            sha3_hex("68 65")
