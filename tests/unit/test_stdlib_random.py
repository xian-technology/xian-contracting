import unittest

from contracting.stdlib.bridge.random import DeterministicRandom


class TestDeterministicRandom(unittest.TestCase):
    def test_same_seed_produces_same_bitstream(self):
        left = DeterministicRandom("seed-material")
        right = DeterministicRandom("seed-material")

        self.assertEqual(left.getrandbits(32), right.getrandbits(32))
        self.assertEqual(left.getrandbits(17), right.getrandbits(17))
        self.assertEqual(left.getrandbits(64), right.getrandbits(64))

    def test_different_seed_produces_different_bitstream(self):
        left = DeterministicRandom("seed-a")
        right = DeterministicRandom("seed-b")

        self.assertNotEqual(left.getrandbits(64), right.getrandbits(64))

    def test_getrandbits_zero_returns_zero(self):
        rng = DeterministicRandom("seed-material")
        self.assertEqual(rng.getrandbits(0), 0)

    def test_randbelow_respects_upper_bound(self):
        rng = DeterministicRandom("seed-material")
        for _ in range(20):
            value = rng.randbelow(7)
            self.assertGreaterEqual(value, 0)
            self.assertLess(value, 7)


if __name__ == "__main__":
    unittest.main()
