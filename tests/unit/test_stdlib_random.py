import unittest

from contracting.execution.runtime import rt
from contracting.stdlib.bridge import random as random_bridge
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

    def test_random_returns_deterministic_unit_interval_float(self):
        previous_env = dict(rt.env)
        rt.env = {
            **previous_env,
            "chain_id": "xian-test",
            "block_num": 7,
            "block_hash": "abcd1234",
            "__input_hash": "input",
        }
        try:
            random_bridge.seed("alpha")
            first = random_bridge.random()
            random_bridge.seed("alpha")
            second = random_bridge.random()
        finally:
            random_bridge.clear_random_state()
            rt.env = previous_env

        self.assertEqual(first, second)
        self.assertIsInstance(first, float)
        self.assertGreaterEqual(first, 0)
        self.assertLess(first, 1)


if __name__ == "__main__":
    unittest.main()
