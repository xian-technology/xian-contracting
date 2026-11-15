from unittest import TestCase
from unittest.mock import patch

from contracting.stdlib.bridge import zk


class TestZkStdlib(TestCase):
    def setUp(self):
        zk._native_verifier_bindings.cache_clear()
        zk.clear_prepared_vk_cache()

    def tearDown(self):
        zk._native_verifier_bindings.cache_clear()
        zk.clear_prepared_vk_cache()
        zk.clear_verified_proof_cache()

    def test_is_available_false_when_native_package_missing(self):
        with patch(
            "contracting.stdlib.bridge.zk._native_verifier_bindings",
            return_value=None,
        ):
            self.assertFalse(zk.is_available())
