from unittest import TestCase
from unittest.mock import Mock, patch

from contracting import constants
from contracting.stdlib.bridge import zk


class FakeEncodingError(Exception):
    pass


class FakeVerifierError(Exception):
    pass


class FakeDriver:
    def __init__(self, mapping):
        self.mapping = mapping

    def get_var(self, contract, variable, arguments=None):
        key = (contract, variable, tuple(arguments or ()))
        return self.mapping.get(key)


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

    def _registered_demo_key(self):
        return FakeDriver(
            {
                (constants.ZK_REGISTRY_CONTRACT_NAME, "verifying_keys", ("demo", field)): value
                for field, value in {
                    "scheme": "groth16",
                    "curve": "bn254",
                    "vk_hex": "0x1234",
                    "vk_hash": "vk-hash",
                    "active": True,
                }.items()
            }
        )

    def test_warm_verified_proofs_passes_every_checked_request_to_the_node_cache(self):
        driver = self._registered_demo_key()
        warm = Mock(return_value=[True, False])
        bindings = {
            "warm_registered": warm,
            "ZkEncodingError": FakeEncodingError,
            "ZkVerifierError": FakeVerifierError,
        }
        requests = [
            {"vk_id": "demo", "proof_hex": proof, "public_inputs": ["0x" + "00" * 32]}
            for proof in ("0xabcd", "0xef01")
        ]

        with patch(
            "contracting.stdlib.bridge.zk._native_verifier_bindings",
            return_value=bindings,
        ):
            self.assertEqual(zk.warm_verified_proofs(requests, driver=driver), [True, False])
            with self.assertRaisesRegex(AssertionError, "requests\\[1\\] must be a dict!"):
                zk.warm_verified_proofs([requests[0], "x"], driver=driver)
            warm.side_effect = FakeEncodingError("invalid proof bytes")
            with self.assertRaisesRegex(AssertionError, "invalid proof bytes"):
                zk.warm_verified_proofs(requests, driver=driver)

        warm.assert_called_with(
            [
                ("demo", "vk-hash", "0x1234", "0xabcd", ["0x" + "00" * 32]),
                ("demo", "vk-hash", "0x1234", "0xef01", ["0x" + "00" * 32]),
            ]
        )
        self.assertEqual(warm.call_count, 2)

    def test_shielded_command_nullifier_digest_uses_native_helper(self):
        nullifier_digest = Mock(return_value="0x" + "33" * 32)
        bindings = {
            "shielded_command_nullifier_digest": nullifier_digest,
            "ZkEncodingError": FakeEncodingError,
            "ZkVerifierError": FakeVerifierError,
        }

        with patch(
            "contracting.stdlib.bridge.zk._native_verifier_bindings",
            return_value=bindings,
        ):
            digest = zk.shielded_command_nullifier_digest(
                ["0x" + "01" * 32, "0x" + "02" * 32]
            )

        nullifier_digest.assert_called_once_with(["0x" + "01" * 32, "0x" + "02" * 32])
        self.assertEqual(digest, "0x" + "33" * 32)

    def test_shielded_command_binding_and_execution_tag_use_native_helpers(self):
        binding_helper = Mock(return_value="0x" + "44" * 32)
        tag_helper = Mock(return_value="0x" + "55" * 32)
        bindings = {
            "shielded_command_binding": binding_helper,
            "shielded_command_execution_tag": tag_helper,
            "ZkEncodingError": FakeEncodingError,
            "ZkVerifierError": FakeVerifierError,
        }

        with patch(
            "contracting.stdlib.bridge.zk._native_verifier_bindings",
            return_value=bindings,
        ):
            binding = zk.shielded_command_binding(
                "0x" + "01" * 32,
                "0x" + "02" * 32,
                "0x" + "03" * 32,
                "0x" + "04" * 32,
                "0x" + "05" * 32,
                "0x" + "06" * 32,
                "0x" + "07" * 32,
                "0x" + "08" * 32,
                7,
                0,
            )
            tag = zk.shielded_command_execution_tag(
                "0x" + "09" * 32,
                "0x" + "0a" * 32,
            )

        binding_helper.assert_called_once_with(
            *("0x" + f"{index:02x}" * 32 for index in range(1, 9)), 7, 0
        )
        tag_helper.assert_called_once_with("0x" + "09" * 32, "0x" + "0a" * 32)
        self.assertEqual(binding, "0x" + "44" * 32)
        self.assertEqual(tag, "0x" + "55" * 32)

    def test_shielded_output_payload_hashes_uses_native_helper(self):
        bindings = {
            "shielded_output_payload_hashes": lambda payloads: [
                "0x" + "77" * 32 for _ in payloads
            ],
            "ZkEncodingError": FakeEncodingError,
            "ZkVerifierError": FakeVerifierError,
        }

        with patch(
            "contracting.stdlib.bridge.zk._native_verifier_bindings",
            return_value=bindings,
        ):
            result = zk.shielded_output_payload_hashes(["0x1234", ""])

        self.assertEqual(result, ["0x" + "77" * 32, "0x" + "77" * 32])

    def test_shielded_deposit_public_inputs_uses_native_helper(self):
        bindings = {
            "shielded_deposit_public_inputs": lambda *_args: [
                "0x" + "88" * 32
            ],
            "ZkEncodingError": FakeEncodingError,
            "ZkVerifierError": FakeVerifierError,
        }

        with patch(
            "contracting.stdlib.bridge.zk._native_verifier_bindings",
            return_value=bindings,
        ):
            result = zk.shielded_deposit_public_inputs(
                "con_demo",
                "0x" + "11" * 32,
                7,
                ["0x" + "22" * 32],
                ["0x" + "33" * 32],
            )

        self.assertEqual(result, ["0x" + "88" * 32])

    def test_shielded_command_public_inputs_uses_native_helper(self):
        bindings = {
            "shielded_command_public_inputs": lambda *_args: [
                "0x" + "99" * 32
            ],
            "ZkEncodingError": FakeEncodingError,
            "ZkVerifierError": FakeVerifierError,
        }

        with patch(
            "contracting.stdlib.bridge.zk._native_verifier_bindings",
            return_value=bindings,
        ):
            result = zk.shielded_command_public_inputs(
                "con_demo",
                "0x" + "11" * 32,
                "0x" + "22" * 32,
                "0x" + "33" * 32,
                1,
                0,
                ["0x" + "44" * 32],
                ["0x" + "55" * 32],
                ["0x" + "66" * 32],
            )

        self.assertEqual(result, ["0x" + "99" * 32])
