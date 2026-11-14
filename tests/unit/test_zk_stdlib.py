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
        zk.rt.env.pop("__Driver", None)

    def test_is_available_false_when_native_package_missing(self):
        with patch(
            "contracting.stdlib.bridge.zk._native_verifier_bindings",
            return_value=None,
        ):
            self.assertFalse(zk.is_available())

    def test_get_vk_info_returns_registered_metadata(self):
        zk.rt.env["__Driver"] = FakeDriver(
            {
                ("zk_registry", "verifying_keys", ("demo", "vk_hex")): "0x1234",
                ("zk_registry", "verifying_keys", ("demo", "scheme")): "groth16",
                ("zk_registry", "verifying_keys", ("demo", "curve")): "bn254",
                ("zk_registry", "verifying_keys", ("demo", "vk_hash")): "0x56",
                ("zk_registry", "verifying_keys", ("demo", "active")): True,
                ("zk_registry", "verifying_keys", ("demo", "circuit_name")): "demo",
                ("zk_registry", "verifying_keys", ("demo", "version")): "1",
                ("zk_registry", "verifying_keys", ("demo", "created_at")): 123,
                ("zk_registry", "verifying_keys", ("demo", "circuit_family")): "shielded_note_v4",
                ("zk_registry", "verifying_keys", ("demo", "statement_version")): "3",
                ("zk_registry", "verifying_keys", ("demo", "contract_name")): "artifact",
                ("zk_registry", "verifying_keys", ("demo", "artifact_contract_name")): "artifact",
                ("zk_registry", "verifying_keys", ("demo", "tree_depth")): 20,
                ("zk_registry", "verifying_keys", ("demo", "leaf_capacity")): 2**20,
                ("zk_registry", "verifying_keys", ("demo", "max_inputs")): 4,
                ("zk_registry", "verifying_keys", ("demo", "max_outputs")): 4,
                ("zk_registry", "verifying_keys", ("demo", "setup_mode")): "dev",
                ("zk_registry", "verifying_keys", ("demo", "setup_ceremony")): "test",
                ("zk_registry", "verifying_keys", ("demo", "artifact_hash")): "0x12",
                ("zk_registry", "verifying_keys", ("demo", "bundle_hash")): "0x34",
                ("zk_registry", "verifying_keys", ("demo", "warning")): "",
                ("zk_registry", "verifying_keys", ("demo", "deprecated")): False,
                ("zk_registry", "verifying_keys", ("demo", "deprecated_at")): None,
                ("zk_registry", "verifying_keys", ("demo", "replacement_vk_id")): "",
                ("zk_registry", "verifying_keys", ("demo", "index")): 0,
            }
        )

        info = zk.get_vk_info("demo")

        self.assertEqual(info["vk_id"], "demo")
        self.assertEqual(info["vk_hash"], "0x56")
        self.assertEqual(info["circuit_family"], "shielded_note_v4")
        self.assertEqual(info["max_outputs"], 4)
        self.assertFalse(info["deprecated"])

    def test_verify_rejects_missing_native_package(self):
        with patch(
            "contracting.stdlib.bridge.zk._native_verifier_bindings",
            return_value=None,
        ):
            with self.assertRaises(AssertionError):
                zk.verify_groth16_bn254(
                    "0x00",
                    "0x00",
                    ["0x" + "00" * 32],
                )

    def test_verify_forwards_exact_payloads_to_native_helper(self):
        verify = Mock(return_value=True)
        bindings = {
            "verify_groth16_bn254": verify,
            "ZkEncodingError": FakeEncodingError,
            "ZkVerifierError": FakeVerifierError,
        }
        vk_hex = "0x1234"
        proof_hex = "0xabcd"
        public_inputs = ["0x" + "00" * 32, "0x" + "01" * 32]

        with patch(
            "contracting.stdlib.bridge.zk._native_verifier_bindings",
            return_value=bindings,
        ):
            self.assertTrue(
                zk.verify_groth16_bn254(vk_hex, proof_hex, public_inputs)
            )

        verify.assert_called_once_with(vk_hex, proof_hex, public_inputs)

    def test_verify_maps_native_encoding_errors_to_assertion(self):
        def _raise(*_args):
            raise FakeEncodingError("bad encoding")

        bindings = {
            "verify_groth16_bn254": _raise,
            "ZkEncodingError": FakeEncodingError,
            "ZkVerifierError": FakeVerifierError,
        }

        with patch(
            "contracting.stdlib.bridge.zk._native_verifier_bindings",
            return_value=bindings,
        ):
            with self.assertRaises(AssertionError):
                zk.verify_groth16_bn254(
                    "0x1234",
                    "0xabcd",
                    ["0x" + "00" * 32],
                )

    def test_verify_rejects_oversized_public_input_list(self):
        bindings = {
            "verify_groth16_bn254": lambda *_args: True,
            "ZkEncodingError": FakeEncodingError,
            "ZkVerifierError": FakeVerifierError,
        }

        with patch(
            "contracting.stdlib.bridge.zk._native_verifier_bindings",
            return_value=bindings,
        ):
            with self.assertRaises(AssertionError):
                zk.verify_groth16_bn254(
                    "0x1234",
                    "0xabcd",
                    ["0x" + "00" * 32]
                    * (constants.MAX_ZK_PUBLIC_INPUTS + 1),
                )

    def test_verify_rejects_non_canonical_public_input_width(self):
        bindings = {
            "verify_groth16_bn254": lambda *_args: True,
            "ZkEncodingError": FakeEncodingError,
            "ZkVerifierError": FakeVerifierError,
        }

        with patch(
            "contracting.stdlib.bridge.zk._native_verifier_bindings",
            return_value=bindings,
        ):
            with self.assertRaises(AssertionError):
                zk.verify_groth16_bn254(
                    "0x1234",
                    "0xabcd",
                    ["0x02"],
                )

    def test_has_verifying_key_uses_registry_state(self):
        mapping = {
            (
                constants.ZK_REGISTRY_CONTRACT_NAME,
                "verifying_keys",
                ("demo", "scheme"),
            ): "groth16",
            (
                constants.ZK_REGISTRY_CONTRACT_NAME,
                "verifying_keys",
                ("demo", "curve"),
            ): "bn254",
            (
                constants.ZK_REGISTRY_CONTRACT_NAME,
                "verifying_keys",
                ("demo", "vk_hex"),
            ): "0x1234",
            (
                constants.ZK_REGISTRY_CONTRACT_NAME,
                "verifying_keys",
                ("demo", "vk_hash"),
            ): "hash",
            (
                constants.ZK_REGISTRY_CONTRACT_NAME,
                "verifying_keys",
                ("demo", "active"),
            ): True,
        }
        zk.rt.env["__Driver"] = FakeDriver(mapping)

        self.assertTrue(zk.has_verifying_key("demo"))
        mapping[
            (
                constants.ZK_REGISTRY_CONTRACT_NAME,
                "verifying_keys",
                ("demo", "active"),
            )
        ] = False
        self.assertFalse(zk.has_verifying_key("demo"))
        self.assertFalse(zk.has_verifying_key("missing"))

    def _registered_demo_key(self):
        zk.rt.env["__Driver"] = FakeDriver(
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

    def test_verify_groth16_verifies_the_registered_key_through_the_node_cache(self):
        # The node's proof caches live in the VM (vm-core `zk_cache`): the
        # bridge passes the key's id, hash and bytes with the proof.
        self._registered_demo_key()
        verify = Mock(return_value=True)
        bindings = {
            "verify_registered": verify,
            "ZkEncodingError": FakeEncodingError,
            "ZkVerifierError": FakeVerifierError,
        }

        with patch(
            "contracting.stdlib.bridge.zk._native_verifier_bindings",
            return_value=bindings,
        ):
            self.assertTrue(zk.verify_groth16("demo", "0xabcd", ["0x" + "00" * 32]))
            verify.side_effect = FakeVerifierError("verification failed")
            with self.assertRaisesRegex(AssertionError, "verification failed"):
                zk.verify_groth16("demo", "0xabcd", ["0x" + "00" * 32])

        verify.assert_called_with("demo", "vk-hash", "0x1234", "0xabcd", ["0x" + "00" * 32])

    def test_warm_verified_proofs_passes_every_checked_request_to_the_node_cache(self):
        self._registered_demo_key()
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
            self.assertEqual(zk.warm_verified_proofs(requests), [True, False])
            with self.assertRaisesRegex(AssertionError, "requests\\[1\\] must be a dict!"):
                zk.warm_verified_proofs([requests[0], "x"])
            warm.side_effect = FakeEncodingError("invalid proof bytes")
            with self.assertRaisesRegex(AssertionError, "invalid proof bytes"):
                zk.warm_verified_proofs(requests)

        warm.assert_called_with(
            [
                ("demo", "vk-hash", "0x1234", "0xabcd", ["0x" + "00" * 32]),
                ("demo", "vk-hash", "0x1234", "0xef01", ["0x" + "00" * 32]),
            ]
        )
        self.assertEqual(warm.call_count, 2)

    def test_shielded_note_append_commitments_uses_native_helper(self):
        append = Mock(return_value=(
            '{"root":"0x' + "11" * 32
            + '","note_count":2,"filled_subtrees":["0x' + "22" * 32 + '"]}'
        ))
        bindings = {
            "shielded_note_append_tree_state_json": append,
            "ZkEncodingError": FakeEncodingError,
            "ZkVerifierError": FakeVerifierError,
        }

        with patch(
            "contracting.stdlib.bridge.zk._native_verifier_bindings",
            return_value=bindings,
        ):
            result = zk.shielded_note_append_commitments(
                1,
                ["0x" + "00" * 32],
                ["0x" + "01" * 32],
            )

        append.assert_called_once_with(1, ["0x" + "00" * 32], ["0x" + "01" * 32])
        self.assertEqual(result["note_count"], 2)
        self.assertEqual(result["root"], "0x" + "11" * 32)

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

    def test_shielded_output_payload_hash_uses_native_helper(self):
        payload_hash = Mock(return_value="0x" + "66" * 32)
        bindings = {
            "shielded_output_payload_hash": payload_hash,
            "ZkEncodingError": FakeEncodingError,
            "ZkVerifierError": FakeVerifierError,
        }
        payload = "0x1234"

        with patch(
            "contracting.stdlib.bridge.zk._native_verifier_bindings",
            return_value=bindings,
        ):
            result = zk.shielded_output_payload_hash(payload)

        payload_hash.assert_called_once_with(payload)
        self.assertEqual(result, "0x" + "66" * 32)

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
