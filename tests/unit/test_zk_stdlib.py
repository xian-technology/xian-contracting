from unittest import TestCase
from unittest.mock import patch

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
                ("zk_registry", "verifying_keys", ("demo", "circuit_family")): "shielded_note_v3",
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
        self.assertEqual(info["circuit_family"], "shielded_note_v3")
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

    def test_verify_deducts_metering_cost(self):
        bindings = {
            "verify_groth16_bn254": lambda *_args: True,
            "ZkEncodingError": FakeEncodingError,
            "ZkVerifierError": FakeVerifierError,
        }
        vk_hex = "0x1234"
        proof_hex = "0xabcd"
        public_inputs = ["0x" + "00" * 32, "0x" + "01" * 32]

        expected = (
            constants.ZK_VERIFY_GROTH16_BASE_COST
            + (
                len(public_inputs)
                * constants.ZK_VERIFY_GROTH16_PER_PUBLIC_INPUT_COST
            )
            + (
                (
                    ((len(vk_hex) - 2) // 2)
                    + ((len(proof_hex) - 2) // 2)
                    + sum((len(v) - 2) // 2 for v in public_inputs)
                )
                * constants.ZK_VERIFY_GROTH16_PER_PAYLOAD_BYTE_COST
            )
        )

        with patch(
            "contracting.stdlib.bridge.zk._native_verifier_bindings",
            return_value=bindings,
        ), patch(
            "contracting.stdlib.bridge.zk.rt.deduct_execution_cost"
        ) as deduct:
            self.assertTrue(
                zk.verify_groth16_bn254(vk_hex, proof_hex, public_inputs)
            )

        deduct.assert_called_once_with(expected)

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

    def test_verify_groth16_reuses_prepared_key_cache(self):
        prepared_calls = []
        verify_calls = []

        zk.rt.env["__Driver"] = FakeDriver(
            {
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
                ): "vk-hash",
                (
                    constants.ZK_REGISTRY_CONTRACT_NAME,
                    "verifying_keys",
                    ("demo", "active"),
                ): True,
            }
        )

        def prepare(vk_hex):
            prepared_calls.append(vk_hex)
            return {"prepared": vk_hex}

        def verify(prepared, proof_hex, public_inputs):
            verify_calls.append((prepared, proof_hex, tuple(public_inputs)))
            return True

        bindings = {
            "prepare_groth16_bn254_vk": prepare,
            "verify_groth16_bn254_prepared": verify,
            "verify_groth16_bn254": lambda *_args: True,
            "ZkEncodingError": FakeEncodingError,
            "ZkVerifierError": FakeVerifierError,
        }

        with patch(
            "contracting.stdlib.bridge.zk._native_verifier_bindings",
            return_value=bindings,
        ):
            self.assertTrue(
                zk.verify_groth16(
                    "demo",
                    "0xabcd",
                    ["0x" + "00" * 32],
                )
            )
            self.assertTrue(
                zk.verify_groth16(
                    "demo",
                    "0xabcd",
                    ["0x" + "00" * 32],
                )
            )

        self.assertEqual(prepared_calls, ["0x1234"])
        self.assertEqual(len(verify_calls), 1)

    def test_warm_verified_proofs_primes_verify_cache(self):
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
            ): "vk-hash",
            (
                constants.ZK_REGISTRY_CONTRACT_NAME,
                "verifying_keys",
                ("demo", "active"),
            ): True,
        }
        zk.rt.env["__Driver"] = FakeDriver(mapping)
        prepare_calls = []
        verify_calls = []

        bindings = {
            "prepare_groth16_bn254_vk": lambda vk_hex: prepare_calls.append(vk_hex),
            "verify_groth16_bn254_prepared": lambda *_args: verify_calls.append(
                _args
            ),
            "verify_groth16_bn254_grouped_json": lambda _payload: "[true]",
            "verify_groth16_bn254": lambda *_args: True,
            "ZkEncodingError": FakeEncodingError,
            "ZkVerifierError": FakeVerifierError,
        }

        with patch(
            "contracting.stdlib.bridge.zk._native_verifier_bindings",
            return_value=bindings,
        ):
            warmed = zk.warm_verified_proofs(
                [
                    {
                        "vk_id": "demo",
                        "proof_hex": "0xabcd",
                        "public_inputs": ["0x" + "00" * 32],
                    }
                ]
            )
            verified = zk.verify_groth16(
                "demo",
                "0xabcd",
                ["0x" + "00" * 32],
            )

        self.assertEqual(warmed, [True])
        self.assertTrue(verified)
        self.assertEqual(prepare_calls, [])
        self.assertEqual(verify_calls, [])

    def test_verify_groth16_reprepares_when_vk_hash_changes(self):
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
            ): "vk-hash-1",
            (
                constants.ZK_REGISTRY_CONTRACT_NAME,
                "verifying_keys",
                ("demo", "active"),
            ): True,
        }
        zk.rt.env["__Driver"] = FakeDriver(mapping)

        prepared_calls = []
        verify_calls = []

        def prepare(vk_hex):
            prepared_calls.append(vk_hex)
            return {"prepared": vk_hex}

        def verify(prepared, proof_hex, public_inputs):
            verify_calls.append((prepared, proof_hex, tuple(public_inputs)))
            return True

        bindings = {
            "prepare_groth16_bn254_vk": prepare,
            "verify_groth16_bn254_prepared": verify,
            "verify_groth16_bn254": lambda *_args: True,
            "ZkEncodingError": FakeEncodingError,
            "ZkVerifierError": FakeVerifierError,
        }

        with patch(
            "contracting.stdlib.bridge.zk._native_verifier_bindings",
            return_value=bindings,
        ):
            self.assertTrue(
                zk.verify_groth16(
                    "demo",
                    "0xabcd",
                    ["0x" + "00" * 32],
                )
            )
            mapping[
                (
                    constants.ZK_REGISTRY_CONTRACT_NAME,
                    "verifying_keys",
                    ("demo", "vk_hex"),
                )
            ] = "0x5678"
            mapping[
                (
                    constants.ZK_REGISTRY_CONTRACT_NAME,
                    "verifying_keys",
                    ("demo", "vk_hash"),
                )
            ] = "vk-hash-2"
            self.assertTrue(
                zk.verify_groth16(
                    "demo",
                    "0xabcd",
                    ["0x" + "00" * 32],
                )
            )

        self.assertEqual(prepared_calls, ["0x1234", "0x5678"])
        self.assertEqual(len(verify_calls), 2)

    def test_shielded_note_append_commitments_uses_native_helper(self):
        bindings = {
            "shielded_note_append_tree_state_json": lambda *_args: (
                '{"root":"0x'
                + "11" * 32
                + '","note_count":2,"filled_subtrees":["0x'
                + "22" * 32
                + '"]}'
            ),
            "ZkEncodingError": FakeEncodingError,
            "ZkVerifierError": FakeVerifierError,
        }

        with patch(
            "contracting.stdlib.bridge.zk._native_verifier_bindings",
            return_value=bindings,
        ), patch(
            "contracting.stdlib.bridge.zk.rt.deduct_execution_cost"
        ) as deduct:
            result = zk.shielded_note_append_commitments(
                1,
                ["0x" + "00" * 32],
                ["0x" + "01" * 32],
            )

        deduct.assert_called_once_with(
            constants.ZK_SHIELDED_TREE_APPEND_BASE_COST
            + constants.ZK_SHIELDED_TREE_APPEND_PER_COMMITMENT_COST
        )
        self.assertEqual(result["note_count"], 2)
        self.assertEqual(result["root"], "0x" + "11" * 32)

    def test_shielded_command_nullifier_digest_uses_native_helper(self):
        bindings = {
            "shielded_command_nullifier_digest": lambda values: "0x" + "33" * 32,
            "ZkEncodingError": FakeEncodingError,
            "ZkVerifierError": FakeVerifierError,
        }

        with patch(
            "contracting.stdlib.bridge.zk._native_verifier_bindings",
            return_value=bindings,
        ), patch(
            "contracting.stdlib.bridge.zk.rt.deduct_execution_cost"
        ) as deduct:
            digest = zk.shielded_command_nullifier_digest(
                ["0x" + "01" * 32, "0x" + "02" * 32]
            )

        deduct.assert_called_once_with(
            constants.ZK_SHIELDED_COMMAND_NULLIFIER_DIGEST_BASE_COST
            + (2 * constants.ZK_SHIELDED_COMMAND_NULLIFIER_DIGEST_PER_INPUT_COST)
        )
        self.assertEqual(digest, "0x" + "33" * 32)

    def test_shielded_command_binding_and_execution_tag_use_native_helpers(self):
        bindings = {
            "shielded_command_binding": lambda *_args: "0x" + "44" * 32,
            "shielded_command_execution_tag": lambda *_args: "0x" + "55" * 32,
            "ZkEncodingError": FakeEncodingError,
            "ZkVerifierError": FakeVerifierError,
        }

        with patch(
            "contracting.stdlib.bridge.zk._native_verifier_bindings",
            return_value=bindings,
        ), patch(
            "contracting.stdlib.bridge.zk.rt.deduct_execution_cost"
        ) as deduct:
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

        deduct.assert_any_call(constants.ZK_SHIELDED_COMMAND_BINDING_COST)
        deduct.assert_any_call(constants.ZK_SHIELDED_COMMAND_EXECUTION_TAG_COST)
        self.assertEqual(binding, "0x" + "44" * 32)
        self.assertEqual(tag, "0x" + "55" * 32)

    def test_shielded_output_payload_hash_uses_native_helper(self):
        bindings = {
            "shielded_output_payload_hash": lambda payload: "0x" + "66" * 32,
            "ZkEncodingError": FakeEncodingError,
            "ZkVerifierError": FakeVerifierError,
        }
        payload = "0x1234"

        with patch(
            "contracting.stdlib.bridge.zk._native_verifier_bindings",
            return_value=bindings,
        ), patch(
            "contracting.stdlib.bridge.zk.rt.deduct_execution_cost"
        ) as deduct:
            result = zk.shielded_output_payload_hash(payload)

        deduct.assert_called_once_with((len(payload) - 2) // 2)
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
