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
        zk.rt.env.pop("__Driver", None)

    def test_is_available_false_when_native_package_missing(self):
        with patch(
            "contracting.stdlib.bridge.zk._native_verifier_bindings",
            return_value=None,
        ):
            self.assertFalse(zk.is_available())

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
                (len(vk_hex) + len(proof_hex) + sum(len(v) for v in public_inputs))
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
        self.assertEqual(len(verify_calls), 2)

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
