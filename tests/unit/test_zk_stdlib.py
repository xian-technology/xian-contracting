from unittest import TestCase
from unittest.mock import patch

from contracting import constants
from contracting.stdlib.bridge import zk


class FakeEncodingError(Exception):
    pass


class FakeVerifierError(Exception):
    pass


class TestZkStdlib(TestCase):
    def setUp(self):
        zk._native_verifier_bindings.cache_clear()

    def tearDown(self):
        zk._native_verifier_bindings.cache_clear()

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
