import json
import os
from unittest import TestCase

import pytest

pytest.importorskip("xian_zk")

from contracting.client import ContractingClient


class TestZkBridge(TestCase):
    def setUp(self):
        self.c = ContractingClient(signer="stu")
        self.c.raw_driver.flush_full()

        submission_path = os.path.join(
            os.path.dirname(__file__),
            "test_contracts",
            "submission.s.py",
        )
        with open(submission_path) as submission_file:
            self.c.raw_driver.set_contract(
                name="submission",
                code=submission_file.read(),
            )
        self.c.raw_driver.commit()

        contract_path = os.path.join(
            os.path.dirname(__file__),
            "test_contracts",
            "zk_probe.s.py",
        )
        with open(contract_path) as contract_file:
            self.c.submit(contract_file.read(), name="con_zk_probe")

        fixture_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "..",
            "packages",
            "xian-zk",
            "tests",
            "fixtures",
            "groth16_bn254_demo.json",
        )
        fixture_path = os.path.abspath(fixture_path)
        with open(fixture_path) as fixture_file:
            self.fixture = json.load(fixture_file)

        self.contract = self.c.get_contract("con_zk_probe")

    def tearDown(self):
        self.c.raw_driver.flush_full()

    def test_runtime_reports_zk_availability(self):
        self.assertTrue(self.contract.available())

    def test_contract_verifies_demo_vector(self):
        self.assertTrue(
            self.contract.verify(
                vk_hex=self.fixture["vk_hex"],
                proof_hex=self.fixture["proof_hex"],
                public_inputs=self.fixture["public_inputs"],
            )
        )

    def test_contract_returns_false_for_invalid_proof_inputs(self):
        tampered = list(self.fixture["public_inputs"])
        tampered[0] = (
            "0x0000000000000000000000000000000000000000000000000000000000000001"
        )
        self.assertFalse(
            self.contract.verify(
                vk_hex=self.fixture["vk_hex"],
                proof_hex=self.fixture["proof_hex"],
                public_inputs=tampered,
            )
        )

    def test_contract_rejects_malformed_inputs(self):
        with self.assertRaises(AssertionError):
            self.contract.verify(
                vk_hex=self.fixture["vk_hex"][2:],
                proof_hex=self.fixture["proof_hex"],
                public_inputs=self.fixture["public_inputs"],
            )
