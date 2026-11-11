import os
from tempfile import TemporaryDirectory
from unittest import TestCase

from contracting.local import ContractingClient
from contracting.storage.driver import Driver


class TestSenecaClientReplacesExecutor(TestCase):
    def setUp(self):
        self.c = ContractingClient(signer="stu")
        self.addCleanup(self.c.close)
        self.c.flush()

        # submit erc20 clone
        constructor_args_contract_path = os.path.join(
            os.path.dirname(__file__),
            "test_contracts",
            "constructor_args_contract.s.py",
        )

        with open(constructor_args_contract_path) as f:
            self.code = f.read()

    def test_custom_args_works(self):
        self.c.submit(
            self.code,
            name="con_constructor_args_contract",
            constructor_args={"a": 123, "b": 321},
        )

        contract = self.c.get_contract_proxy("con_constructor_args_contract")
        a, b = contract.get()

        self.assertEqual(a, 123)
        self.assertEqual(b, 321)

    def test_custom_args_overloading(self):
        with self.assertRaises(TypeError):
            self.c.submit(
                self.code,
                name="con_constructor_args_contract",
                constructor_args={"a": 123, "x": 321},
            )

    def test_custom_args_not_enough_args(self):
        with self.assertRaises(TypeError):
            self.c.submit(
                self.code,
                name="con_constructor_args_contract",
                constructor_args={"a": 123},
            )

    def test_native_deployment_uses_provided_driver_for_constructor(self):
        with TemporaryDirectory() as path, Driver(storage_home=path) as driver:
            with ContractingClient(driver=driver) as client:
                client.submit(
                    self.code,
                    name="con_constructor_args_contract",
                    constructor_args={"a": 123, "b": 321},
                )
                client.raw_driver.commit()
                self.assertEqual(
                    client.get_contract_proxy("con_constructor_args_contract").get(), (123, 321)
                )
                self.assertTrue(driver.has_contract("con_constructor_args_contract"))
                self.assertFalse(self.c.raw_driver.has_contract("con_constructor_args_contract"))
