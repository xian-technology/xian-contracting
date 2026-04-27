import glob
import os
import subprocess
import sys
import tempfile
import types
from contextvars import copy_context
from unittest import TestCase

from contracting.execution.module import (
    ContractModuleFinder,
    ContractModuleLoader,
    install_contract_module_loader,
    uninstall_contract_module_loader,
)
from contracting.names import is_safe_contract_name
from contracting.storage.driver import Driver


class TestContractStorage(TestCase):
    def setUp(self):
        self.d = Driver()
        self.d.flush_full()

    def tearDown(self):
        self.d.flush_full()

    def test_push_and_get_contract(self):
        code = "a = 123"
        name = "test"

        self.d.set_contract(name, code)
        _code = self.d.get_contract(name)

        self.assertEqual(
            code,
            _code,
            "Pushing and getting contracts is not working.",
        )

    def test_flush(self):
        code = "a = 123"
        name = "test"

        self.d.set_contract(name, code)
        self.d.commit()
        self.d.flush_full()

        self.assertIsNone(self.d.get_contract(name))


class TestContractModuleLoader(TestCase):
    def setUp(self):
        self.loader = ContractModuleLoader()

    def test_init(self):
        self.assertTrue(
            isinstance(self.loader.driver, Driver),
            "self.loader.driver is not a Driver object.",
        )

    def test_create_module(self):
        self.assertEqual(
            self.loader.create_module(None),
            None,
            "self.create_module should return None",
        )

    def test_exec_module(self):
        module = types.ModuleType("test")

        self.loader.driver.set_contract("test", "b = 1337")
        self.loader.exec_module(module)
        self.loader.driver.flush_full()

        self.assertEqual(module.b, 1337)

    def test_exec_module_nonattribute(self):
        module = types.ModuleType("test")

        self.loader.driver.set_contract("test", "b = 1337")
        self.loader.exec_module(module)
        self.loader.driver.flush_full()

        with self.assertRaises(AttributeError):
            module.a

    def test_module_representation(self):
        module = types.ModuleType("howdy")

        self.assertEqual(
            self.loader.module_repr(module),
            "<module 'howdy' (smart contract)>",
        )


class TestInstallLoader(TestCase):
    def test_contract_module_finder_does_not_open_default_driver_on_import(
        self,
    ):
        with tempfile.TemporaryDirectory() as home_dir:
            env = os.environ.copy()
            env["HOME"] = home_dir
            script = """
from pathlib import Path

from contracting.client import ContractingClient
from contracting.execution.module import ContractModuleFinder

storage_home = Path.home() / ".cometbft" / "xian"
assert ContractModuleFinder.default_driver is None
ContractingClient(storage_home=storage_home, submission_filename=None)
print("ok")
"""
            result = subprocess.run(
                [sys.executable, "-c", script],
                capture_output=True,
                text=True,
                env=env,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), "ok")

    def test_install_loader(self):
        uninstall_contract_module_loader()

        self.assertNotIn(ContractModuleFinder, sys.meta_path)

        install_contract_module_loader()

        self.assertIn(ContractModuleFinder, sys.meta_path)

        uninstall_contract_module_loader()

        self.assertNotIn(ContractModuleFinder, sys.meta_path)

    def test_integration_and_importing(self):
        loader = ContractModuleLoader()
        module_name = "testing_integration"
        sys.modules.pop(module_name, None)
        loader.driver.set_contract(module_name, "a = 1234567890")
        loader.driver.commit()

        install_contract_module_loader(driver=loader.driver)

        imported = __import__(module_name)

        self.assertEqual(imported.a, 1234567890)

    def test_finder_uses_context_local_driver(self):
        with (
            tempfile.TemporaryDirectory() as storage_a,
            tempfile.TemporaryDirectory() as storage_b,
        ):
            driver_a = Driver(storage_home=storage_a)
            driver_b = Driver(storage_home=storage_b)

            driver_a.flush_full()
            driver_b.flush_full()
            driver_a.set_contract("testing", "a = 111")
            driver_b.set_contract("testing", "a = 222")
            driver_a.commit()
            driver_b.commit()

            install_contract_module_loader(driver=driver_a)

            def resolve_contract(driver, expected):
                install_contract_module_loader(driver=driver)
                spec = ContractModuleFinder.find_spec("testing")
                self.assertIsNotNone(spec)
                return spec.loader.driver.get_contract("testing") == expected

            context_a = copy_context()
            context_b = copy_context()

            self.assertTrue(
                context_a.run(resolve_contract, driver_a, "a = 111")
            )
            self.assertTrue(
                context_b.run(resolve_contract, driver_b, "a = 222")
            )


driver = Driver()


class TestModuleLoadingIntegration(TestCase):
    def setUp(self):
        install_contract_module_loader(driver=driver)
        driver.flush_full()

        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        contracts = glob.glob(
            os.path.join(self.script_dir, "test_sys_contracts", "*.py")
        )
        for contract in contracts:
            name = contract.split("/")[-1].split(".")[0]
            if not is_safe_contract_name(name):
                continue

            with open(contract) as f:
                code = f.read()

            driver.set_contract(name=name, code=code)
            driver.commit()

    def tearDown(self):
        uninstall_contract_module_loader()
        for module_name in tuple(sys.modules):
            if module_name.startswith("module"):
                sys.modules.pop(module_name, None)
        driver.flush_full()

    def test_get_code_string(self):
        ctx = types.ModuleType("ctx")
        code = """import module1

print("now i can run my functions!")
"""

        exec(code, vars(ctx))

        print("ok do it again")

        exec(code, vars(ctx))
