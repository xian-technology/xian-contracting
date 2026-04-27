import os
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import Mock

from contracting.client import (
    AbstractContract,
    ContractingClient,
)
from contracting.compilation.artifacts import CONTRACT_ARTIFACT_FORMAT_V1
from contracting.storage.driver import Driver


class TestClient(TestCase):
    def setUp(self):
        self.client = None

        self.driver = Driver()
        
        self.script_dir = os.path.dirname(os.path.abspath(__file__))

        submission_file_path = os.path.join(self.script_dir, "contracts", "submission.s.py")
        with open(submission_file_path) as f:
            self.submission_contract_file = f.read()

    def tearDown(self):
        if self.client:
            self.client.flush()
            self.client.close()

    def test_set_submission_updates_contract_file(self):
        self.client = ContractingClient(driver=self.driver)
        self.client.flush()

        submission_1_code = self.client.raw_driver.get('submission.__code__')
        
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        submission_file_path = os.path.join(self.script_dir, "precompiled", "updated_submission.py")
        
        self.driver.flush_full()
        self.client.set_submission_contract(filename=submission_file_path)

        submission_2_code = self.client.raw_driver.get('submission.__code__')

        self.assertNotEqual(submission_1_code, submission_2_code)

    def test_default_submission_seeds_source_and_ir(self):
        self.client = ContractingClient(driver=self.driver)

        self.assertIsNotNone(
            self.client.raw_driver.get("submission.__source__")
        )
        self.assertIsNotNone(
            self.client.raw_driver.get("submission.__xian_ir_v1__")
        )

    def test_can_create_instance_without_submission_contract(self):
        self.client = ContractingClient(submission_filename=None, driver=self.driver)

        self.assertIsNotNone(self.client)

    def test_close_closes_owned_driver(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            client = ContractingClient(
                submission_filename=None,
                storage_home=Path(tmpdir),
            )
            store = client.raw_driver._store

            client.close()

            self.assertIsNone(store._env)

    def test_close_leaves_injected_driver_open(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            driver = Driver(storage_home=Path(tmpdir))
            client = ContractingClient(
                submission_filename=None,
                driver=driver,
            )

            client.close()

            driver.set_var("currency", "balances", ["alice"], value=1000)
            driver.commit()
            self.assertEqual(
                driver.get_var("currency", "balances", ["alice"]),
                1000,
            )
            driver.close()

    def test_context_manager_closes_owned_driver(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with ContractingClient(
                submission_filename=None,
                storage_home=Path(tmpdir),
            ) as client:
                store = client.raw_driver._store

            self.assertIsNone(store._env)

    def test_gets_submission_contract_from_state_if_no_filename_provided(self):
        self.driver.set_contract(name='submission', code=self.submission_contract_file)
        self.driver.commit()

        self.client = ContractingClient(submission_filename=None, driver=self.driver)

        self.assertIsNotNone(self.client.submission_contract)

    def test_set_submission_contract__sets_from_submission_filename_property(self):
        self.client = ContractingClient(driver=self.driver)

        self.client.raw_driver.flush_full()
        self.client.submission_contract = None

        contract = self.client.raw_driver.get_contract('submission')
        self.assertIsNone(contract)
        self.assertIsNone(self.client.submission_contract)

        self.client.set_submission_contract()

        contract = self.client.raw_driver.get_contract('submission')
        self.assertIsNotNone(contract)
        self.assertIsNotNone(self.client.submission_contract)

    def test_set_submission_contract__sets_from_submission_from_state(self):
        self.client = ContractingClient(driver=self.driver)

        self.client.raw_driver.flush_full()
        self.client.submission_contract = None

        contract = self.client.raw_driver.get_contract('submission')
        self.assertIsNone(contract)
        self.assertIsNone(self.client.submission_contract)

        self.driver.set_contract(name='submission', code=self.submission_contract_file)
        self.driver.commit()

        self.client.set_submission_contract()

        contract = self.client.raw_driver.get_contract('submission')
        self.assertIsNotNone(contract)
        self.assertIsNotNone(self.client.submission_contract)

    def test_set_submission_contract__no_contract_provided_or_found_raises_AssertionError(self):
        self.client = ContractingClient(driver=self.driver)

        self.client.raw_driver.flush_full()
        self.client.submission_filename = None

        with self.assertRaises(AssertionError):
            self.client.set_submission_contract()

    def test_submit__raises_AssertionError_if_no_submission_contract_set(self):
        self.client = ContractingClient(submission_filename=None, driver=self.driver)

        with self.assertRaises(AssertionError):
            self.client.submit(f="")

    def test_closure_to_code_string_dedents_and_unparses_nested_source(self):
        self.client = ContractingClient(submission_filename=None, driver=self.driver)

        def con_nested_source():
            values=[1,2,3]

            @export
            def get():
                return values[0]

        code, name = self.client.closure_to_code_string(con_nested_source)

        self.assertEqual(name, "con_nested_source")
        self.assertIn("values = [1, 2, 3]", code)

    def test_closure_to_code_string_does_not_execute_source(self):
        self.client = ContractingClient(submission_filename=None, driver=self.driver)
        sentinel = Path(tempfile.gettempdir()) / "xian_closure_source_probe"
        if sentinel.exists():
            sentinel.unlink()

        def con_source_probe():
            payload = f"; touch {sentinel}"

            @export
            def get():
                return payload

        code, name = self.client.closure_to_code_string(con_source_probe)

        self.assertEqual(name, "con_source_probe")
        self.assertIn("touch", code)
        self.assertFalse(sentinel.exists())

    def test_build_deployment_artifacts_returns_canonical_bundle(self):
        self.client = ContractingClient(submission_filename=None, driver=self.driver)

        artifacts = self.client.build_deployment_artifacts(
            """
v = Variable()

@construct
def seed(value: int = 1):
    v.set(value)

@export
def ping():
    return v.get()
""",
            name="con_bundle_probe",
        )

        self.assertEqual(artifacts["format"], CONTRACT_ARTIFACT_FORMAT_V1)
        self.assertEqual(artifacts["module_name"], "con_bundle_probe")
        self.assertEqual(artifacts["vm_profile"], "xian_vm_v1")
        self.assertIn("source", artifacts)
        self.assertNotIn("runtime_code", artifacts)
        self.assertIn("vm_ir_json", artifacts)
        self.assertIn("hashes", artifacts)

    def test_submit_includes_deployment_artifacts(self):
        self.client = ContractingClient(submission_filename=None, driver=self.driver)
        self.client.submission_contract = Mock()

        code = """
v = Variable()

@construct
def seed(value: int = 1):
    v.set(value)

@export
def ping():
    return v.get()
"""
        self.client.submit(f=code, name="con_submit_probe")

        self.client.submission_contract.submit_contract.assert_called_once()
        kwargs = self.client.submission_contract.submit_contract.call_args.kwargs
        self.assertEqual(kwargs["name"], "con_submit_probe")
        self.assertEqual(kwargs["code"], code)
        self.assertEqual(
            kwargs["deployment_artifacts"]["module_name"],
            "con_submit_probe",
        )
        self.assertEqual(
            kwargs["deployment_artifacts"]["format"],
            CONTRACT_ARTIFACT_FORMAT_V1,
        )

    def test_abstract_function_call_raises_result_on_error_by_default(self):
        error = RuntimeError("boom")
        output = {
            "status_code": 1,
            "result": error,
            "chi_used": 5,
            "writes": {},
            "reads": {},
            "events": [],
        }
        executor = Mock()
        executor.execute.return_value = output
        executor.production = False

        contract = AbstractContract(
            name="test_contract",
            signer="stu",
            environment={},
            executor=executor,
            funcs=[("failing_function", [])],
        )

        with self.assertRaisesRegex(RuntimeError, "boom"):
            contract.failing_function()

    def test_abstract_function_call_returns_full_output_on_error_when_requested(self):
        error = RuntimeError("boom")
        output = {
            "status_code": 1,
            "result": error,
            "chi_used": 5,
            "writes": {},
            "reads": {},
            "events": [],
        }
        executor = Mock()
        executor.execute.return_value = output
        executor.production = False

        contract = AbstractContract(
            name="test_contract",
            signer="stu",
            environment={},
            executor=executor,
            funcs=[("failing_function", [])],
        )

        result = contract.failing_function(return_full_output=True)

        self.assertIs(result, output)
        self.assertEqual(result["status_code"], 1)
        self.assertIs(result["result"], error)
