import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import Mock

from contracting.artifacts import CONTRACT_ARTIFACT_FORMAT_V1
from contracting.local import (
    AbstractContract,
    ContractingClient,
)
from contracting.storage.driver import Driver


class TestClient(TestCase):
    def setUp(self):
        self.client = None

        self.driver = Driver()
        self.addCleanup(self.driver.close)

    def tearDown(self):
        if self.client:
            self.client.close()

    def test_set_submission_updates_native_source_and_ir(self):
        self.client = ContractingClient(driver=self.driver)
        original_source = self.client.get_contract_source("submission")
        original_ir = self.client.get_contract_ir("submission")
        replacement = Path.home() / "updated_submission.s.py"
        replacement.write_text("@export\ndef version():\n    return 2\n")

        self.client.set_submission_contract(filename=replacement)

        self.assertNotEqual(original_source, self.client.get_contract_source("submission"))
        self.assertNotEqual(original_ir, self.client.get_contract_ir("submission"))
        self.assertEqual(self.client.submission_contract.version(), 2)
        with Driver(storage_home=self.driver.storage_home) as reopened:
            with ContractingClient(submission_filename=None, driver=reopened) as reader:
                self.assertEqual(reader.submission_contract.version(), 2)

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
        self.driver.set_contract_from_source(
            name="submission", source="@export\ndef submit_contract():\n    pass",
        )
        self.driver.commit()

        self.client = ContractingClient(submission_filename=None, driver=self.driver)

        self.assertIsNotNone(self.client.submission_contract)

    def test_set_submission_contract__sets_from_submission_filename_property(self):
        self.client = ContractingClient(driver=self.driver)

        self.client.raw_driver.flush_full()
        self.client.submission_contract = None

        contract = self.client.get_contract_ir('submission')
        self.assertIsNone(contract)
        self.assertIsNone(self.client.submission_contract)

        self.client.set_submission_contract()

        contract = self.client.get_contract_ir('submission')
        self.assertIsNotNone(contract)
        self.assertIsNotNone(self.client.submission_contract)

    def test_set_submission_contract__sets_from_submission_from_state(self):
        self.client = ContractingClient(driver=self.driver)

        self.client.raw_driver.flush_full()
        self.client.submission_contract = None

        contract = self.client.get_contract_ir('submission')
        self.assertIsNone(contract)
        self.assertIsNone(self.client.submission_contract)

        self.driver.set_contract_from_source(
            name="submission", source="@export\ndef submit_contract():\n    pass",
        )
        self.driver.commit()

        self.client.set_submission_contract()

        contract = self.client.get_contract_ir('submission')
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

    def test_closure_to_code_string_preserves_original_source(self):
        self.client = ContractingClient(submission_filename=None, driver=self.driver)

        def con_nested_source():
            values=[1,2,3]

            @export
            def get():
                return values[0]

        code, name = self.client.closure_to_code_string(con_nested_source)

        self.assertEqual(name, "con_nested_source")
        self.assertIn("values=[1,2,3]", code)

    def test_closure_to_code_string_does_not_execute_source(self):
        self.client = ContractingClient(submission_filename=None, driver=self.driver)
        sentinel = Path.home() / "xian_closure_source_probe"

        def con_source_probe():
            payload = f"; touch {sentinel}"

            @export
            def get():
                return payload

        code, name = self.client.closure_to_code_string(con_source_probe)

        self.assertEqual(name, "con_source_probe")
        self.assertIn("touch", code)
        self.assertFalse(sentinel.exists())

    def test_build_contract_artifacts_returns_canonical_bundle(self):
        self.client = ContractingClient(submission_filename=None, driver=self.driver)

        artifacts = self.client.build_contract_artifacts(
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
        self.assertEqual(artifacts["vm_profile"], "xian_vm_v2")
        self.assertIn("source", artifacts)
        self.assertNotIn("runtime_code", artifacts)
        self.assertIn("vm_ir_json", artifacts)
        self.assertIn("hashes", artifacts)

    def test_submit_includes_source_code(self):
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
        self.assertIn("def ping():", kwargs["code"])
        self.assertNotIn("deployment_artifacts", kwargs)

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


def test_default_client_runs_exact_native_arithmetic(tmp_path):
    from decimal import Decimal

    with ContractingClient(storage_home=tmp_path) as client:
        assert client.vm_profile == "xian_vm_v2"
        client.submit("@export\ndef divide():\n    return 1 / 3", name="con_divide")
        assert client.get_contract_proxy("con_divide").divide() == Decimal("0." + "3" * 30)


def test_native_client_lint_reports_and_raises_canonical_diagnostics(tmp_path):
    import pytest

    with ContractingClient(storage_home=tmp_path, submission_filename=None) as client:
        valid = "@export\ndef answer():\n    return 42\n"
        assert client.lint(valid) is None
        assert client.lint(valid, raise_errors=True) is None

        rejected = '@export\ndef forbidden():\n    return open("file")\n'
        diagnostics = client.lint(rejected)
        assert diagnostics[0]["code"] == "xian.lint.E014"
        assert "'open' is not allowed" in diagnostics[0]["message"]
        with pytest.raises(ValueError, match="'open' is not allowed"):
            client.lint(rejected, raise_errors=True)


def test_native_client_compiles_and_lints_function_source(tmp_path):
    with ContractingClient(storage_home=tmp_path) as client:
        def con_function_source():
            @export
            def answer():
                return 42

        assert client.lint(con_function_source) is None
        source = client.compile(con_function_source)
        assert "def answer():" in source
        assert "return 42" in source
        client.submit(source, name="con_function_source")
        assert client.get_contract_proxy("con_function_source").answer() == 42


def test_native_client_preserves_explicit_environment_and_adapter_defaults(tmp_path):
    from xian_runtime_types.time import Datetime

    environment = {"now": Datetime(2020, 1, 1)}
    with ContractingClient(storage_home=tmp_path, environment=environment) as client:
        client.submit("@export\ndef current_year():\n    return now.year\n", name="con_time")
        contract = client.get_contract_proxy("con_time")
        assert contract.current_year() == 2020
        assert contract.current_year(environment={"now": Datetime(2024, 1, 1)}) == 2024
        assert environment["now"].year == 2020

        output = client.executor.execute(
            sender="alice", contract_name="con_time", function_name="current_year", kwargs={}
        )
        assert output["status_code"] == 0, output["result"]
        assert output["result"] == 1970


def test_native_client_defaults_to_unmetered_calls_and_supports_explicit_metering(tmp_path):
    from contracting import constants

    with ContractingClient(storage_home=tmp_path) as client:
        client.submit("@export\ndef answer():\n    return 42\n", name="con_meter")
        contract = client.get_contract_proxy("con_meter")
        unmetered = contract.answer(return_full_output=True)
        metered = contract.answer(metering=True, return_full_output=True)
        assert unmetered["result"] == metered["result"] == 42
        assert unmetered["chi_used"] == constants.TRANSACTION_BASE_CHI
        assert metered["chi_used"] > unmetered["chi_used"]


def test_ordinary_call_name_argument_cannot_spoof_submission_context(tmp_path):
    with ContractingClient(storage_home=tmp_path) as client:
        client.submit(
            "@export\ndef submission_context(name: str):\n    return ctx.submission_name\n",
            name="con_context",
        )
        contract = client.get_contract_proxy("con_context")
        assert contract.submission_context(
            name="con_spoof", environment={"submission_name": "stale"}
        ) is None
