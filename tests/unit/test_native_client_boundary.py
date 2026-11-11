"""The supported local harness executes native V2 without a Python engine."""

import os
import subprocess
import sys
import textwrap

import pytest

from contracting.execution.parallel import ParallelBatchExecutor
from contracting.local import ContractingClient
from contracting.local.native_executor import NativeExecutor
from contracting.storage.driver import Driver


@pytest.mark.parametrize("profile", ["xian_vm_v1", "unknown"])
def test_public_client_rejects_non_v2_before_creating_storage(tmp_path, profile):
    home = tmp_path / "must-not-open"
    with pytest.raises(ValueError, match="ContractingClient only supports xian_vm_v2"):
        with ContractingClient(storage_home=home, vm_profile=profile, submission_filename=None):
            pass
    assert not home.exists()


def test_public_client_rejects_injected_v1_driver_without_seeding_state(tmp_path):
    with Driver(storage_home=tmp_path / "archive", vm_profile="xian_vm_v1") as driver:
        driver.set("con_archive.value", 7)
        driver.commit()
        before = set(driver.keys())
        with pytest.raises(ValueError, match="ContractingClient only supports xian_vm_v2"):
            with ContractingClient(driver=driver):
                pass
        assert set(driver.keys()) == before
        assert driver.get("con_archive.value") == 7
        assert not driver.has_contract("submission")


@pytest.mark.parametrize("enabled", [False, True])
def test_public_parallel_rejects_native_v1_adapter_before_scheduling(tmp_path, enabled):
    with Driver(storage_home=tmp_path / "archive", vm_profile="xian_vm_v1") as driver:
        executor = NativeExecutor(driver, metering=False)
        with pytest.raises(ValueError, match="ParallelBatchExecutor only supports xian_vm_v2"):
            parallel = ParallelBatchExecutor(executor=executor, enabled=enabled, workers=1)
            parallel.close()


def test_archival_native_v1_executes_without_public_client(tmp_path):
    from xian_vm_core import execute_contract

    from contracting.artifacts import compile_contract_source
    compiled = compile_contract_source(
        module_name="con_archive",
        source="@export\ndef answer():\n    return 42\n",
        vm_profile="xian_vm_v1",
    )
    with Driver(storage_home=tmp_path / "archive", vm_profile="xian_vm_v1") as driver:
        driver.set_contract(
            name="con_archive", source=compiled["source"], vm_ir_json=compiled["vm_ir_json"]
        )
        driver.commit()
        result = execute_contract(
            driver=driver,
            contract_name="con_archive",
            function_name="answer",
            context={"signer": "sys", "caller": "sys"},
            vm_profile="xian_vm_v1",
        )

        assert result.status_code == 0, result.result
        assert result.result == 42
        assert result.writes == {}
        assert driver.get_contract_ir("con_archive") == compiled["vm_ir_json"]


def test_native_client_does_not_load_python_executor_or_tracer(tmp_path):
    program = textwrap.dedent(
        """
        import importlib.abc
        import sys

        forbidden = {
            "contracting.execution.executor",
            "contracting.execution.python_tracer",
            "contracting.execution.tracer",
        }

        class RejectPythonEngine(importlib.abc.MetaPathFinder):
            def find_spec(self, fullname, path=None, target=None):
                if fullname in forbidden:
                    raise AssertionError(f"native client imported {fullname}")

        sys.meta_path.insert(0, RejectPythonEngine())
        from contracting.local import ContractingClient

        with ContractingClient(storage_home=sys.argv[1]) as client:
            client.submit("@export\\ndef answer():\\n    return 42", name="con_answer")
            assert client.get_contract_proxy("con_answer").answer() == 42
            parallel = client.build_parallel_executor(workers=1, min_batch_size=1)
            try:
                from contracting.execution.parallel import ExecutionRequest
                outputs, stats = parallel.execute(requests=[
                    ExecutionRequest(sender="sys", contract_name="con_answer", function_name="answer")
                ])
                assert outputs[0]["status_code"] == 0, outputs
                assert outputs[0]["result"] == 42, outputs
            finally:
                parallel.close()
        assert not forbidden.intersection(sys.modules), forbidden.intersection(sys.modules)
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", program, str(tmp_path / "storage")],
        env=os.environ.copy(),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
