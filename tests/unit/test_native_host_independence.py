"""Native host operations must not load or initialize the Python execution engine."""

import subprocess
import sys
import textwrap

import pytest


PYTHON_ENGINE_IMPORT_GUARD = """
import importlib.abc
import sys

blocked = {
    "contracting.execution.executor",
    "contracting.execution.module",
    "contracting.execution.python_tracer",
    "contracting.execution.tracer",
    "contracting.execution.tracer_common",
}
class BlockPythonEngine(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname in blocked:
            raise AssertionError(f"native host imported {fullname}")
sys.meta_path.insert(0, BlockPythonEngine())
"""


def run_fresh(source, *arguments):
    program = PYTHON_ENGINE_IMPORT_GUARD + textwrap.dedent(source)
    result = subprocess.run(
        [sys.executable, "-c", program, *map(str, arguments)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_storage_works_with_python_execution_imports_blocked(tmp_path):
    run_fresh(
        """
        from contracting.storage.driver import Driver

        with Driver(storage_home=sys.argv[1]) as driver:
            driver.set("con_native.value", 42)
            driver.commit()
            assert driver.get("con_native.value") == 42
        assert not blocked.intersection(sys.modules)
        """,
        tmp_path / "store",
    )


@pytest.mark.optional_native
def test_native_execution_runs_without_python_execution(tmp_path):
    run_fresh(
        """
        from contracting.artifacts import compile_contract_source
        from contracting.storage.driver import Driver
        from tests.vm_calls import execute_contract

        source = '''
        value = Variable()
        @export
        def put(amount: int, fail: bool):
            value.set(amount)
            assert not fail, "rollback"
            return ctx.caller
        '''
        source = __import__("textwrap").dedent(source).strip()
        artifact = compile_contract_source(module_name="con_host_independence", source=source)
        with Driver(storage_home=sys.argv[1]) as driver:
            driver.set_contract(
                "con_host_independence", source=artifact["source"],
                vm_ir_json=artifact["vm_ir_json"]
            )
            driver.commit()
            for fail in (False, True):
                result = execute_contract(
                    driver=driver, contract_name="con_host_independence",
                    function_name="put", kwargs={"amount": 17, "fail": fail},
                    context={"caller": "alice", "signer": "alice"},
                )
                assert result.status_code == int(fail), result
                if fail:
                    assert result.writes == {}, result
                else:
                    assert result.result == "alice", result
                    assert result.writes["con_host_independence.value"] == 17, result
        assert not blocked.intersection(sys.modules)
        """,
        tmp_path / "store",
    )


@pytest.mark.optional_native
def test_native_zk_syscall_keeps_exact_metering_without_python_execution(tmp_path):
    run_fresh(
        """
        from contracting.artifacts import compile_contract_source
        from contracting.storage.driver import Driver
        from tests.vm_calls import execute_contract

        source = (
            "@export\\ndef payload_hash(payload: str):\\n"
            "    return zk.shielded_output_payload_hash(payload)"
        )
        artifact = compile_contract_source(module_name="con_zk_host_meter", source=source)
        cases = [
            ("0x1234", "0x0feb163751a5811a7274c305e97bd758478907b941889bb7463e6895f7231fdb"),
            ("0x123456", "0x00c55be8ddcc5127ba04bb81cfbae05b7b83257dc70ee084bfa697d4b1beaf0d"),
        ]
        with Driver(storage_home=sys.argv[1]) as driver:
            driver.set_contract(
                "con_zk_host_meter", source=artifact["source"],
                vm_ir_json=artifact["vm_ir_json"]
            )
            driver.commit()
            for payload, digest in cases:
                result = execute_contract(
                    driver=driver, contract_name="con_zk_host_meter",
                    function_name="payload_hash", kwargs={"payload": payload},
                    context={"caller": "alice", "signer": "alice"},
                    meter=True, chi_budget_raw=100_000_000,
                )
                assert result.status_code == 0, result
                assert result.result == digest, result
                assert result.chi_used == 15, result
            failure = execute_contract(
                driver=driver, contract_name="con_zk_host_meter",
                function_name="payload_hash", kwargs={"payload": "0x1234"},
                context={"caller": "alice", "signer": "alice"},
                meter=True, chi_budget_raw=1,
            )
            assert failure.status_code == 1, failure
            assert failure.result == "Out of chi.", failure
            assert failure.writes == {}, failure
        assert not blocked.intersection(sys.modules)
        """,
        tmp_path / "zk",
    )
