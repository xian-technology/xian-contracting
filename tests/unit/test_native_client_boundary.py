"""The supported local harness executes native V2 without a Python engine."""

import os
import subprocess
import sys
import textwrap

import pytest

from contracting.local import ContractingClient
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


def test_archival_v1_artifacts_are_stored_but_never_executed(tmp_path):
    # V1 compilation and storage stay for archival tooling; current code has
    # no V1 execution (V1 replays on its pinned release).
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

        assert driver.get_contract_ir("con_archive") == compiled["vm_ir_json"]
        # The VM executes over V2 storage only.
        assert driver.committed_storage() is None


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
