"""Opt-in diagnostics are private-data-free and cannot change VM observations."""

import json
import os
import re
import subprocess
import sys
import textwrap

import pytest

pytestmark = pytest.mark.optional_native

SCRIPT = textwrap.dedent("""
    import json
    import os
    from tempfile import TemporaryDirectory
    from contracting.artifacts import build_contract_artifacts
    from contracting.storage.driver import Driver
    from tests.vm_calls import execute_contract

    source = "value = Variable()\\n@export\\ndef probe(fail: bool):\\n    value.set('private-contract-value')\\n    assert not fail, 'private-error-message'\\n    return 'private-return-value'\\n"
    with TemporaryDirectory() as home:
        with Driver(storage_home=home) as driver:
            artifact = build_contract_artifacts(module_name='con_diagnostics', source=source)
            driver.set_contract('con_diagnostics', source=artifact['source'], vm_ir_json=artifact['vm_ir_json'])
            driver.commit()
            if os.environ.get('BROKEN_STDERR'):
                reader, writer = os.pipe()
                os.close(reader)
                os.dup2(writer, 2)
                os.close(writer)
            output = execute_contract(driver=driver, contract_name='con_diagnostics', function_name='probe',
                kwargs={'fail': os.environ['CASE_FAIL'] == '1'},
                context={'caller': 'private-caller', 'signer': 'private-signer', 'this': 'con_diagnostics'},
                meter=True, chi_budget_raw=100_000_000)
            print(json.dumps({'status': output.status_code, 'result': str(output.result),
                'writes': output.writes, 'events': output.events,
                'chi_used': output.chi_used, 'costs': output.contract_costs}))
""")


def run_vm(tmp_path, fail, *, trace, broken=False):
    environment = {
        key: value for key, value in os.environ.items() if not key.startswith("XIAN_VM_TRACE_")
    }
    environment.update(HOME=str(tmp_path), CASE_FAIL=str(int(fail)))
    if trace:
        environment.update(XIAN_VM_TRACE_CALLS="1", XIAN_VM_TRACE_STATEMENTS="1")
    if broken:
        environment["BROKEN_STDERR"] = "1"
    result = subprocess.run(
        [sys.executable, "-c", SCRIPT], env=environment, capture_output=True, text=True, timeout=30
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout), result.stderr


@pytest.mark.parametrize("fail", [False, True])
def test_tracing_preserves_observations_without_payloads(tmp_path, fail):
    baseline, _ = run_vm(tmp_path, fail, trace=False)
    observed, diagnostic = run_vm(tmp_path, fail, trace=True)
    assert observed == baseline
    assert diagnostic
    assert "private-" not in diagnostic
    assert re.search(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z \| DEBUG \| xian-vm \|", diagnostic
    )
    assert "contract=con_diagnostics" in diagnostic
    assert ("call_error" if fail else "call_exit") in diagnostic


@pytest.mark.parametrize("fail", [False, True])
def test_broken_stderr_cannot_change_vm_results(tmp_path, fail):
    baseline, _ = run_vm(tmp_path, fail, trace=False)
    observed, _ = run_vm(tmp_path, fail, trace=True, broken=True)
    assert observed == baseline
