"""Rejected deployment receipts and committed fee effects are consensus data."""

import json
import os
import subprocess
import sys
import textwrap


def test_paid_conflicting_source_has_the_same_receipt_and_state_in_fresh_processes():
    program = textwrap.dedent(
        """
        import json
        import tempfile
        from pathlib import Path
        from xian_runtime_types.decimal import ContractingDecimal
        from xian_runtime_types.time import Datetime
        from xian_vm_core import StateRootTree
        from xian_vm_core._native import execute_tx
        from contracting.local.client import BUILTIN_SUBMISSION_SOURCE_PATH
        from contracting.storage.driver import Driver
        from tests.determinism.observer import encode_exact

        source = 'a = 1\\nb = 2\\n@export\\ndef a():\\n    return 1\\n@export\\ndef b():\\n    return 2\\n'
        now = Datetime(2026, 1, 1)
        with tempfile.TemporaryDirectory() as home:
            with Driver(storage_home=home, vm_profile='xian_vm_v2') as driver:
                driver.set_contract('submission', source=BUILTIN_SUBMISSION_SOURCE_PATH.read_text(), timestamp=now)
                driver.set('currency.balances:alice', ContractingDecimal('100000'))
                driver.set('chi_cost.S:value', 20)
                driver.commit()
                environment, pending = driver.committed_storage()
                outcome, reason = execute_tx(environment, pending,
                    sender='alice', contract='submission', function='submit_contract',
                    kwargs={'name': 'con_conflict', 'code': source},
                    context={'caller': 'alice', 'signer': 'alice', 'this': 'submission',
                        'entry': ('submission', 'submit_contract'), 'now': now,
                        'block_num': 1, 'chain_id': 'local-test', '__input_hash': '11'},
                    chi_budget=50000, transaction_size_bytes=0, meter_execution=True,
                    charge_fees=True, protected_keys=[], zk_enabled_without_state=True)
                assert reason is None, reason
                assert outcome['status'] == 1
                assert "conflicting module binding 'a'" in str(outcome['result'])
                assert sum(outcome['contract_costs'].values()) >= 15000000
                assert [key for key, _ in outcome['writes']] == ['currency.balances:alice']
                assert outcome['events'] == []
                driver.commit()
                root = StateRootTree.from_storage(environment, [], []).root_hash.hex()
                print(json.dumps({'receipt': encode_exact(outcome), 'root': root}))
        """
    )
    observations = []
    for seed in range(16):
        result = subprocess.run(
            [sys.executable, "-c", program],
            env={**os.environ, "PYTHONHASHSEED": str(seed), "TZ": "UTC"},
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        observations.append(json.loads(result.stdout))
    assert all(observation == observations[0] for observation in observations[1:])
