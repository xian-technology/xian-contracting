"""One contract call for the VM tests, run by the block executor's rules.

``execute_contract`` runs a call with ``xian_vm_core.execute_tx`` (the code a
block runs: preparation, entry checks, the VM, the Rust host syscalls,
metering) on a fork of ``driver``'s state, without fees. The effects are
returned and never staged; a test that keeps them applies ``writes`` itself.
The arguments are the call's VM context and budget: ``context`` holds the
signer, caller, this, entry, now, block and chain fields; ``chi_budget_raw``
is the raw budget (1000 raw per chi) of a metered call, 0 for none.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from xian_vm_core import execute_tx

from contracting.runtime_features import RUNTIME_FEATURE_ZK, runtime_feature_without_state


@dataclass(frozen=True, slots=True)
class CallResult:
    status_code: int
    result: Any
    writes: dict[str, Any]
    events: list[dict[str, Any]]
    chi_used: int
    contract_costs: dict[str, int]


def _chi_budget(chi_budget_raw: int) -> int:
    """The chi budget covering ``chi_budget_raw`` (rounded up, so a tiny raw
    budget still runs out of chi); 0 leaves a metered call unbounded."""
    return -(-max(int(chi_budget_raw), 0) // 1000)


def execute_contract(
    *,
    driver,
    contract_name: str,
    function_name: str,
    kwargs: dict | None = None,
    context: dict | None = None,
    meter: bool = False,
    chi_budget_raw: int = 0,
    transaction_size_bytes: int = 0,
) -> CallResult:
    context = dict(context or {})
    sender = context.get("signer") or context.get("caller") or "sys"
    environment, overlay = driver.committed_storage()
    run = execute_tx(
        environment,
        overlay.snapshot(),
        sender=sender,
        contract_name=contract_name,
        function_name=function_name,
        kwargs=dict(kwargs or {}),
        context=context,
        meter=meter,
        chi_budget=_chi_budget(chi_budget_raw),
        transaction_size_bytes=max(int(transaction_size_bytes), 0),
        zk_enabled_without_state=runtime_feature_without_state(driver, RUNTIME_FEATURE_ZK),
    )
    return CallResult(
        status_code=run.status_code,
        result=run.result,
        writes=dict(run.writes),
        events=list(run.events),
        chi_used=run.chi_used,
        contract_costs=dict(run.contract_costs),
    )
