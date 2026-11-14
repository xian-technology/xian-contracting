import json
from dataclasses import dataclass
from typing import Any

from xian_runtime_types.encoding import decode_wire_numbers, normalize_wire_numbers

from ._native import (
    MAX_STORAGE_KEY_BYTES,
    BlockExecutor,
    BlockState,
    LmdbEnvironment,
    LmdbItems,
    LmdbMapFullError,
    LmdbStorageError,
    StateRootTree,
    VmIrValidationError,
    VmRuntimeExecutionError,
    decode_and_validate_transaction,
    runtime_info_json,
    state_root_leaf_hash,
    stored_value_bytes,
    supports_execution_policy,
    validate_module_ir_json,
    validate_storage_key,
    validated_chi_rate,
)
from ._native import (
    execute_tx as _execute_tx,
)


def runtime_info(vm_profile: str = "xian_vm_v2") -> dict:
    return json.loads(runtime_info_json(vm_profile))


def validate_module_ir(module_ir: dict | str) -> None:
    payload = (
        module_ir
        if isinstance(module_ir, str)
        else json.dumps(module_ir, separators=(",", ":"), sort_keys=True)
    )
    validate_module_ir_json(payload)


@dataclass(frozen=True, slots=True)
class TxRun:
    """One call run by the block executor's rules (``execute_tx``)."""

    status_code: int
    # The return value; for a failure its exception when the VM gave its
    # type, else the failure text (``native_error_result``).
    result: Any
    # Staged writes in receipt order; a deletion is None.
    writes: dict[str, Any]
    events: list[dict[str, Any]]
    chi_used: int
    contract_costs: dict[str, int]
    # The contract cannot run in current chain state (preparation refused it).
    unprepared: bool


def execute_tx(
    environment,
    overlay,
    *,
    sender: str,
    contract_name: str,
    function_name: str,
    kwargs: dict,
    context: dict,
    meter: bool,
    charge_fees: bool = False,
    chi_budget: int = 0,
    transaction_size_bytes: int = 0,
    protected_keys=(),
    zk_enabled_without_state: bool = True,
    estimate: bool = False,
) -> TxRun:
    """Run one call with the code a block runs, over ``environment`` (LMDB)
    and ``overlay`` (a ``BlockState``), staging its effects into ``overlay``.

    Pass ``overlay.snapshot()`` to drop them afterwards. ``context`` is the
    call's VM context (``signer``, ``caller``, ``this``, ``entry``,
    ``submission_name``, ``now``, ``block_num``, ``block_hash``,
    ``chain_id``, ``__input_hash``); ``estimate`` settles the fee
    as a dry run does (no budget reservation). A call whose arguments the VM
    boundary refuses fails before execution (status 1, the refusal as its
    result, no chi, nothing staged).
    """
    try:
        coerced_kwargs = coerce_call_kwargs(kwargs)
    except Exception as exc:  # noqa: BLE001 - the refusal is the call's result
        return _refused_call(exc)
    outcome, reason = _execute_tx(
        environment,
        overlay,
        sender=sender,
        contract=contract_name,
        function=function_name,
        kwargs=coerced_kwargs,
        context=context,
        chi_budget=chi_budget,
        transaction_size_bytes=transaction_size_bytes,
        meter_execution=meter,
        charge_fees=charge_fees,
        protected_keys=list(protected_keys),
        zk_enabled_without_state=zk_enabled_without_state,
        estimate=estimate,
    )
    if outcome is None:
        return _refused_call(ValueError(reason))
    return TxRun(
        status_code=outcome["status"],
        result=native_error_result(
            outcome["status"], outcome["result"], exception=outcome["exception"]
        ),
        writes=dict(outcome["writes"]),
        events=outcome["events"],
        chi_used=outcome["chi_used"],
        contract_costs=outcome["contract_costs"],
        unprepared=outcome["unprepared"],
    )


def _refused_call(error: Exception) -> TxRun:
    """A call whose inputs the VM does not take: it fails before execution."""
    return TxRun(
        status_code=1,
        result=error,
        writes={},
        events=[],
        chi_used=0,
        contract_costs={},
        unprepared=False,
    )


def coerce_call_kwargs(kwargs: dict[str, Any]) -> dict[str, Any]:
    """Keyword arguments of an external call, as the VM receives them."""
    return decode_wire_numbers(normalize_wire_numbers(kwargs))


def native_error_result(status_code: int, result: Any, *, exception=None) -> Any:
    """The receipt result of a native execution: the structured exception of
    a failure when there is one, else the value or failure text. Failure
    text is never interpreted: only the VM's structured exception selects a
    type; anything else remains an opaque message."""
    if int(status_code) == 0 or not isinstance(result, str):
        return result
    return _structured_native_exception(exception) or result


_NATIVE_EXCEPTION_TYPES: dict[str, type[BaseException]] = {
    "AssertionError": AssertionError,
    "TypeError": TypeError,
    "ValueError": ValueError,
    "RuntimeError": RuntimeError,
    "Exception": Exception,
    "KeyError": KeyError,
    "IndexError": IndexError,
}


def _structured_native_exception(exception) -> BaseException | None:
    if exception is None:
        return None
    name, args = exception
    exception_type = _NATIVE_EXCEPTION_TYPES.get(name)
    return None if exception_type is None else exception_type(*args)


__all__ = [
    "MAX_STORAGE_KEY_BYTES",
    "BlockExecutor",
    "BlockState",
    "LmdbEnvironment",
    "LmdbItems",
    "LmdbMapFullError",
    "LmdbStorageError",
    "StateRootTree",
    "VmIrValidationError",
    "VmRuntimeExecutionError",
    "TxRun",
    "coerce_call_kwargs",
    "decode_and_validate_transaction",
    "execute_tx",
    "native_error_result",
    "runtime_info",
    "runtime_info_json",
    "state_root_leaf_hash",
    "stored_value_bytes",
    "supports_execution_policy",
    "validate_module_ir",
    "validate_module_ir_json",
    "validate_storage_key",
    "validated_chi_rate",
]
