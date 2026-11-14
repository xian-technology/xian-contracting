import ast
import hashlib
import json
from dataclasses import dataclass
from typing import Any

from xian_runtime_types.decimal import ContractingDecimal
from xian_runtime_types.encoding import decode_wire_numbers, encode_kv, normalize_wire_numbers

from contracting import constants
from contracting.artifacts import compile_contract_source
from contracting.execution.runtime import WRITE_MAX, rt
from contracting.names import assert_safe_contract_name
from contracting.runtime_features import (
    RUNTIME_FEATURE_ZK,
    module_ir_uses_runtime_feature,
    runtime_feature_enabled,
)
from contracting.stdlib.bridge import random as random_bridge
from contracting.stdlib.bridge import zk as zk_bridge
from contracting.storage.content_cache import ContentKeyedCache
from contracting.storage.keys import (
    DEPLOYER_KEY,
    DEVELOPER_KEY,
    INITIATOR_KEY,
    OWNER_KEY,
    SOURCE_KEY,
    TIME_KEY,
    XIAN_VM_V1_IR_KEY,
)
from contracting.storage.ordered import iter_overlay_items

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
    _TransactionBudget,
    decode_and_validate_transaction,
    execute_bundle,
    runtime_info_json,
    state_root_leaf_hash,
    supports_execution_policy,
    tx_rewards,
    validate_module_ir_json,
    validate_storage_key,
)

_RANDOM_SYSCALLS = {
    "seed": random_bridge.seed,
    "random": random_bridge.random,
    "shuffle": random_bridge.shuffle,
    "getrandbits": random_bridge.getrandbits,
    "randrange": random_bridge.randrange,
    "randint": random_bridge.randint,
    "choice": random_bridge.choice,
    "choices": random_bridge.choices,
}


@dataclass(slots=True)
class NativeExecutionResult:
    status_code: int
    result: Any
    writes: dict[str, Any]
    events: list[dict[str, Any]]
    snapshots: list[dict[str, Any]]
    raw_cost: int
    chi_used: int
    contract_costs: dict[str, int]


@dataclass(frozen=True, slots=True)
class _ModuleSummary:
    """What the host checks about a module, read once from its IR."""

    vm_profile: Any
    uses_zk: bool
    exports: frozenset
    construct_name: str | None

    @classmethod
    def of(cls, module_ir: dict[str, Any]) -> "_ModuleSummary":
        return cls(
            vm_profile=module_ir.get("vm_profile"),
            uses_zk=module_ir_uses_runtime_feature(module_ir, RUNTIME_FEATURE_ZK),
            exports=frozenset(
                function.get("name")
                for function in module_ir.get("functions", [])
                if function.get("visibility") == "export"
            ),
            construct_name=_construct_function_name(module_ir),
        )


# Summaries by contract name, reused while the contract's IR text is identical.
_MODULE_SUMMARIES = ContentKeyedCache()


def runtime_info(vm_profile: str = "xian_vm_v2") -> dict:
    return json.loads(runtime_info_json(vm_profile))


def validate_module_ir(module_ir: dict | str) -> None:
    payload = (
        module_ir
        if isinstance(module_ir, str)
        else json.dumps(module_ir, separators=(",", ":"), sort_keys=True)
    )
    validate_module_ir_json(payload)


class NativeVmHost:
    def __init__(
        self,
        driver,
        *,
        vm_profile: str = "xian_vm_v2",
        entry_contract: str | None = None,
        meter_enabled: bool = False,
        chi_budget_raw: int = 0,
        context: dict[str, Any] | None = None,
    ) -> None:
        if getattr(driver, "vm_profile", vm_profile) != vm_profile:
            raise ValueError("execution profile differs from the storage driver profile")
        self.driver = driver
        self.vm_profile = vm_profile
        self._ir_cache: dict[str, str] = {}
        self._module_summaries: dict[str, _ModuleSummary] = {}
        self._entry_contract = entry_contract
        self._meter_enabled = meter_enabled
        self._budget = _TransactionBudget(max(int(chi_budget_raw), 0), vm_profile)
        self._context = dict(context or {})
        self._pending_writes: dict[str, Any] = {}
        self._pending_events: list[dict[str, Any]] = []
        self._extra_raw_cost = 0
        self._extra_contract_costs: dict[str, int] = {}
        self._written_bytes = 0

    @property
    def pending_writes(self) -> dict[str, Any]:
        return dict(self._pending_writes)

    @property
    def pending_events(self) -> list[dict[str, Any]]:
        return list(self._pending_events)

    @property
    def extra_raw_cost(self) -> int:
        return int(self._extra_raw_cost)

    @property
    def extra_contract_costs(self) -> dict[str, int]:
        return dict(self._extra_contract_costs)

    def _make_key(self, contract: str, variable: str, args=None) -> str:
        return self.driver.make_key(contract, variable, args)

    def _lookup_key(self, key: str):
        if key in self._pending_writes:
            return self._pending_writes[key]
        return self.driver.get(key)

    def _contract_var(self, contract: str, variable: str):
        return self._lookup_key(self._make_key(contract, variable))

    def _stage_write(self, key: str, value: Any) -> None:
        self._pending_writes[key] = value

    def _record_raw_cost(self, raw_cost: int, *, contract: str | None = None):
        raw_cost = int(raw_cost)
        if raw_cost <= 0:
            return
        self._extra_raw_cost += raw_cost
        target_contract = contract or self._entry_contract
        if target_contract:
            self._extra_contract_costs[target_contract] = (
                self._extra_contract_costs.get(target_contract, 0) + raw_cost
            )
        if self._meter_enabled:
            self._budget.charge(raw_cost)

    def _add_raw_cost(self, raw_cost: int) -> None:
        raw_cost = int(raw_cost)
        if raw_cost > 0:
            self._extra_raw_cost += raw_cost

    def _write_raw_cost(self, key: str, value: Any) -> int:
        encoded_key, encoded_value = encode_kv(key, value, vm_profile=self.vm_profile)
        return (len(encoded_key) + len(encoded_value)) * constants.WRITE_COST_PER_BYTE

    def _charge_host_write(
        self,
        key: str,
        value: Any,
        *,
        enforce_write_cap: bool = True,
    ) -> None:
        if not self._meter_enabled:
            return
        encoded_key, encoded_value = encode_kv(key, value, vm_profile=self.vm_profile)
        written = len(encoded_key) + len(encoded_value)
        if enforce_write_cap:
            self._written_bytes += written
            if self._written_bytes >= WRITE_MAX:
                raise VmRuntimeExecutionError(
                    "AssertionError('You have exceeded the maximum write capacity "
                    "per transaction!')"
                )
        self._record_raw_cost(written * constants.WRITE_COST_PER_BYTE)

    def committed_storage(self):
        """State the VM reads in Rust: the LMDB environment, the driver's block
        overlay, and the writes staged here, which the VM must still ask for."""
        committed = getattr(self.driver, "committed_storage", None)
        storage = committed() if committed is not None else None
        if storage is None or self.vm_profile != "xian_vm_v2":
            return None
        environment, overlay = storage
        return environment, overlay, self._pending_writes

    def read_variable(self, contract: str, binding: str):
        return self._lookup_key(self._make_key(contract, binding))

    def read_hash(self, contract: str, binding: str, key):
        return self._lookup_key(self._make_key(contract, binding, _hash_key_args(key)))

    def iter_hash_entries(self, contract: str, binding: str, prefix: str):
        # The VM passes the selected key suffix with its trailing delimiter;
        # an empty prefix selects the whole hash.
        base_key = self._make_key(contract, binding)
        full_prefix = f"{base_key}{constants.DELIMITER}{prefix}"
        suffix_offset = len(base_key) + len(constants.DELIMITER)
        for key, value in iter_overlay_items(
            self._pending_writes, self.driver.iter_items(full_prefix), full_prefix
        ):
            yield key[suffix_offset:], value

    def scan_hash_entries(self, contract: str, binding: str, prefix: str) -> list[tuple[str, Any]]:
        return list(self.iter_hash_entries(contract, binding, prefix))

    def get_owner(self, contract: str):
        return self._contract_var(contract, OWNER_KEY)

    def caller_is_owner(self, contract: str, caller: str | None) -> bool:
        owner = self.get_owner(contract)
        return owner is None or owner == caller

    def load_module_ir_json(self, module_name: str):
        cached = self._ir_cache.get(module_name)
        if cached is not None:
            return cached
        pending_ir = self._contract_var(module_name, XIAN_VM_V1_IR_KEY)
        if isinstance(pending_ir, str) and pending_ir:
            self._ir_cache[module_name] = pending_ir
            return pending_ir
        get_contract_ir = getattr(self.driver, "get_contract_ir", None)
        payload = None
        if get_contract_ir is not None:
            payload = get_contract_ir(
                module_name,
                vm_profile=self.vm_profile,
            )
            if not isinstance(payload, str) or not payload:
                payload = None
        if payload is None:
            return None
        self._ir_cache[module_name] = payload
        return payload

    def module_summary(self, module_name: str) -> _ModuleSummary | None:
        cached = self._module_summaries.get(module_name)
        if cached is not None:
            self._reject_disabled_runtime_features(module_name, cached)
            return cached
        module_ir_json = self.load_module_ir_json(module_name)
        if not module_ir_json:
            return None
        summary = _MODULE_SUMMARIES.get(module_name, module_ir_json)
        if summary is None:
            summary = _ModuleSummary.of(json.loads(module_ir_json))
            _MODULE_SUMMARIES.put(module_name, module_ir_json, summary)
        if summary.vm_profile != self.vm_profile:
            raise VmRuntimeExecutionError(
                f"contract {module_name!r} does not target {self.vm_profile}"
            )
        self._reject_disabled_runtime_features(module_name, summary)
        self._module_summaries[module_name] = summary
        return summary

    def _reject_disabled_runtime_features(self, module_name: str, summary: _ModuleSummary) -> None:
        if summary.uses_zk and not runtime_feature_enabled(
            self.driver,
            RUNTIME_FEATURE_ZK,
            default_enabled=True,
        ):
            raise VmRuntimeExecutionError(
                f"contract '{module_name}' uses zk host syscalls, "
                "but the chain zk runtime feature is disabled"
            )

    def _contract_exists(self, contract: str) -> bool:
        for artifact_key in (XIAN_VM_V1_IR_KEY, SOURCE_KEY):
            pending_artifact = self._contract_var(contract, artifact_key)
            if pending_artifact is not None:
                return True
        has_contract = getattr(self.driver, "has_contract", None)
        if callable(has_contract):
            return bool(has_contract(contract))
        return False

    def _contract_has_export(self, contract: str, export_name: str) -> bool:
        summary = self.module_summary(contract)
        return summary is not None and export_name in summary.exports

    def _stage_contract_metadata_write(self, contract: str, variable: str, value: Any) -> None:
        key = self._make_key(contract, variable)
        self._stage_write(key, value)
        self._charge_host_write(key, value, enforce_write_cap=False)

    def _deployment_artifacts(self, name: str, code: str | None):
        assert_safe_contract_name(name)
        if self._contract_exists(name):
            raise VmRuntimeExecutionError("Contract already exists.")
        if not isinstance(code, str) or code == "":
            raise VmRuntimeExecutionError(
                "native contract deployment requires non-empty source code"
            )

        artifacts = compile_contract_source(
            module_name=name,
            source=code,
            lint=True,
            vm_profile=self.vm_profile,
        )
        source = artifacts["source"]
        vm_ir_json = artifacts["vm_ir_json"]

        module_ir = json.loads(vm_ir_json)
        validate_module_ir(module_ir)
        summary = _ModuleSummary.of(module_ir)
        self._reject_disabled_runtime_features(name, summary)

        return source, vm_ir_json, summary

    def _execute_constructor(self, name, vm_ir_json, construct_name, context, constructor_args):
        raw = execute_bundle(
            {name: vm_ir_json},
            name,
            construct_name,
            [],
            coerce_call_kwargs(dict(constructor_args or {}), self.vm_profile),
            context,
            self,
            meter=self._meter_enabled,
            transaction_size_bytes=0,
            budget=self._budget,
            vm_profile=self.vm_profile,
        )
        # Native execution already debited the shared budget. Keep its measured
        # work and attribution even when construction fails and state rolls back.
        self._extra_contract_costs = _merge_contract_costs(
            self._extra_contract_costs,
            dict(raw.get("contract_costs") or {}),
        )
        self._add_raw_cost(int(raw.get("raw_cost", 0)))
        if int(raw["status_code"]) != 0:
            error = VmRuntimeExecutionError(f"contract constructor failed: {raw['result']}")
            if self.vm_profile == "xian_vm_v2" and raw.get("exception") is not None:
                # The deploying execution reports the constructor's exception.
                error.__xian_exception__ = tuple(raw["exception"])
            raise error
        return {
            **_snapshots_to_writes(self.driver, raw["snapshots"]),
            **dict(raw.get("storage_writes") or {}),
        }, list(raw["events"])

    def _run_constructor(self, name, summary, vm_ir_json, context, constructor_args):
        caches = [
            (self._ir_cache, self._ir_cache.get(name)),
            (self._module_summaries, self._module_summaries.get(name)),
        ]
        self._ir_cache[name] = vm_ir_json
        self._module_summaries[name] = summary
        try:
            construct_name = summary.construct_name
            if construct_name is not None:
                return self._execute_constructor(
                    name, vm_ir_json, construct_name, context, constructor_args
                )
            return {}, []
        except Exception:
            for cache, previous in caches:
                if previous is None:
                    cache.pop(name, None)
                else:
                    cache[name] = previous
            raise

    def _stage_contract_deploy(
        self,
        *,
        name: str,
        code: str | None,
        owner: str | None,
        constructor_args: dict | None,
        developer: str | None,
        deployer: str | None,
        initiator: str | None,
    ) -> None:
        source, vm_ir_json, summary = self._deployment_artifacts(name, code)
        deployment_developer = self._context.get("caller") if developer is None else developer
        deployment_deployer = self._context.get("caller") if deployer is None else deployer
        deployment_initiator = self._context.get("signer") if initiator is None else initiator
        submitted_at = self._context.get("now")
        if submitted_at is None:
            raise VmRuntimeExecutionError(
                "native contract deployment requires deterministic now context"
            )
        constructor_context = {
            "signer": deployment_initiator,
            "caller": deployment_deployer,
            "this": name,
            "entry": self._context.get("entry"),
            "owner": owner,
            "submission_name": name,
            "now": submitted_at,
            "block_num": self._context.get("block_num"),
            "block_hash": self._context.get("block_hash"),
            "chain_id": self._context.get("chain_id"),
        }
        constructor_writes, constructor_events = self._run_constructor(
            name,
            summary,
            vm_ir_json,
            constructor_context,
            constructor_args,
        )

        metadata_writes = {
            self._make_key(name, SOURCE_KEY): source,
            self._make_key(name, XIAN_VM_V1_IR_KEY): vm_ir_json,
            self._make_key(name, OWNER_KEY): owner,
            self._make_key(name, TIME_KEY): submitted_at,
            self._make_key(name, DEVELOPER_KEY): deployment_developer,
            self._make_key(name, DEPLOYER_KEY): deployment_deployer,
            self._make_key(name, INITIATOR_KEY): deployment_initiator,
        }
        for key, value in constructor_writes.items():
            self._stage_write(key, value)
        for key, value in metadata_writes.items():
            self._stage_write(key, value)
            if value is not None:
                self._charge_host_write(
                    key,
                    value,
                    enforce_write_cap=False,
                )

        self._pending_events.extend(constructor_events)
        self._record_raw_cost(
            constants.DEPLOYMENT_BASE_COST
            + (len(source.encode("utf-8")) * constants.DEPLOYMENT_COST_PER_SOURCE_BYTE)
        )

    def _code_hash(self, contract_name, args, kwargs):
        kind = kwargs.get("kind")
        if kind is None and len(args) > 1:
            kind = args[1]
        if self.vm_profile == "xian_vm_v2":
            kind = "runtime" if kind is None else kind
            if kind not in ("runtime", "ir", "source"):
                raise VmRuntimeExecutionError("Hash kind must be 'ir' or 'source'!")
        else:
            kind = kind or "runtime"
        key = XIAN_VM_V1_IR_KEY if kind in {"runtime", "ir"} else SOURCE_KEY
        contract_text = self._contract_var(contract_name, key)
        if contract_text is None:
            return None
        code = contract_text.encode("utf-8")
        if self.vm_profile == "xian_vm_v2":
            self._record_raw_cost(len(code) * constants.CODE_HASH_COST_PER_BYTE)
        return hashlib.sha3_256(code).hexdigest()

    def handle_syscall(self, syscall_id: str, args, kwargs):
        kwargs = dict(kwargs or {})
        if syscall_id == "contract.exists":
            return self._contract_exists(args[0])
        if syscall_id == "contract.has_export":
            return self._contract_has_export(args[0], args[1])
        if syscall_id == "contract.owner_of":
            return self._contract_var(args[0], OWNER_KEY)
        if syscall_id == "contract.info":
            return {
                "name": args[0],
                "owner": self._contract_var(args[0], OWNER_KEY),
                "developer": self._contract_var(args[0], DEVELOPER_KEY),
                "deployer": self._contract_var(args[0], DEPLOYER_KEY),
                "initiator": self._contract_var(args[0], INITIATOR_KEY),
                "submitted": self._contract_var(args[0], TIME_KEY),
            }
        if syscall_id == "contract.set_owner":
            self._stage_contract_metadata_write(args[0], OWNER_KEY, args[1])
            return None
        if syscall_id == "contract.set_developer":
            self._stage_contract_metadata_write(args[0], DEVELOPER_KEY, args[1])
            return None
        if syscall_id == "contract.deploy":
            name = kwargs.get("name", args[0] if len(args) > 0 else None)
            code = kwargs.get("code", args[1] if len(args) > 1 else None)
            owner = kwargs.get("owner")
            if owner is None and len(args) > 2:
                owner = args[2]
            constructor_args = kwargs.get("constructor_args")
            if constructor_args is None and len(args) > 3:
                constructor_args = args[3]
            developer = kwargs.get("developer")
            deployer = kwargs.get("deployer")
            initiator = kwargs.get("initiator")
            if kwargs.get("deployment_artifacts") is not None:
                raise VmRuntimeExecutionError("native contract deployment accepts source code only")
            self._stage_contract_deploy(
                name=name,
                code=code,
                owner=owner,
                constructor_args=constructor_args,
                developer=developer,
                deployer=deployer,
                initiator=initiator,
            )
            return None
        if syscall_id == "contract.code_hash":
            return self._code_hash(args[0], args, kwargs)
        if syscall_id.startswith("random."):
            function_name = syscall_id.split(".", 1)[1]
            handler = _RANDOM_SYSCALLS.get(function_name)
            if handler is None:
                raise VmRuntimeExecutionError(f"unsupported host syscall '{syscall_id}'")
            if function_name == "shuffle":
                handler(*args, **kwargs)
                return args[0]
            return handler(*args, **kwargs)
        if syscall_id.startswith("zk."):
            function_name = syscall_id.split(".", 1)[1]
            handler = getattr(zk_bridge, function_name)
            return handler(*args, **kwargs)
        raise VmRuntimeExecutionError(f"unsupported host syscall '{syscall_id}'")


def _rejected_entry(error: Exception) -> NativeExecutionResult:
    return NativeExecutionResult(
        status_code=1,
        result=error,
        writes={},
        events=[],
        snapshots=[],
        raw_cost=0,
        chi_used=constants.TRANSACTION_BASE_CHI,
        contract_costs={},
    )


def _external_entry_error(host, summary, contract_name, function_name, context):
    if not host.caller_is_owner(contract_name, context.get("caller")):
        return Exception("Caller is not the owner!")
    if host.vm_profile != "xian_vm_v2":
        return None
    if function_name in summary.exports:
        return None
    return RuntimeError(
        f"Function '{function_name}' is not exported by contract '{contract_name}'."
    )


def execute_contract(
    *,
    driver,
    contract_name: str,
    function_name: str,
    args: list | None = None,
    kwargs: dict | None = None,
    context: dict | None = None,
    meter: bool = False,
    chi_budget_raw: int = 0,
    transaction_size_bytes: int = 0,
    vm_profile: str = "xian_vm_v2",
) -> NativeExecutionResult:
    context = dict(context or {})
    host = NativeVmHost(
        driver,
        vm_profile=vm_profile,
        entry_contract=contract_name,
        meter_enabled=meter,
        chi_budget_raw=chi_budget_raw,
        context=context,
    )
    coerced_args = _coerce_external_call_args(args or [], vm_profile)
    coerced_kwargs = coerce_call_kwargs(kwargs or {}, vm_profile)
    summary = host.module_summary(contract_name)
    if summary is None:
        raise VmRuntimeExecutionError(
            f"{vm_profile} requires persisted __xian_ir_v1__ for contract "
            f"'{contract_name}'; stored source is inspection-only"
        )
    # A contract with an owner may only be called by that owner, whether the
    # call comes from another contract or straight from a transaction.
    error = _external_entry_error(host, summary, contract_name, function_name, context)
    if error is not None:
        return _rejected_entry(error)
    bundle = {contract_name: host.load_module_ir_json(contract_name)}
    previous_env = dict(rt.env)
    # Host syscalls must use only this execution's explicit inputs. Ambient
    # state is restored afterward, never inherited into consensus execution.
    rt.env = {**context, "__Driver": driver}
    random_bridge.clear_random_state()
    try:
        raw = execute_bundle(
            bundle,
            contract_name,
            function_name,
            coerced_args,
            coerced_kwargs,
            context,
            host,
            meter=meter,
            chi_budget_raw=max(int(chi_budget_raw), 0),
            transaction_size_bytes=max(int(transaction_size_bytes), 0),
            budget=host._budget,
            vm_profile=vm_profile,
        )
    finally:
        random_bridge.clear_random_state()
        rt.env = previous_env
    result = native_error_result(
        int(raw["status_code"]),
        raw["result"],
        vm_profile=vm_profile,
        exception=raw.get("exception"),
    )
    status_code = int(raw["status_code"])
    writes = {
        **_snapshots_to_writes(driver, raw["snapshots"]),
        **dict(raw.get("storage_writes") or {}),
    }
    events = list(raw["events"])
    if status_code == 0:
        writes = {**writes, **host.pending_writes}
        events = host.pending_events + events
    return NativeExecutionResult(
        status_code=status_code,
        result=result,
        writes=dict(sorted(writes.items())),
        events=events,
        snapshots=list(raw["snapshots"]),
        raw_cost=int(raw.get("raw_cost", 0)) + host.extra_raw_cost,
        chi_used=_combined_chi_used(
            raw_chi_used=int(raw.get("chi_used", 0)),
            raw_cost=int(raw.get("raw_cost", 0)),
            extra_raw_cost=host.extra_raw_cost,
            chi_budget_raw=host._budget.limit,
        ),
        contract_costs=_merge_contract_costs(
            dict(raw.get("contract_costs") or {}),
            host.extra_contract_costs,
        ),
    )


def _coerce_external_call_args(args: list[Any], vm_profile) -> list[Any]:
    if vm_profile == "xian_vm_v2":
        return decode_wire_numbers(normalize_wire_numbers(args))
    return [ContractingDecimal(str(value)) if isinstance(value, float) else value for value in args]


def coerce_call_kwargs(kwargs: dict[str, Any], vm_profile="xian_vm_v2") -> dict[str, Any]:
    """Keyword arguments of an external call, as the VM receives them."""
    if vm_profile == "xian_vm_v2":
        return decode_wire_numbers(normalize_wire_numbers(kwargs))
    return {
        key: ContractingDecimal(str(value)) if isinstance(value, float) else value
        for key, value in kwargs.items()
    }


def _merge_contract_costs(left: dict[str, int], right: dict[str, int]) -> dict[str, int]:
    merged = dict(left)
    for contract, raw_cost in right.items():
        merged[contract] = int(merged.get(contract, 0)) + int(raw_cost)
    return dict(sorted(merged.items()))


def native_error_result(
    status_code: int, result: Any, *, vm_profile: str = "xian_vm_v2", exception=None
) -> Any:
    """The receipt result of a native execution: the structured exception of
    a failure when there is one, else the value or failure text."""
    if int(status_code) == 0 or not isinstance(result, str):
        return result
    if vm_profile == "xian_vm_v2":
        # V2 never interprets failure text: only the VM's structured exception
        # selects a type. Anything else remains an opaque message.
        return _structured_native_exception(exception) or result
    return _native_exception_from_repr(result) or result


_NATIVE_EXCEPTION_TYPES: dict[str, type[BaseException]] = {
    "AssertionError": AssertionError,
    "TypeError": TypeError,
    "ValueError": ValueError,
    "RuntimeError": RuntimeError,
    "Exception": Exception,
    "KeyError": KeyError,
    "IndexError": IndexError,
}
_METADATA_AUTHORITY_ERROR = "Contract metadata changes are restricted to submission."


def _structured_native_exception(exception) -> BaseException | None:
    if exception is None:
        return None
    name, args = exception
    exception_type = _NATIVE_EXCEPTION_TYPES.get(name)
    return None if exception_type is None else exception_type(*args)


def _literal_native_exception(exception_type, inner):
    if inner == "":
        return exception_type()
    try:
        args = ast.literal_eval(f"({inner},)")
    except (SyntaxError, ValueError):
        return exception_type(inner)
    if not isinstance(args, tuple):
        args = (args,)
    return exception_type(*args)


def _native_exception_at(result, start):
    if len(result) - start == len(_METADATA_AUTHORITY_ERROR) and result.startswith(
        _METADATA_AUTHORITY_ERROR, start
    ):
        return AssertionError(_METADATA_AUTHORITY_ERROR)
    for name, exception_type in _NATIVE_EXCEPTION_TYPES.items():
        if result.startswith(f"{name}: ", start):
            return exception_type(result[start + len(name) + 2 :])
        if result.startswith(f"{name}(", start) and result.endswith(")"):
            return _literal_native_exception(exception_type, result[start + len(name) + 1 : -1])
    return None


def _native_exception_offsets(result):
    position = len(result)
    while True:
        position = result.rfind(": ", 0, position)
        if position < 0:
            break
        yield position + 2
    yield 0


def _native_exception_from_repr(result: str) -> BaseException | None:
    """Archival V1 classification: the rightmost recognized exception prefix.

    Offsets are scanned without recursion or successively shorter copies of
    the message.
    """
    for start in _native_exception_offsets(result):
        error = _native_exception_at(result, start)
        if error is not None:
            return error
    return None


def _combined_chi_used(
    *,
    raw_chi_used: int,
    raw_cost: int,
    extra_raw_cost: int,
    chi_budget_raw: int,
) -> int:
    combined = ((int(raw_cost) + int(extra_raw_cost)) // 1000) + constants.TRANSACTION_BASE_CHI
    if chi_budget_raw > 0:
        combined = min(combined, chi_budget_raw // 1000)
    return max(combined, int(raw_chi_used))


def _snapshots_to_writes(driver, snapshots: list[dict[str, Any]]) -> dict[str, Any]:
    writes: dict[str, Any] = {}
    for snapshot in snapshots:
        contract_name = snapshot["contract_name"]
        for variable in snapshot["variables"]:
            writes[driver.make_key(contract_name, variable["binding"])] = variable["value"]
        for hash_snapshot in snapshot["hashes"]:
            binding = hash_snapshot["binding"]
            for storage_key, value in hash_snapshot["entries"].items():
                writes[driver.make_key(contract_name, binding, [storage_key])] = value
    return writes


def _hash_key_args(key) -> list[Any]:
    if isinstance(key, tuple):
        return list(key)
    return [key]


def _construct_function_name(module_ir: dict[str, Any]) -> str | None:
    for function in module_ir.get("functions", []):
        if function.get("visibility") == "construct":
            return function.get("name")
    return None


__all__ = [
    "MAX_STORAGE_KEY_BYTES",
    "BlockExecutor",
    "BlockState",
    "LmdbEnvironment",
    "LmdbItems",
    "LmdbMapFullError",
    "LmdbStorageError",
    "NativeExecutionResult",
    "NativeVmHost",
    "StateRootTree",
    "VmIrValidationError",
    "VmRuntimeExecutionError",
    "coerce_call_kwargs",
    "decode_and_validate_transaction",
    "execute_bundle",
    "execute_contract",
    "native_error_result",
    "runtime_info",
    "runtime_info_json",
    "state_root_leaf_hash",
    "supports_execution_policy",
    "tx_rewards",
    "validate_module_ir",
    "validate_module_ir_json",
    "validate_storage_key",
]
