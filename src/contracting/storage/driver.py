from __future__ import annotations

import decimal
import functools
import json
import operator
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime
from pathlib import Path

from cachetools import TTLCache
from xian_runtime_types.collections import ContractingSet
from xian_runtime_types.decimal import ContractingDecimal, canonical_fixed
from xian_runtime_types.encoding import (
    decode_wire_numbers,
    normalize_wire_numbers,
    validate_persistent_value,
)
from xian_runtime_types.time import Datetime

from contracting import constants
from contracting.compilation.compiler import ContractingCompiler
from contracting.compilation.vm import DEFAULT_VM_PROFILE, SUPPORTED_VM_PROFILES, XIAN_VM_V2_PROFILE
from contracting.names import assert_safe_contract_name
from contracting.storage.lmdb_store import LMDBStore
from contracting.storage.ordered import iter_overlay_items

INDEX_SEPARATOR = constants.INDEX_SEPARATOR
HASH_DELIMITER = constants.DELIMITER
_MISSING = object()
SOURCE_KEY = "__source__"
XIAN_VM_V1_IR_KEY = "__xian_ir_v1__"
TYPE_KEY = "__type__"
AUTHOR_KEY = "__author__"
OWNER_KEY = "__owner__"
TIME_KEY = "__submitted__"
DEVELOPER_KEY = "__developer__"
DEPLOYER_KEY = "__deployer__"
INITIATOR_KEY = "__initiator__"


def _copy_mutable_value(value):
    if isinstance(value, (list, dict, bytearray, ContractingSet)):
        return deepcopy(value)
    return value


class _PendingStateUndo:
    """First-touch undo records for one ``Driver.discarding_changes`` scope.

    Inside a scope the pending containers only gain or change entries, so the
    previous value of each touched entry, the new read prefixes and the event
    count restore them exactly, in their original order. The cost follows what
    the scope touched, not the size of the block's pending state.
    """

    __slots__ = ("_containers", "_previous", "_new_prefixes", "_event_count")

    def __init__(self, driver):
        self._containers = driver._pending_containers()
        self._previous = {}
        self._new_prefixes = []
        self._event_count = len(driver.log_events)

    def remember(self, container: dict, key) -> None:
        previous = self._previous.get(id(container))
        if previous is None:
            previous = self._previous[id(container)] = (container, {})
        if key not in previous[1]:
            previous[1][key] = container.get(key, _MISSING)

    def remember_prefix(self, prefixes: set, prefix: str) -> None:
        if prefix not in prefixes:
            self._new_prefixes.append(prefix)

    def revert(self, driver) -> None:
        if any(map(operator.is_not, driver._pending_containers(), self._containers)):
            raise RuntimeError("pending state containers were replaced inside a discarding scope")
        for container, previous in self._previous.values():
            for key, value in previous.items():
                if value is _MISSING:
                    del container[key]
                else:
                    container[key] = value
        driver.transaction_read_prefixes.difference_update(self._new_prefixes)
        del driver.log_events[self._event_count :]


def _outside_discarding_scope(method):
    """Bulk changes cannot be undone entry by entry, so a scope forbids them."""

    @functools.wraps(method)
    def guarded(self, *args, **kwargs):
        if self._undo is not None:
            raise RuntimeError(f"Driver.{method.__name__} cannot run inside a discarding scope")
        return method(self, *args, **kwargs)

    return guarded


def _require_contract_artifact_inputs(source, vm_ir_json):
    if source is None and vm_ir_json is None:
        raise TypeError("set_contract requires at least one contract artifact.")
    if source is not None and not isinstance(source, str):
        raise TypeError("Contract source must be a string.")


def _require_contract_ir_profile(vm_ir_json, profile):
    if vm_ir_json is None:
        return
    ir = json.loads(vm_ir_json)
    if not isinstance(ir, dict) or ir.get("vm_profile") != profile:
        raise ValueError(f"contract IR must target {profile}")


class Driver:
    def __init__(
        self,
        bypass_cache: bool = False,
        storage_home: Path | None = None,
        *,
        vm_profile: str = DEFAULT_VM_PROFILE,
    ) -> None:
        if vm_profile not in SUPPORTED_VM_PROFILES:
            raise ValueError(f"unsupported vm_profile {vm_profile!r}")
        self.vm_profile = vm_profile
        self.pending_deltas = {}
        self.pending_writes = {}
        self.pending_reads = {}
        self.transaction_reads = {}
        self.transaction_read_prefixes = set()
        self.transaction_writes = {}
        self.log_events = []
        self.track_transaction_reads = True
        self._undo: _PendingStateUndo | None = None
        self.cache = TTLCache(maxsize=1000, ttl=6 * 3600)
        self.bypass_cache = bypass_cache
        self.storage_home = (
            Path(storage_home) if storage_home is not None else constants.STORAGE_HOME
        )
        self.storage_path = self.storage_home / "lmdb"
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self._store = LMDBStore(self.storage_path, vm_profile=vm_profile)

        try:
            self._check_bootstrap_profile()
        except Exception:
            self.close()
            raise

    def _check_bootstrap_profile(self):
        # The submission IR identifies an initialized chain without decoding its
        # application state. Pre-IR submission contracts used the V1 runtime.
        name = "submission"
        if not self.is_file(name):
            # Some local stores have contracts but no submission contract yet.
            key = self._store.first_key_with_suffix((f".{XIAN_VM_V1_IR_KEY}", f".{SOURCE_KEY}"))
            if key is None:
                return
            name, _ = key.rsplit(".", 1)
        ir = self._store.get(f"{name}.{XIAN_VM_V1_IR_KEY}")
        stored_profile = json.loads(ir)["vm_profile"] if ir is not None else "xian_vm_v1"
        if stored_profile != self.vm_profile:
            raise ValueError(
                f"storage at {self.storage_home} uses {stored_profile!r}, "
                f"requested {self.vm_profile!r}. Open it with its original profile "
                "or choose a fresh storage directory."
            )

    def close(self) -> None:
        self._store.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def get(self, key: str, save: bool = True):
        value = self.find(key)
        if save:
            if self.pending_reads.get(key) is None:
                self._put(self.pending_reads, key, value)
            if self.track_transaction_reads and self.transaction_reads.get(key) is None:
                self._put(self.transaction_reads, key, value)
        return value

    def _put(self, container: dict, key, value) -> None:
        if self._undo is not None:
            self._undo.remember(container, key)
        container[key] = value

    def _track_prefix(self, prefix: str) -> None:
        if not self.track_transaction_reads:
            return
        if self._undo is not None:
            self._undo.remember_prefix(self.transaction_read_prefixes, prefix)
        self.transaction_read_prefixes.add(prefix)

    def _pending_containers(self) -> tuple:
        return (
            self.pending_writes,
            self.pending_reads,
            self.transaction_reads,
            self.transaction_writes,
            self.transaction_read_prefixes,
            self.log_events,
        )

    @contextmanager
    def discarding_changes(self):
        """Undo every pending-state change made inside the ``with`` block.

        Leaves the pending containers exactly as ``snapshot_state`` followed
        by ``restore_state`` would, without copying them. Disk is not part of
        the pending state; bulk operations are rejected inside the block.
        """
        if self._undo is not None:
            raise RuntimeError("a discarding scope is already open on this driver")
        undo = self._undo = _PendingStateUndo(self)
        try:
            yield
        finally:
            self._undo = None
            undo.revert(self)

    def set(
        self,
        key,
        value,
        is_txn_write: bool = False,
    ):
        if self.pending_reads.get(key) is None:
            self.get(key)
        value = _copy_mutable_value(self._typed_value(value))
        self._put(self.pending_writes, key, value)
        if is_txn_write:
            self._put(self.transaction_writes, key, value)

    def _typed_value(self, value):
        if self.vm_profile == XIAN_VM_V2_PROFILE:
            validate_persistent_value(value, vm_profile=self.vm_profile)
            return decode_wire_numbers(normalize_wire_numbers(value))
        if isinstance(value, (decimal.Decimal, float)):
            return ContractingDecimal(str(value))
        return value

    def apply_writes(self, writes: dict[str, object]) -> None:
        typed = {key: self._typed_value(value) for key, value in writes.items()}
        for key, value in typed.items():
            self._put(self.pending_writes, key, value)

    def find(self, key: str):
        # Pending and cached values are live driver state; storage decodes fresh copies.
        value = self.pending_writes.get(key, _MISSING)
        if value is not _MISSING:
            return _copy_mutable_value(value)

        if not self.bypass_cache:
            value = self.cache.get(key, _MISSING)
            if value is not _MISSING:
                return _copy_mutable_value(value)

        return self._store.get(key)

    def keys_from_disk(self, prefix: str | None = None, length: int = 0):
        self._track_prefix(prefix or "")
        keys = self._store.keys(prefix or "")
        if length > 0:
            return keys[:length]
        return keys

    def scan_keys_from_disk(
        self,
        prefix: str = "",
        *,
        limit: int = 100,
        after_key: str | None = None,
    ) -> tuple[list[str], bool]:
        self._track_prefix(prefix)
        return self._store.scan_keys(
            prefix,
            limit=limit,
            after_key=after_key,
        )

    def iter_from_disk(self, prefix: str = "", length: int = 0):
        self._track_prefix(prefix)
        keys = self._store.keys(prefix)
        if length > 0:
            return keys[:length]
        return keys

    def value_from_disk(self, key):
        return self._store.get(key)

    def iter_items(self, prefix: str = ""):
        """Read a canonical merged view without copying the complete disk range."""
        self._track_prefix(prefix)
        cached = iter_overlay_items(self.cache, self._store.iter_items(prefix), prefix)
        for key, value in iter_overlay_items(self.pending_writes, cached, prefix):
            yield key, _copy_mutable_value(value)

    def items(self, prefix: str = ""):
        return dict(self.iter_items(prefix))

    def keys(self, prefix: str = ""):
        return list(self.items(prefix).keys())

    def values(self, prefix: str = ""):
        return list(self.items(prefix).values())

    def make_key(self, contract, variable, args=None):
        contract_variable = INDEX_SEPARATOR.join((contract, variable))
        if args:

            def key_text(arg):
                if self.vm_profile == XIAN_VM_V2_PROFILE and isinstance(
                    arg, (decimal.Decimal, ContractingDecimal)
                ):
                    return canonical_fixed(arg)
                return str(arg)

            return HASH_DELIMITER.join((contract_variable, *map(key_text, args)))
        return contract_variable

    def set_var(
        self,
        contract,
        variable,
        arguments=None,
        value=None,
        mark=True,
        *,
        is_txn_write: bool = False,
    ):
        key = self.make_key(contract, variable, arguments)
        self.set(key, value, is_txn_write=is_txn_write)

    def get_var(self, contract, variable, arguments=None, mark=True):
        key = self.make_key(contract, variable, arguments)
        return self.get(key, save=mark)

    def get_owner(self, name):
        owner = self.get_var(name, OWNER_KEY)
        if owner == "":
            owner = None
        return owner

    def get_time_submitted(self, name):
        return self.get_var(name, TIME_KEY)

    def get_contract_source(self, name):
        return self.get_var(name, SOURCE_KEY)

    def get_contract_ir(self, name, *, vm_profile: str | None = None):
        if vm_profile is not None and vm_profile != self.vm_profile:
            raise ValueError(f"unsupported vm_profile {vm_profile!r}")
        return self.get_var(name, XIAN_VM_V1_IR_KEY)

    def get_contract_developer(self, name):
        return self.get_var(name, DEVELOPER_KEY)

    def get_contract_deployer(self, name):
        return self.get_var(name, DEPLOYER_KEY)

    def get_contract_initiator(self, name):
        return self.get_var(name, INITIATOR_KEY)

    def has_contract(self, name):
        artifact_keys = (XIAN_VM_V1_IR_KEY, SOURCE_KEY)
        for variable in artifact_keys:
            key = self.make_key(name, variable)
            value = self.find(key)
            if value is not None:
                return True
        return False

    def set_contract_from_source(
        self,
        name,
        source,
        owner=None,
        overwrite=False,
        timestamp=None,
        developer=None,
        deployer=None,
        initiator=None,
        lint=True,
    ):
        if self.vm_profile == XIAN_VM_V2_PROFILE:
            from contracting.artifacts import compile_contract_source

            compiled = compile_contract_source(
                module_name=name, source=source, lint=lint, vm_profile=self.vm_profile
            )
            normalized_source, vm_ir_json = compiled["source"], compiled["vm_ir_json"]
        else:
            compiler = ContractingCompiler(module_name=name)
            normalized_source = compiler.normalize_source(
                source,
                lint=lint,
                vm_profile="xian_vm_v1",
            )
            vm_ir_json = compiler.lower_to_ir_json(
                normalized_source,
                lint=False,
                vm_profile="xian_vm_v1",
                indent=None,
                sort_keys=True,
            )
        self.set_contract(
            name=name,
            source=normalized_source,
            vm_ir_json=vm_ir_json,
            owner=owner,
            overwrite=overwrite,
            timestamp=timestamp,
            developer=developer,
            deployer=deployer,
            initiator=initiator,
        )

    def _prepare_contract_artifacts(self, name, source, vm_ir_json):
        _require_contract_artifact_inputs(source, vm_ir_json)
        if self.vm_profile == XIAN_VM_V2_PROFILE and source is not None and vm_ir_json is None:
            from contracting.artifacts import compile_contract_source

            compiled = compile_contract_source(
                module_name=name, source=source, vm_profile=self.vm_profile
            )
            source, vm_ir_json = compiled["source"], compiled["vm_ir_json"]
        _require_contract_ir_profile(vm_ir_json, self.vm_profile)
        return source, vm_ir_json

    def set_contract(
        self,
        name,
        *,
        source=None,
        vm_ir_json=None,
        owner=None,
        overwrite=False,
        timestamp=None,
        developer=None,
        deployer=None,
        initiator=None,
        is_txn_write: bool = False,
    ):
        assert_safe_contract_name(name)

        if self.has_contract(name) and not overwrite:
            return

        source, vm_ir_json = self._prepare_contract_artifacts(name, source, vm_ir_json)
        if timestamp is None:
            timestamp = Datetime._from_datetime(datetime.now())

        if source is not None:
            self.set_var(
                name,
                SOURCE_KEY,
                value=source,
                is_txn_write=is_txn_write,
            )
        if vm_ir_json is not None:
            self.set_var(
                name,
                XIAN_VM_V1_IR_KEY,
                value=vm_ir_json,
                is_txn_write=is_txn_write,
            )
        self.set_var(name, OWNER_KEY, value=owner, is_txn_write=is_txn_write)
        self.set_var(name, TIME_KEY, value=timestamp, is_txn_write=is_txn_write)
        self.set_var(
            name,
            DEVELOPER_KEY,
            value=developer,
            is_txn_write=is_txn_write,
        )
        self.set_var(
            name,
            DEPLOYER_KEY,
            value=deployer,
            is_txn_write=is_txn_write,
        )
        self.set_var(
            name,
            INITIATOR_KEY,
            value=initiator,
            is_txn_write=is_txn_write,
        )

    @_outside_discarding_scope
    def delete_contract(self, name):
        prefix = f"{name}{INDEX_SEPARATOR}"
        for key in self.keys(prefix):
            self.cache.pop(key, None)
            self.pending_writes.pop(key, None)
        self._store.delete_prefix(prefix)

    def get_contract_files(self):
        contracts = set()
        for key in self._store.keys():
            contract = key.split(INDEX_SEPARATOR, 1)[0]
            if not contract.startswith("__"):
                contracts.add(contract)
        return sorted(contracts)

    def delete_key_from_disk(self, key):
        self._store.delete(key)

    @_outside_discarding_scope
    def flush_cache(self):
        self.pending_writes.clear()
        self.pending_reads.clear()
        self.pending_deltas.clear()
        self.transaction_reads.clear()
        self.transaction_read_prefixes.clear()
        self.transaction_writes.clear()
        self.log_events.clear()
        self.cache.clear()

    def flush_disk(self):
        self._store.flush()

    def flush_file(self, filename):
        self._store.delete_prefix(f"{filename}{INDEX_SEPARATOR}")

    def set_event(self, event):
        self.log_events.append(event)

    @_outside_discarding_scope
    def flush_full(self):
        self.flush_disk()
        self.flush_cache()

    def delete(self, key):
        self.set(key, None)

    @_outside_discarding_scope
    def rollback(self, nanos=None):
        if nanos is None:
            self.cache.clear()
            self.pending_reads.clear()
            self.pending_writes.clear()
            self.pending_deltas.clear()
            self.transaction_reads.clear()
            self.transaction_read_prefixes.clear()
            self.transaction_writes.clear()
            self.log_events.clear()
            return

        to_delete = []
        for delta_nanos, deltas in sorted(
            self.pending_deltas.items(),
            reverse=True,
        ):
            if delta_nanos < nanos:
                break
            to_delete.append(delta_nanos)
            for key, delta in deltas["writes"].items():
                self.cache[key] = delta[0]

        for delta_nanos in to_delete:
            self.pending_deltas.pop(delta_nanos, None)

    def snapshot_state(self) -> dict:
        """Deep-copy the in-flight execution state for later ``restore_state``.

        Includes ``pending_deltas`` so the driver can be returned to the exact
        captured point even if ``hard_apply`` or ``rollback`` ran in between.
        Safe for simulation/replay flows that keep mutating the driver after
        taking the snapshot; the snapshot can be restored more than once.
        """
        return {
            "pending_deltas": deepcopy(self.pending_deltas),
            "pending_writes": deepcopy(self.pending_writes),
            "pending_reads": deepcopy(self.pending_reads),
            "transaction_reads": deepcopy(self.transaction_reads),
            "transaction_read_prefixes": deepcopy(self.transaction_read_prefixes),
            "transaction_writes": deepcopy(self.transaction_writes),
            "log_events": deepcopy(self.log_events),
        }

    @_outside_discarding_scope
    def restore_state(self, snapshot: dict | None) -> None:
        """Restore state captured by ``snapshot_state``; ``None`` is a no-op.

        Deep-copies out of the snapshot so the same snapshot stays valid for
        repeated restores.
        """
        if not snapshot:
            return
        self.pending_deltas = deepcopy(snapshot["pending_deltas"])
        self.pending_writes = deepcopy(snapshot["pending_writes"])
        self.pending_reads = deepcopy(snapshot["pending_reads"])
        self.transaction_reads = deepcopy(snapshot["transaction_reads"])
        self.transaction_read_prefixes = deepcopy(snapshot["transaction_read_prefixes"])
        self.transaction_writes = deepcopy(snapshot["transaction_writes"])
        self.log_events = deepcopy(snapshot["log_events"])

    @_outside_discarding_scope
    def detach_pending_state(self) -> dict:
        """Move the pending per-block state off the driver without copying.

        Returns the live containers and leaves the driver with fresh empty
        ones, so the cost is constant regardless of how much the block wrote.
        ``pending_deltas`` deliberately stays on the driver: it is the journal
        ``hard_apply`` and ``rollback`` consume at commit time and must
        survive the window between detaching and re-attaching.
        """
        detached = {
            "pending_writes": self.pending_writes,
            "pending_reads": self.pending_reads,
            "transaction_reads": self.transaction_reads,
            "transaction_read_prefixes": self.transaction_read_prefixes,
            "transaction_writes": self.transaction_writes,
            "log_events": self.log_events,
        }
        self.pending_writes = {}
        self.pending_reads = {}
        self.transaction_reads = {}
        self.transaction_read_prefixes = set()
        self.transaction_writes = {}
        self.log_events = []
        return detached

    @_outside_discarding_scope
    def attach_pending_state(self, detached: dict) -> None:
        """Re-attach pending state previously moved off by ``detach_pending_state``.

        Anything accumulated on the driver since the detach is discarded in
        favor of the detached containers.
        """
        self.pending_writes = detached["pending_writes"]
        self.pending_reads = detached["pending_reads"]
        self.transaction_reads = detached["transaction_reads"]
        self.transaction_read_prefixes = detached["transaction_read_prefixes"]
        self.transaction_writes = detached["transaction_writes"]
        self.log_events = detached["log_events"]

    @_outside_discarding_scope
    def commit(self):
        if self.pending_writes:
            self._store.batch_set(self.pending_writes)

        self.cache.clear()
        self.pending_writes.clear()
        self.pending_reads.clear()
        self.transaction_reads.clear()
        self.transaction_read_prefixes.clear()
        self.transaction_writes.clear()
        self.log_events.clear()

    @_outside_discarding_scope
    def hard_apply(self, nanos):
        deltas = {}
        for key, value in self.pending_writes.items():
            current = self.pending_reads.get(key)
            deltas[key] = (current, value)
            self.cache[key] = value

        self.pending_deltas[nanos] = {
            "writes": deltas,
            "reads": self.pending_reads,
        }

        self.pending_reads = {}
        self.pending_writes.clear()

        to_delete = []
        for delta_nanos, deltas in sorted(self.pending_deltas.items()):
            writes = {key: delta[1] for key, delta in deltas["writes"].items()}
            if writes:
                self._store.batch_set(writes)
            to_delete.append(delta_nanos)
            if delta_nanos == nanos:
                break

        for delta_nanos in to_delete:
            self.pending_deltas.pop(delta_nanos, None)

    def get_all_contract_state(self):
        contract_state = {}
        for key, value in self._store.items().items():
            contract = key.split(INDEX_SEPARATOR, 1)[0]
            if not contract.startswith("__"):
                contract_state[key] = value
        return contract_state

    def get_run_state(self):
        run_state = {}
        for key, value in self._store.items().items():
            contract = key.split(INDEX_SEPARATOR, 1)[0]
            if contract.startswith("__"):
                run_state[key] = value
        return run_state

    @_outside_discarding_scope
    def clear_transaction_writes(self):
        self.transaction_writes.clear()

    @_outside_discarding_scope
    def clear_transaction_reads(self):
        self.transaction_reads.clear()
        self.transaction_read_prefixes.clear()

    @_outside_discarding_scope
    def set_transaction_read_tracking(self, enabled: bool) -> None:
        self.track_transaction_reads = enabled
        if not enabled:
            self.transaction_reads.clear()
            self.transaction_read_prefixes.clear()

    @_outside_discarding_scope
    def clear_events(self):
        self.log_events.clear()

    @property
    def contract_state(self):
        return self.storage_path

    @property
    def run_state(self):
        return self.storage_path

    def is_file(self, filename):
        return any(
            self._store.exists(f"{filename}{INDEX_SEPARATOR}{artifact_key}")
            for artifact_key in (XIAN_VM_V1_IR_KEY, SOURCE_KEY)
        )
