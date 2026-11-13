from __future__ import annotations

import decimal
import functools
import json
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime
from pathlib import Path

from xian_runtime_types.decimal import ContractingDecimal, canonical_fixed
from xian_runtime_types.encoding import (
    decode_wire_numbers,
    encode,
    normalize_wire_numbers,
    validate_persistent_value,
)
from xian_runtime_types.time import Datetime
from xian_vm_core import BlockState

from contracting import constants
from contracting.compilation.compiler import ContractingCompiler
from contracting.compilation.vm import DEFAULT_VM_PROFILE, SUPPORTED_VM_PROFILES, XIAN_VM_V2_PROFILE
from contracting.names import assert_safe_contract_name
from contracting.storage.keys import (  # noqa: F401 - re-exported storage key names
    AUTHOR_KEY,
    DEPLOYER_KEY,
    DEVELOPER_KEY,
    INITIATOR_KEY,
    OWNER_KEY,
    SOURCE_KEY,
    TIME_KEY,
    TYPE_KEY,
    XIAN_VM_V1_IR_KEY,
)
from contracting.storage.lmdb_environment import validate_storage_key
from contracting.storage.lmdb_store import LMDBStore
from contracting.storage.ordered import iter_overlay_items

INDEX_SEPARATOR = constants.INDEX_SEPARATOR
HASH_DELIMITER = constants.DELIMITER
_MISSING = object()


class _PendingStateUndo:
    """First-touch undo records of the Python-side containers for one
    ``Driver.discarding_changes`` scope; the block overlay undoes itself.

    Inside a scope the containers only gain or change entries, so the previous
    value of each touched entry and the event count restore them exactly, in
    their original order.
    """

    __slots__ = ("_pending", "_writes", "_previous", "_event_count")

    def __init__(self, driver):
        self._pending = driver._pending
        self._writes = driver.transaction_writes
        self._previous = {}
        self._event_count = len(driver.log_events)

    def remember(self, key) -> None:
        if key not in self._previous:
            self._previous[key] = self._writes.get(key, _MISSING)

    def revert(self, driver) -> None:
        if driver._pending is not self._pending or driver.transaction_writes is not self._writes:
            raise RuntimeError("pending state containers were replaced inside a discarding scope")
        for key, value in self._previous.items():
            if value is _MISSING:
                del self._writes[key]
            else:
                self._writes[key] = value
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
        storage_home: Path | None = None,
        *,
        vm_profile: str = DEFAULT_VM_PROFILE,
    ) -> None:
        if vm_profile not in SUPPORTED_VM_PROFILES:
            raise ValueError(f"unsupported vm_profile {vm_profile!r}")
        self.vm_profile = vm_profile
        # The block overlay: pending writes as stored values.
        self._pending = BlockState()
        self.transaction_writes = {}
        self.log_events = []
        self._undo: _PendingStateUndo | None = None
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

    def get(self, key: str):
        return self.find(key)

    def committed_storage(self):
        """The state the VM may read without this driver, or None.

        Returns the LMDB environment and the block overlay; the VM reads both
        in Rust.
        """
        if self.vm_profile != XIAN_VM_V2_PROFILE:
            return None
        return self._store.environment, self._pending

    def pending_items(self) -> list[tuple[str, object]]:
        """The block's pending writes in key order; a deletion reads as None."""
        return [(key, self._decode(key, raw)) for key, raw in self.pending_stored_items()]

    def pending_stored_items(self) -> list[tuple[str, bytes | None]]:
        """The block's pending writes in key order as the bytes Commit stores;
        a deletion is None."""
        return list(self._pending.items())

    def _decode(self, key: str, raw: bytes | None):
        return None if raw is None else self._store.decode(key, raw)

    def _stored(self, value) -> bytes | None:
        """The stored bytes of `value` (validated); None stages a deletion.

        V2 encoding validates and normalizes the value in the same pass, and
        decoding those bytes gives the typed value ``_typed_value`` would.
        """
        if value is None:
            return None
        if self.vm_profile != XIAN_VM_V2_PROFILE:
            value = self._typed_value(value)
        return encode(value, vm_profile=self.vm_profile).encode("utf-8")

    @contextmanager
    def discarding_changes(self):
        """Undo every pending-state change made inside the ``with`` block.

        Leaves the pending state exactly as ``snapshot_state`` followed by
        ``restore_state`` would, without copying it. Disk is not part of the
        pending state; bulk operations are rejected inside the block.
        """
        if self._undo is not None:
            raise RuntimeError("a discarding scope is already open on this driver")
        self._pending.begin_discarding()
        undo = self._undo = _PendingStateUndo(self)
        try:
            yield
        finally:
            self._undo = None
            self._pending.discard()
            undo.revert(self)

    def set(
        self,
        key,
        value,
        is_txn_write: bool = False,
    ):
        validate_storage_key(key)
        self._pending.write(key, self._stored(value))
        if is_txn_write:
            if self._undo is not None:
                self._undo.remember(key)
            self.transaction_writes[key] = self._typed_value(value)

    def _typed_value(self, value):
        if self.vm_profile == XIAN_VM_V2_PROFILE:
            validate_persistent_value(value, vm_profile=self.vm_profile)
            return decode_wire_numbers(normalize_wire_numbers(value))
        if isinstance(value, (decimal.Decimal, float)):
            return ContractingDecimal(str(value))
        return value

    def apply_writes(self, writes: dict[str, object]) -> None:
        # Stage all or nothing: every key and value is checked first.
        for key in writes:
            validate_storage_key(key)
        encoded = [(key, self._stored(value)) for key, value in writes.items()]
        for key, raw in encoded:
            self._pending.write(key, raw)

    def find(self, key: str):
        # Every value is decoded fresh, so callers never share a live value.
        held, raw = self._pending.lookup(key)
        if held:
            return self._decode(key, raw)
        return self._store.get(key)

    def keys_from_disk(self, prefix: str | None = None, length: int = 0):
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
        return self._store.scan_keys(
            prefix,
            limit=limit,
            after_key=after_key,
        )

    def iter_from_disk(self, prefix: str = "", length: int = 0):
        keys = self._store.keys(prefix)
        if length > 0:
            return keys[:length]
        return keys

    def value_from_disk(self, key):
        return self._store.get(key)

    def iter_items(self, prefix: str = ""):
        """Read a canonical merged view without copying the complete disk range."""
        overlay = {key: self._decode(key, raw) for key, raw in self._pending.items(prefix)}
        yield from iter_overlay_items(overlay, self._store.iter_items(prefix), prefix)

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
        *,
        is_txn_write: bool = False,
    ):
        key = self.make_key(contract, variable, arguments)
        self.set(key, value, is_txn_write=is_txn_write)

    def get_var(self, contract, variable, arguments=None):
        key = self.make_key(contract, variable, arguments)
        return self.get(key)

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
        self._pending.forget_prefix(prefix)
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
        """Discard the pending block state (disk is untouched)."""
        self._pending.clear()
        self.transaction_writes.clear()
        self.log_events.clear()

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
    def rollback(self):
        """Discard the pending block state; same as ``flush_cache``."""
        self.flush_cache()

    def snapshot_state(self) -> dict:
        """Capture the pending state as plain data for later ``restore_state``.

        Safe for simulation/replay flows that keep mutating the driver after
        taking the snapshot; the snapshot can be restored more than once and
        sent to another process.
        """
        return {
            "pending_writes": self._pending.items(),
            "transaction_writes": deepcopy(self.transaction_writes),
            "log_events": deepcopy(self.log_events),
        }

    @_outside_discarding_scope
    def restore_state(self, snapshot: dict | None) -> None:
        """Restore state captured by ``snapshot_state``; ``None`` is a no-op."""
        if not snapshot:
            return
        pending = BlockState()
        for key, raw in snapshot["pending_writes"]:
            pending.write(key, raw)
        self._pending = pending
        self.transaction_writes = deepcopy(snapshot["transaction_writes"])
        self.log_events = deepcopy(snapshot["log_events"])

    @_outside_discarding_scope
    def detach_pending_state(self) -> dict:
        """Move the pending per-block state off the driver without copying.

        Returns the live state and leaves the driver with a fresh empty one,
        so the cost is constant regardless of how much the block wrote.
        """
        detached = {
            "pending": self._pending,
            "transaction_writes": self.transaction_writes,
            "log_events": self.log_events,
        }
        self._pending = BlockState()
        self.transaction_writes = {}
        self.log_events = []
        return detached

    @_outside_discarding_scope
    def attach_pending_state(self, detached: dict) -> None:
        """Re-attach pending state previously moved off by ``detach_pending_state``.

        Anything accumulated on the driver since the detach is discarded in
        favor of the detached state.
        """
        self._pending = detached["pending"]
        self.transaction_writes = detached["transaction_writes"]
        self.log_events = detached["log_events"]

    @_outside_discarding_scope
    def commit(self):
        """Write the pending block state to disk in one transaction.

        The pending state is cleared only after the write succeeded; a failed
        commit leaves it in place, so the same block can be committed again.
        """
        if len(self._pending):
            self._store.commit_overlay(self._pending)
        self.flush_cache()

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
