from __future__ import annotations

import decimal
from copy import deepcopy
from datetime import datetime
from pathlib import Path

from cachetools import TTLCache
from xian_runtime_types.collections import ContractingSet
from xian_runtime_types.decimal import ContractingDecimal
from xian_runtime_types.encoding import encode_kv
from xian_runtime_types.time import Datetime

from contracting import constants
from contracting.compilation.compiler import ContractingCompiler
from contracting.execution.runtime import rt
from contracting.names import assert_safe_contract_name
from contracting.storage.lmdb_store import LMDBStore

INDEX_SEPARATOR = constants.INDEX_SEPARATOR
HASH_DELIMITER = constants.DELIMITER
_MISSING = object()

SOURCE_KEY = "__source__"
CODE_KEY = "__code__"
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


class Driver:
    def __init__(
        self,
        bypass_cache: bool = False,
        storage_home: Path = constants.STORAGE_HOME,
    ) -> None:
        self.pending_deltas = {}
        self.pending_writes = {}
        self.pending_reads = {}
        self.transaction_reads = {}
        self.transaction_read_prefixes = set()
        self.transaction_writes = {}
        self.log_events = []
        self.track_transaction_reads = True
        self.cache = TTLCache(maxsize=1000, ttl=6 * 3600)
        self.bypass_cache = bypass_cache
        self.storage_home = Path(storage_home)
        self.storage_path = self.storage_home / "lmdb"
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self._store = LMDBStore(self.storage_path)

    def get(self, key: str, save: bool = True):
        value = self.find(key)
        if save:
            if self.pending_reads.get(key) is None:
                self.pending_reads[key] = value
            if (
                self.track_transaction_reads
                and self.transaction_reads.get(key) is None
            ):
                self.transaction_reads[key] = value
        return value

    def set(
        self,
        key,
        value,
        is_txn_write: bool = False,
        *,
        enforce_write_cap: bool = True,
    ):
        rt.deduct_write(
            *encode_kv(key, value),
            enforce_write_cap=enforce_write_cap,
        )
        if self.pending_reads.get(key) is None:
            self.get(key)
        if isinstance(value, (decimal.Decimal, float)):
            value = ContractingDecimal(str(value))
        self.pending_writes[key] = value
        if is_txn_write:
            self.transaction_writes[key] = value

    def apply_writes(self, writes: dict[str, object]) -> None:
        for key, value in writes.items():
            if isinstance(value, (decimal.Decimal, float)):
                value = ContractingDecimal(str(value))
            self.pending_writes[key] = value

    def find(self, key: str):
        value = self.pending_writes.get(key, _MISSING)
        if value is not _MISSING:
            return value

        if not self.bypass_cache:
            value = self.cache.get(key, _MISSING)
            if value is not _MISSING:
                return value

        return self._store.get(key)

    def keys_from_disk(self, prefix: str | None = None, length: int = 0):
        if self.track_transaction_reads:
            self.transaction_read_prefixes.add(prefix or "")
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
        if self.track_transaction_reads:
            self.transaction_read_prefixes.add(prefix)
        return self._store.scan_keys(
            prefix,
            limit=limit,
            after_key=after_key,
        )

    def iter_from_disk(self, prefix: str = "", length: int = 0):
        if self.track_transaction_reads:
            self.transaction_read_prefixes.add(prefix)
        keys = self._store.keys(prefix)
        if length > 0:
            return keys[:length]
        return keys

    def value_from_disk(self, key):
        return self._store.get(key)

    def items(self, prefix: str = ""):
        if self.track_transaction_reads:
            self.transaction_read_prefixes.add(prefix)
        items = {}
        seen = set()

        for key, value in self.pending_writes.items():
            if key.startswith(prefix):
                seen.add(key)
                if value is not None:
                    items[key] = _copy_mutable_value(value)

        for key, value in self.cache.items():
            if key.startswith(prefix):
                seen.add(key)
                if value is not None:
                    items[key] = _copy_mutable_value(value)

        for key, value in self._store.items(prefix).items():
            if key not in seen:
                items[key] = _copy_mutable_value(value)

        return items

    def keys(self, prefix: str = ""):
        return list(self.items(prefix).keys())

    def values(self, prefix: str = ""):
        return list(self.items(prefix).values())

    def make_key(self, contract, variable, args=None):
        contract_variable = INDEX_SEPARATOR.join((contract, variable))
        if args:
            return HASH_DELIMITER.join(
                (contract_variable, *[str(arg) for arg in args])
            )
        return contract_variable

    def set_var(
        self,
        contract,
        variable,
        arguments=None,
        value=None,
        mark=True,
        *,
        enforce_write_cap: bool = True,
    ):
        key = self.make_key(contract, variable, arguments)
        self.set(key, value, enforce_write_cap=enforce_write_cap)

    def get_var(self, contract, variable, arguments=None, mark=True):
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

    def get_contract_ir(self, name, *, vm_profile: str = "xian_vm_v1"):
        if vm_profile != "xian_vm_v1":
            raise ValueError(f"unsupported vm_profile {vm_profile!r}")
        return self.get_var(name, XIAN_VM_V1_IR_KEY)

    def get_contract_developer(self, name):
        return self.get_var(name, DEVELOPER_KEY)

    def get_contract_deployer(self, name):
        return self.get_var(name, DEPLOYER_KEY)

    def get_contract_initiator(self, name):
        return self.get_var(name, INITIATOR_KEY)

    def get_contract(self, name):
        return self.get_var(name, CODE_KEY)

    def has_contract(self, name):
        artifact_keys = (XIAN_VM_V1_IR_KEY, SOURCE_KEY, CODE_KEY)
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
        store_runtime_code=True,
    ):
        compiler = ContractingCompiler(module_name=name)
        normalized_source = compiler.normalize_source(source, lint=lint)
        runtime_code = None
        if store_runtime_code:
            runtime_code = compiler.parse_to_code(source, lint=lint)
        vm_ir_json = compiler.lower_to_ir_json(
            normalized_source,
            lint=False,
            vm_profile="xian_vm_v1",
            indent=None,
            sort_keys=True,
        )
        self.set_contract(
            name=name,
            code=runtime_code,
            source=normalized_source,
            vm_ir_json=vm_ir_json,
            owner=owner,
            overwrite=overwrite,
            timestamp=timestamp,
            developer=developer,
            deployer=deployer,
            initiator=initiator,
        )

    def set_contract(
        self,
        name,
        code=None,
        source=None,
        vm_ir_json=None,
        owner=None,
        overwrite=False,
        timestamp=None,
        developer=None,
        deployer=None,
        initiator=None,
    ):
        assert_safe_contract_name(name)

        if self.has_contract(name) and not overwrite:
            return

        if timestamp is None:
            timestamp = Datetime._from_datetime(datetime.now())

        if code is None and source is None and vm_ir_json is None:
            raise TypeError(
                "set_contract requires at least one contract artifact."
            )

        if code is not None:
            compile(code, name, "exec")

        if source is not None:
            self.set_var(
                name,
                SOURCE_KEY,
                value=source,
                enforce_write_cap=False,
            )
        if code is not None:
            self.set_var(name, CODE_KEY, value=code, enforce_write_cap=False)
        if vm_ir_json is not None:
            self.set_var(
                name,
                XIAN_VM_V1_IR_KEY,
                value=vm_ir_json,
                enforce_write_cap=False,
            )
        self.set_var(name, OWNER_KEY, value=owner, enforce_write_cap=False)
        self.set_var(name, TIME_KEY, value=timestamp, enforce_write_cap=False)
        self.set_var(
            name,
            DEVELOPER_KEY,
            value=developer,
            enforce_write_cap=False,
        )
        self.set_var(
            name,
            DEPLOYER_KEY,
            value=deployer,
            enforce_write_cap=False,
        )
        self.set_var(
            name,
            INITIATOR_KEY,
            value=initiator,
            enforce_write_cap=False,
        )

    def delete_contract(self, name):
        for key in self.keys(name):
            self.cache.pop(key, None)
            self.pending_writes.pop(key, None)
        self._store.delete_prefix(f"{name}{INDEX_SEPARATOR}")

    def get_contract_files(self):
        contracts = set()
        for key in self._store.keys():
            contract = key.split(INDEX_SEPARATOR, 1)[0]
            if not contract.startswith("__"):
                contracts.add(contract)
        return sorted(contracts)

    def delete_key_from_disk(self, key):
        self._store.delete(key)

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

    def flush_full(self):
        self.flush_disk()
        self.flush_cache()

    def delete(self, key):
        self.set(key, None)

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

    def clear_transaction_writes(self):
        self.transaction_writes.clear()

    def clear_transaction_reads(self):
        self.transaction_reads.clear()
        self.transaction_read_prefixes.clear()

    def set_transaction_read_tracking(self, enabled: bool) -> None:
        self.track_transaction_reads = enabled
        if not enabled:
            self.transaction_reads.clear()
            self.transaction_read_prefixes.clear()

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
            for artifact_key in (XIAN_VM_V1_IR_KEY, SOURCE_KEY, CODE_KEY)
        )
