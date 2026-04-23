from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from nacl.signing import SigningKey
from xian_runtime_types.decimal import ContractingDecimal
from xian_runtime_types.time import Datetime, Timedelta

from contracting.client import ContractingClient
from contracting.compilation.compiler import ContractingCompiler
from contracting.stdlib.bridge import zk as zk_bridge

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _workspace_root() -> Path:
    configured = os.environ.get("XIAN_WORKSPACE_ROOT")
    if configured:
        return Path(configured).expanduser().resolve()
    return PROJECT_ROOT.parent


WORKSPACE_ROOT = _workspace_root()
FIXTURE_DIR = PROJECT_ROOT / "packages" / "xian-vm-core" / "tests" / "fixtures"
SHIELDED_NOTE_TOKEN_SOURCE = (
    WORKSPACE_ROOT
    / "xian-contracts"
    / "contracts"
    / "shielded-note-token"
    / "src"
    / "con_shielded_note_token.py"
)
SHIELDED_COMMANDS_SOURCE = (
    WORKSPACE_ROOT
    / "xian-contracts"
    / "contracts"
    / "shielded-commands"
    / "src"
    / "con_shielded_commands.py"
)
ZK_REGISTRY_SOURCE = (
    WORKSPACE_ROOT / "xian-configs" / "contracts" / "zk_registry.s.py"
)
GENESIS_CURRENCY_SOURCE = (
    WORKSPACE_ROOT / "xian-configs" / "contracts" / "currency.s.py"
)
STABLE_TOKEN_SOURCE = (
    WORKSPACE_ROOT / "xian-stable-protocol" / "contracts" / "stable_token.s.py"
)
REFLECTION_TOKEN_SOURCE = (
    WORKSPACE_ROOT
    / "xian-contracts"
    / "contracts"
    / "reflection-token"
    / "src"
    / "con_reflection_token.py"
)
PROFILE_REGISTRY_SOURCE = (
    WORKSPACE_ROOT
    / "xian-contracts"
    / "contracts"
    / "profile-registry"
    / "src"
    / "con_profile_registry.py"
)
TURN_BASED_GAMES_SOURCE = (
    WORKSPACE_ROOT
    / "xian-contracts"
    / "contracts"
    / "turn-based-games"
    / "src"
    / "con_turn_based_games.py"
)
ORACLE_SOURCE = (
    WORKSPACE_ROOT / "xian-stable-protocol" / "contracts" / "oracle.s.py"
)
DAO_SOURCE = WORKSPACE_ROOT / "xian-configs" / "contracts" / "dao.s.py"
CHI_COST_SOURCE = (
    WORKSPACE_ROOT / "xian-configs" / "contracts" / "chi_cost.s.py"
)
REWARDS_SOURCE = WORKSPACE_ROOT / "xian-configs" / "contracts" / "rewards.s.py"
MEMBERS_SOURCE = WORKSPACE_ROOT / "xian-configs" / "contracts" / "members.s.py"
DEX_SOURCE = (
    WORKSPACE_ROOT
    / "xian-contracts"
    / "contracts"
    / "dex"
    / "src"
    / "con_dex.py"
)
PAIRS_SOURCE = (
    WORKSPACE_ROOT
    / "xian-contracts"
    / "contracts"
    / "dex"
    / "src"
    / "con_pairs.py"
)
FIELD_ONE_HEX = "0x" + "00" * 31 + "01"
FIELD_TWO_HEX = "0x" + "00" * 31 + "02"
FIELD_ZERO_HEX = "0x" + "00" * 32
FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617
MIMC_ROUNDS = 91
MAX_ZK_INPUTS = 4


def _json_value(value: Any) -> Any:
    if value is None or isinstance(value, (bool, float, str)):
        return value
    if isinstance(value, int):
        if -(2**63) <= value <= 2**63 - 1:
            return value
        return {"__vm_type__": "int", "value": str(value)}
    if isinstance(value, ContractingDecimal):
        return {"__vm_type__": "decimal", "value": format(value._d, "f")}
    if isinstance(value, Datetime):
        return {
            "__vm_type__": "datetime",
            "parts": [
                value.year,
                value.month,
                value.day,
                value.hour,
                value.minute,
                value.second,
                value.microsecond,
            ],
        }
    if isinstance(value, Timedelta):
        return {"__vm_type__": "timedelta", "seconds": value.seconds}
    if isinstance(value, list | tuple):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


def _module_source(spec: dict[str, Any]) -> str:
    source = spec.get("source")
    if source is not None:
        resolved = source
    else:
        source_path = spec.get("source_path")
        assert source_path is not None, (
            "fixture module/source must define source or source_path"
        )
        path = Path(source_path)
        if not path.is_absolute():
            path = WORKSPACE_ROOT / path
        resolved = path.read_text(encoding="utf-8")
    for old, new in spec.get("source_replacements", []):
        resolved = resolved.replace(old, new)
    return resolved


def _field_hex(value: int) -> str:
    assert 0 <= value < FIELD_MODULUS, "field value out of range"
    return "0x" + format(value, "064x")


def _field_int_from_text(value: str) -> int:
    assert isinstance(value, str) and value != "", (
        "field text must be non-empty"
    )
    return (
        int(hashlib.sha3_256(value.encode("utf-8")).hexdigest(), 16)
        % FIELD_MODULUS
    )


def _field_int(value: str) -> int:
    assert (
        isinstance(value, str) and value.startswith("0x") and len(value) == 66
    ), "field value must be 0x-prefixed 32-byte hex"
    parsed = int(value[2:], 16)
    assert parsed < FIELD_MODULUS, "field value must be canonical"
    return parsed


def _mimc_round_constant(round_index: int) -> int:
    return _field_int_from_text(f"xian-mimc-bn254-{round_index}")


def _mimc_permute(state: int) -> int:
    state %= FIELD_MODULUS
    for round_index in range(MIMC_ROUNDS):
        state = pow(
            (state + _mimc_round_constant(round_index)) % FIELD_MODULUS,
            7,
            FIELD_MODULUS,
        )
    return state


def _mimc_hash_many_int(values: list[int]) -> int:
    state = 0
    for value in values:
        state = _mimc_permute((state + value) % FIELD_MODULUS)
    return state


def _fallback_shielded_command_nullifier_digest(
    input_nullifiers: list[str],
) -> str:
    assert 1 <= len(input_nullifiers) <= MAX_ZK_INPUTS, (
        "invalid input nullifier count"
    )
    parsed = [_field_int(value) for value in input_nullifiers]
    while len(parsed) < MAX_ZK_INPUTS:
        parsed.append(0)
    return _field_hex(_mimc_hash_many_int(parsed))


def _fallback_shielded_command_binding(
    nullifier_digest: str,
    target_digest: str,
    payload_digest: str,
    relayer_digest: str,
    expiry_digest: str,
    chain_digest: str,
    entrypoint_digest: str,
    version_digest: str,
    fee: int,
    public_amount: int,
) -> str:
    return _field_hex(
        _mimc_hash_many_int(
            [
                _field_int(nullifier_digest),
                _field_int(target_digest),
                _field_int(payload_digest),
                _field_int(relayer_digest),
                _field_int(expiry_digest),
                _field_int(chain_digest),
                _field_int(entrypoint_digest),
                _field_int(version_digest),
                fee,
                public_amount,
            ]
        )
    )


def _fallback_shielded_command_execution_tag(
    nullifier_digest: str,
    command_binding: str,
) -> str:
    return _field_hex(
        _mimc_hash_many_int(
            [
                _field_int(nullifier_digest),
                _field_int(command_binding),
            ]
        )
    )


def _install_zk_fallback_bindings() -> None:
    if zk_bridge._native_verifier_bindings() is not None:
        return
    fallback_bindings = {
        "shielded_command_nullifier_digest": _fallback_shielded_command_nullifier_digest,
        "shielded_command_binding": _fallback_shielded_command_binding,
        "shielded_command_execution_tag": _fallback_shielded_command_execution_tag,
        "ZkEncodingError": AssertionError,
        "ZkVerifierError": AssertionError,
    }

    def _fallback_bindings():
        return fallback_bindings

    zk_bridge._native_verifier_bindings = _fallback_bindings


_install_zk_fallback_bindings()


def _set_local_hash_entry(
    client: ContractingClient,
    module_name: str,
    binding: str,
    key: Any,
    value: Any,
) -> None:
    arguments = list(key) if isinstance(key, tuple) else [key]
    client.raw_driver.set_var(
        module_name, binding, arguments=arguments, value=value
    )


def _set_seed_state(
    client: ContractingClient, module_name: str, seed: dict[str, Any]
) -> None:
    for item in seed.get("variables", []):
        client.raw_driver.set_var(
            module_name, item["binding"], value=item["value"]
        )
    for item in seed.get("hashes", []):
        for entry in item.get("entries", []):
            _set_local_hash_entry(
                client,
                module_name,
                item["binding"],
                entry["key"],
                entry["value"],
            )
    for item in seed.get("foreign_variables", []):
        client.raw_driver.set_var(
            item["contract"],
            item["name"],
            value=item["value"],
        )
    for item in seed.get("foreign_hashes", []):
        for entry in item.get("entries", []):
            arguments = (
                list(entry["key"])
                if isinstance(entry["key"], tuple)
                else [entry["key"]]
            )
            client.raw_driver.set_var(
                item["contract"],
                item["name"],
                arguments=arguments,
                value=entry["value"],
            )
    client.raw_driver.commit()


def _query_state(
    client: ContractingClient, module_name: str, queries: dict[str, Any]
) -> dict[str, Any]:
    result: dict[str, Any] = {"variables": [], "hashes": []}
    for binding in queries.get("variables", []):
        result["variables"].append(
            {
                "binding": binding,
                "value": _json_value(
                    client.raw_driver.get_var(module_name, binding)
                ),
            }
        )
    for query in queries.get("hashes", []):
        entries = []
        for key in query.get("keys", []):
            arguments = list(key) if isinstance(key, tuple) else [key]
            entries.append(
                {
                    "key": _json_value(
                        list(key) if isinstance(key, tuple) else key
                    ),
                    "value": _json_value(
                        client.raw_driver.get_var(
                            module_name,
                            query["binding"],
                            arguments=arguments,
                        )
                    ),
                }
            )
        result["hashes"].append(
            {"binding": query["binding"], "entries": entries}
        )
    return result


def _seed_to_json(seed: dict[str, Any]) -> dict[str, Any]:
    return {
        "variables": [
            {
                "binding": item["binding"],
                "value": _json_value(item["value"]),
            }
            for item in seed.get("variables", [])
        ],
        "hashes": [
            {
                "binding": item["binding"],
                "entries": [
                    {
                        "key": _json_value(
                            list(entry["key"])
                            if isinstance(entry["key"], tuple)
                            else entry["key"]
                        ),
                        "value": _json_value(entry["value"]),
                    }
                    for entry in item.get("entries", [])
                ],
            }
            for item in seed.get("hashes", [])
        ],
        "foreign_variables": [
            {
                "contract": item["contract"],
                "name": item["name"],
                "value": _json_value(item["value"]),
            }
            for item in seed.get("foreign_variables", [])
        ],
        "foreign_hashes": [
            {
                "contract": item["contract"],
                "name": item["name"],
                "entries": [
                    {
                        "key": _json_value(
                            list(entry["key"])
                            if isinstance(entry["key"], tuple)
                            else entry["key"]
                        ),
                        "value": _json_value(entry["value"]),
                    }
                    for entry in item.get("entries", [])
                ],
            }
            for item in seed.get("foreign_hashes", [])
        ],
    }


def _initial_state_to_json(
    client: ContractingClient,
    module_name: str,
    spec: dict[str, Any],
) -> dict[str, Any]:
    queries = spec.get("initial_state_queries")
    if queries is not None:
        return _query_state(client, module_name, queries)
    return _seed_to_json(spec.get("seed", {}))


def _merged_context(
    base_context: dict[str, Any], overrides: dict[str, Any] | None = None
) -> dict[str, Any]:
    merged = dict(base_context)
    if overrides is not None:
        merged.update(overrides)
    return merged


def _execute_call(
    client: ContractingClient,
    default_module_name: str,
    base_context: dict[str, Any],
    call_spec: dict[str, Any],
) -> dict[str, Any]:
    context = _merged_context(base_context, call_spec.get("context"))
    contract_name = call_spec.get("module", default_module_name)
    output = client.executor.execute(
        sender=context["signer"],
        contract_name=contract_name,
        function_name=call_spec["function"],
        kwargs=call_spec.get("kwargs", {}),
        environment={
            "now": context["now"],
            "block_num": context["block_num"],
            "block_hash": context["block_hash"],
            "chain_id": context["chain_id"],
        },
        metering=False,
        auto_commit=False,
    )
    if output.get("status_code") != 0:
        raise AssertionError(
            f"{contract_name}.{call_spec['function']} failed during fixture generation: {output.get('result')}"
        )
    return output


def _child_ctx_probe_source() -> str:
    return """
last_caller = Variable()
last_signer = Variable()
last_this = Variable()
last_entry = Variable()
balances = Hash(default_value=0)

@export
def balance_of(account: str):
    last_caller.set(ctx.caller)
    last_signer.set(ctx.signer)
    last_this.set(ctx.this)
    last_entry.set(f"{ctx.entry[0]}.{ctx.entry[1]}")
    return balances[account]
""".strip()


def _ed25519_fixture() -> dict[str, str]:
    signing_key = SigningKey(b"\x11" * 32)
    verify_key = signing_key.verify_key.encode().hex()
    message = "xian-vm-host"
    signature = signing_key.sign(message.encode()).signature.hex()
    return {
        "verify_key": verify_key,
        "message": message,
        "signature": signature,
    }


ED25519_FIXTURE = _ed25519_fixture()


FIXTURES = [
    {
        "name": "transfer_event",
        "module_name": "con_vm_parity_transfer",
        "source": """
balances = Hash(default_value=0)
metadata = Variable()
TransferEvent = LogEvent(
    "Transfer",
    {
        "from": indexed(str),
        "to": indexed(str),
        "amount": int,
    },
)

@export
def transfer(amount: int, to: str):
    sender = ctx.caller
    metadata.set(now)
    balances[sender] -= amount
    balances[to] += amount
    TransferEvent({"from": sender, "to": to, "amount": amount})
    return balances[to]
""".strip(),
        "context": {
            "caller": "alice",
            "signer": "alice",
            "now": 1234,
            "block_num": 99,
            "block_hash": "abc123",
            "chain_id": "localnet",
        },
        "seed": {
            "hashes": [
                {
                    "binding": "balances",
                    "entries": [{"key": "alice", "value": 20}],
                }
            ]
        },
        "call": {
            "function": "transfer",
            "kwargs": {"amount": 5, "to": "bob"},
        },
        "assert_state": {
            "variables": ["metadata"],
            "hashes": [{"binding": "balances", "keys": ["alice", "bob"]}],
        },
    },
    {
        "name": "range_summary",
        "module_name": "con_vm_parity_range",
        "source": """
stats = Hash(default_value=0)
last_summary = Variable()

@export
def summarize(values: list[int], floor: int):
    total = 0
    positives = 0
    for index in range(0, len(values)):
        value = values[index]
        if value > floor and value > 0:
            positives += 1
            total += value
    summary = {"total": total, "positives": positives}
    last_summary.set(summary)
    stats["runs"] += 1
    return summary
""".strip(),
        "context": {
            "caller": "alice",
            "signer": "alice",
            "now": 1,
            "block_num": 1,
            "block_hash": "block1",
            "chain_id": "localnet",
        },
        "seed": {},
        "call": {
            "function": "summarize",
            "kwargs": {"values": [2, -1, 5, 1, 9], "floor": 1},
        },
        "assert_state": {
            "variables": ["last_summary"],
            "hashes": [{"binding": "stats", "keys": ["runs"]}],
        },
    },
    {
        "name": "foreign_state_probe",
        "module_name": "con_vm_parity_foreign",
        "source": """
remote_owner = ForeignVariable(foreign_contract="bank", foreign_name="owner")
remote_balances = ForeignHash(foreign_contract="bank", foreign_name="balances")
seen = Hash(default_value=None)

@export
def inspect(account: str):
    owner = remote_owner.get()
    balance = remote_balances[account]
    snapshot = {"owner": owner, "balance": balance}
    seen[account] = snapshot
    return snapshot
""".strip(),
        "context": {
            "caller": "auditor",
            "signer": "auditor",
            "now": 55,
            "block_num": 5,
            "block_hash": "block5",
            "chain_id": "localnet",
        },
        "seed": {
            "foreign_variables": [
                {"contract": "bank", "name": "owner", "value": "banker"}
            ],
            "foreign_hashes": [
                {
                    "contract": "bank",
                    "name": "balances",
                    "entries": [{"key": "alice", "value": 7}],
                }
            ],
        },
        "call": {
            "function": "inspect",
            "kwargs": {"account": "alice"},
        },
        "assert_state": {
            "variables": [],
            "hashes": [{"binding": "seen", "keys": ["alice"]}],
        },
    },
    {
        "name": "decimal_arithmetic",
        "module_name": "con_vm_parity_decimal",
        "source": """
balances = Hash(default_value=decimal("0"))
last_snapshot = Variable()

@export
def probe():
    balances["alice"] += decimal("0.1234567890123456789012345678909") + 1.5
    total = balances["alice"]
    quotient = total / decimal("2")
    floored = decimal("-5") // decimal("2")
    snapshot = {
        "total": total,
        "quotient": quotient,
        "floored": floored,
        "is_decimal": isinstance(quotient, decimal),
    }
    last_snapshot.set(snapshot)
    return snapshot
""".strip(),
        "context": {
            "caller": "alice",
            "signer": "alice",
            "now": 5,
            "block_num": 5,
            "block_hash": "block5",
            "chain_id": "localnet",
        },
        "seed": {},
        "call": {
            "function": "probe",
        },
        "assert_state": {
            "variables": ["last_snapshot"],
            "hashes": [{"binding": "balances", "keys": ["alice"]}],
        },
    },
    {
        "name": "collection_helpers",
        "module_name": "con_vm_parity_collections",
        "source": """
last_snapshot = Variable()

@export
def probe():
    value = {"b": 2, "a": 5}
    ordered = []
    for key in sorted(value.keys()):
        ordered.append(value.get(key))
    snapshot = {
        "ordered": ordered,
        "sum": sum(ordered),
        "min": min(ordered),
        "max": max(ordered),
        "all": all(ordered),
        "any": any([0, ordered[0]]),
    }
    last_snapshot.set(snapshot)
    return snapshot
""".strip(),
        "context": {
            "caller": "alice",
            "signer": "alice",
            "now": 6,
            "block_num": 6,
            "block_hash": "block6",
            "chain_id": "localnet",
        },
        "seed": {},
        "call": {
            "function": "probe",
        },
        "assert_state": {
            "variables": ["last_snapshot"],
            "hashes": [],
        },
    },
    {
        "name": "time_hash_crypto",
        "module_name": "con_vm_parity_time_hash_crypto",
        "source": """
last_snapshot = Variable()

@export
def probe(vk: str, message: str, signature: str):
    start = datetime.datetime.strptime("2024-01-01 00:00:00", "%Y-%m-%d %H:%M:%S")
    end = now + datetime.timedelta(days=1, seconds=5)
    delta = end - start
    snapshot = {
        "after_now": end > now,
        "delta_seconds": delta.seconds,
        "sha3": hashlib.sha3(message),
        "sha256": hashlib.sha256(message),
        "key_ok": crypto.key_is_valid(vk),
        "sig_ok": crypto.verify(vk, message, signature),
    }
    last_snapshot.set(snapshot)
    return snapshot
""".strip(),
        "context": {
            "caller": "alice",
            "signer": "alice",
            "now": Datetime(2024, 1, 2, 12, 0, 0),
            "block_num": 10,
            "block_hash": "block10",
            "chain_id": "localnet",
        },
        "seed": {},
        "call": {
            "function": "probe",
            "kwargs": {
                "vk": ED25519_FIXTURE["verify_key"],
                "message": ED25519_FIXTURE["message"],
                "signature": ED25519_FIXTURE["signature"],
            },
        },
        "assert_state": {
            "variables": ["last_snapshot"],
            "hashes": [],
        },
    },
    {
        "name": "bigint_shielded_primitives",
        "module_name": "con_vm_parity_bigint_shielded",
        "source": """
FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617
FIELD_ZERO_HEX = "0x" + "00" * 32
last_snapshot = Variable()

@export
def probe():
    digest = int(hashlib.sha3("xian-vm-bigint"), 16) % FIELD_MODULUS
    reduced = pow(digest + 7, 7, FIELD_MODULUS)
    rendered_parts = []
    rendered_parts.extend(["0x", format(reduced, "064x")])
    rendered = "".join(rendered_parts)
    prefix_ok = rendered.startswith("0x")
    padded = [FIELD_ZERO_HEX]
    padded.extend([FIELD_ZERO_HEX] * 2)
    snapshot = {
        "field_modulus": FIELD_MODULUS,
        "digest": digest,
        "reduced": reduced,
        "rendered": rendered,
        "prefix_ok": prefix_ok,
        "padded_len": len(padded),
    }
    last_snapshot.set(snapshot)
    return snapshot
""".strip(),
        "context": {
            "caller": "alice",
            "signer": "alice",
            "now": 11,
            "block_num": 11,
            "block_hash": "block11",
            "chain_id": "localnet",
        },
        "seed": {},
        "call": {
            "function": "probe",
        },
        "assert_state": {
            "variables": ["last_snapshot"],
            "hashes": [],
        },
    },
    {
        "name": "static_import_ctx",
        "modules": [
            {
                "module_name": "con_vm_parity_static_child",
                "source": _child_ctx_probe_source(),
                "seed": {
                    "hashes": [
                        {
                            "binding": "balances",
                            "entries": [{"key": "alice", "value": 42}],
                        }
                    ]
                },
            },
            {
                "module_name": "con_vm_parity_static_root",
                "source": """
import con_vm_parity_static_child

@export
def read_balance(account: str):
    return con_vm_parity_static_child.balance_of(account=account)
""".strip(),
                "seed": {},
            },
        ],
        "context": {
            "caller": "alice",
            "signer": "alice",
            "now": 77,
            "block_num": 7,
            "block_hash": "block7",
            "chain_id": "localnet",
        },
        "call": {
            "module": "con_vm_parity_static_root",
            "function": "read_balance",
            "kwargs": {"account": "alice"},
        },
        "assert_state": {
            "con_vm_parity_static_root": {"variables": [], "hashes": []},
            "con_vm_parity_static_child": {
                "variables": [
                    "last_caller",
                    "last_signer",
                    "last_this",
                    "last_entry",
                ],
                "hashes": [{"binding": "balances", "keys": ["alice"]}],
            },
        },
    },
    {
        "name": "dynamic_import_factory_ctx",
        "modules": [
            {
                "module_name": "con_vm_parity_dynamic_child",
                "source": _child_ctx_probe_source(),
                "seed": {
                    "hashes": [
                        {
                            "binding": "balances",
                            "entries": [{"key": "alice", "value": 33}],
                        }
                    ]
                },
            },
            {
                "module_name": "con_vm_parity_dynamic_root",
                "source": """
def load_token(tok: str):
    return importlib.import_module(tok)

@export
def read_balance(tok: str, account: str):
    token = load_token(tok)
    return token.balance_of(account=account)
""".strip(),
                "seed": {},
            },
        ],
        "context": {
            "caller": "alice",
            "signer": "alice",
            "now": 88,
            "block_num": 8,
            "block_hash": "block8",
            "chain_id": "localnet",
        },
        "call": {
            "module": "con_vm_parity_dynamic_root",
            "function": "read_balance",
            "kwargs": {
                "tok": "con_vm_parity_dynamic_child",
                "account": "alice",
            },
        },
        "assert_state": {
            "con_vm_parity_dynamic_root": {"variables": [], "hashes": []},
            "con_vm_parity_dynamic_child": {
                "variables": [
                    "last_caller",
                    "last_signer",
                    "last_this",
                    "last_entry",
                ],
                "hashes": [{"binding": "balances", "keys": ["alice"]}],
            },
        },
    },
    {
        "name": "authored_shielded_note_hash",
        "modules": [
            {
                "module_name": "con_zk_registry",
                "source_path": str(ZK_REGISTRY_SOURCE),
                "constructor_args": {"owner": "operator.alice"},
                "initial_state_queries": {
                    "variables": ["registry_owner", "vk_count"],
                    "hashes": [],
                },
            },
            {
                "module_name": "con_authored_shielded_note_token",
                "source_path": str(SHIELDED_NOTE_TOKEN_SOURCE),
                "source_replacements": [
                    (
                        "import zk_registry",
                        "import con_zk_registry as zk_registry",
                    )
                ],
                "constructor_args": {
                    "token_name": "VM Shielded Note",
                    "token_symbol": "VMSN",
                    "operator_address": "operator.alice",
                    "root_window_size": 16,
                    "token_logo_url": "https://example.invalid/logo.png",
                    "token_logo_svg": "<svg/>",
                    "token_website": "https://example.invalid",
                },
                "initial_state_queries": {
                    "variables": [
                        "operator",
                        "total_supply",
                        "public_supply",
                        "shielded_supply",
                        "root_history_window",
                        "root_count",
                        "current_root",
                        "relay_execution_count",
                        "recent_roots",
                        "frontier_state",
                        "note_count",
                    ],
                    "hashes": [
                        {
                            "binding": "metadata",
                            "keys": [
                                "token_name",
                                "token_symbol",
                                "token_logo_url",
                                "token_logo_svg",
                                "token_website",
                                "precision",
                                "total_supply",
                            ],
                        }
                    ],
                },
            },
        ],
        "context": {
            "caller": "wallet.alice",
            "signer": "wallet.alice",
            "now": Datetime(2024, 3, 1, 10, 30, 0),
            "block_num": 12,
            "block_hash": "block12",
            "chain_id": "localnet",
        },
        "call": {
            "module": "con_authored_shielded_note_token",
            "function": "hash_relay_transfer",
            "kwargs": {
                "input_nullifiers": [FIELD_ONE_HEX, FIELD_TWO_HEX],
                "relayer": "relayer-1",
                "relayer_fee": 3,
                "expires_at": Datetime(2024, 3, 5, 18, 0, 0),
            },
        },
        "assert_state": {
            "con_zk_registry": {
                "variables": ["registry_owner", "vk_count"],
                "hashes": [],
            },
            "con_authored_shielded_note_token": {
                "variables": [
                    "operator",
                    "total_supply",
                    "public_supply",
                    "shielded_supply",
                    "root_history_window",
                    "root_count",
                    "current_root",
                    "relay_execution_count",
                    "recent_roots",
                    "frontier_state",
                    "note_count",
                ],
                "hashes": [
                    {
                        "binding": "metadata",
                        "keys": [
                            "token_name",
                            "token_symbol",
                            "token_logo_url",
                            "token_logo_svg",
                            "token_website",
                            "precision",
                            "total_supply",
                        ],
                    }
                ],
            },
        },
    },
    {
        "name": "authored_shielded_commands_hash",
        "modules": [
            {
                "module_name": "con_zk_registry",
                "source_path": str(ZK_REGISTRY_SOURCE),
                "constructor_args": {"owner": "operator.alice"},
                "initial_state_queries": {
                    "variables": ["registry_owner", "vk_count"],
                    "hashes": [],
                },
            },
            {
                "module_name": "con_vm_fee_token",
                "source": """
balances = Hash(default_value=0)

@export
def transfer(amount: int, to: str):
    return amount

@export
def transfer_from(amount: int, to: str, main_account: str):
    return amount

@export
def balance_of(account: str):
    return balances[account]
""".strip(),
                "initial_state_queries": {
                    "variables": [],
                    "hashes": [],
                },
            },
            {
                "module_name": "con_vm_target_app",
                "source": """
@export
def interact(payload: dict = None):
    return payload
""".strip(),
                "initial_state_queries": {
                    "variables": [],
                    "hashes": [],
                },
            },
            {
                "module_name": "con_authored_shielded_commands",
                "source_path": str(SHIELDED_COMMANDS_SOURCE),
                "source_replacements": [
                    (
                        "import zk_registry",
                        "import con_zk_registry as zk_registry",
                    )
                ],
                "constructor_args": {
                    "token_contract": "con_vm_fee_token",
                    "name": "VM Shielded Commands",
                    "operator_address": "operator.alice",
                    "root_window_size": 16,
                },
                "initial_state_queries": {
                    "variables": [
                        "operator",
                        "fee_token_contract",
                        "escrow_balance",
                        "root_history_window",
                        "root_count",
                        "current_root",
                        "execution_count",
                        "execution_lock",
                        "active_execution_target",
                        "active_public_spend_remaining",
                        "note_count",
                    ],
                    "hashes": [
                        {
                            "binding": "accepted_roots",
                            "keys": [
                                "0x2fdfc505f5f2654af1528f65398e82c2c38814001634e8ea2965f51b038551f1"
                            ],
                        },
                        {"binding": "root_history", "keys": [0]},
                        {
                            "binding": "metadata",
                            "keys": ["name", "restrict_relayers"],
                        },
                    ],
                },
            },
        ],
        "context": {
            "caller": "wallet.alice",
            "signer": "wallet.alice",
            "now": Datetime(2024, 4, 1, 9, 0, 0),
            "block_num": 13,
            "block_hash": "block13",
            "chain_id": "localnet",
        },
        "call": {
            "module": "con_authored_shielded_commands",
            "function": "hash_command",
            "kwargs": {
                "input_nullifiers": [FIELD_ONE_HEX, FIELD_TWO_HEX],
                "target_contract": "con_vm_target_app",
                "relayer": "relayer-1",
                "fee": 4,
                "public_amount": 9,
                "payload": {
                    "memo": "vm parity",
                    "flags": [1, True],
                    "meta": {"route": "dex", "limit": 2},
                },
                "expires_at": Datetime(2024, 4, 3, 12, 15, 0),
            },
        },
        "assert_state": {
            "con_zk_registry": {
                "variables": ["registry_owner", "vk_count"],
                "hashes": [],
            },
            "con_vm_fee_token": {"variables": [], "hashes": []},
            "con_vm_target_app": {"variables": [], "hashes": []},
            "con_authored_shielded_commands": {
                "variables": [
                    "operator",
                    "fee_token_contract",
                    "escrow_balance",
                    "root_history_window",
                    "root_count",
                    "current_root",
                    "execution_count",
                    "execution_lock",
                    "active_execution_target",
                    "active_public_spend_remaining",
                    "note_count",
                ],
                "hashes": [
                    {
                        "binding": "accepted_roots",
                        "keys": [
                            "0x2fdfc505f5f2654af1528f65398e82c2c38814001634e8ea2965f51b038551f1"
                        ],
                    },
                    {"binding": "root_history", "keys": [0]},
                    {
                        "binding": "metadata",
                        "keys": ["name", "restrict_relayers"],
                    },
                ],
            },
        },
    },
    {
        "name": "authored_currency_transfer",
        "module_name": "con_currency_vm",
        "source_path": str(GENESIS_CURRENCY_SOURCE),
        "constructor_args": {"vk": "founder_alice"},
        "context": {
            "caller": "founder_alice",
            "signer": "founder_alice",
            "now": Datetime(2024, 5, 1, 8, 0, 0),
            "block_num": 14,
            "block_hash": "block14",
            "chain_id": "localnet",
        },
        "initial_state_queries": {
            "variables": [],
            "hashes": [
                {
                    "binding": "balances",
                    "keys": ["founder_alice", "team_lock", "dao"],
                },
                {
                    "binding": "metadata",
                    "keys": [
                        "token_name",
                        "token_symbol",
                        "token_logo_url",
                        "token_logo_svg",
                        "token_website",
                        "total_supply",
                        "operator",
                        "permit_authorizer",
                    ],
                },
            ],
        },
        "call": {
            "function": "transfer",
            "kwargs": {"amount": 12.5, "to": "bob_wallet"},
        },
        "assert_state": {
            "variables": [],
            "hashes": [
                {
                    "binding": "balances",
                    "keys": ["founder_alice", "bob_wallet", "team_lock", "dao"],
                },
                {
                    "binding": "metadata",
                    "keys": [
                        "token_name",
                        "token_symbol",
                        "token_logo_url",
                        "token_logo_svg",
                        "token_website",
                        "total_supply",
                        "operator",
                        "permit_authorizer",
                    ],
                },
            ],
        },
    },
    {
        "name": "authored_stable_token_burn",
        "module_name": "con_stable_token_vm",
        "source_path": str(STABLE_TOKEN_SOURCE),
        "constructor_args": {
            "token_name": "VM Stable",
            "token_symbol": "VMS",
            "token_logo_url": "https://example.invalid/vms.png",
            "token_logo_svg": "<svg/>",
            "token_website": "https://example.invalid/stable",
            "initial_supply": 1000.25,
            "initial_holder": "stable_alice",
            "governor_address": "gov_alice",
        },
        "context": {
            "caller": "stable_alice",
            "signer": "stable_alice",
            "now": Datetime(2024, 5, 2, 9, 30, 0),
            "block_num": 15,
            "block_hash": "block15",
            "chain_id": "localnet",
        },
        "initial_state_queries": {
            "variables": ["governor", "proposed_governor", "total_supply"],
            "hashes": [
                {"binding": "balances", "keys": ["stable_alice"]},
                {
                    "binding": "metadata",
                    "keys": [
                        "token_name",
                        "token_symbol",
                        "token_logo_url",
                        "token_logo_svg",
                        "token_website",
                        "total_supply",
                    ],
                },
            ],
        },
        "call": {
            "function": "burn",
            "kwargs": {"amount": 7.5},
        },
        "assert_state": {
            "variables": ["governor", "proposed_governor", "total_supply"],
            "hashes": [
                {"binding": "balances", "keys": ["stable_alice"]},
                {
                    "binding": "metadata",
                    "keys": [
                        "token_name",
                        "token_symbol",
                        "token_logo_url",
                        "token_logo_svg",
                        "token_website",
                        "total_supply",
                    ],
                },
            ],
        },
    },
    {
        "name": "authored_reflection_transfer",
        "module_name": "con_reflection_token_vm",
        "source_path": str(REFLECTION_TOKEN_SOURCE),
        "context": {
            "caller": "reflect_alice",
            "signer": "reflect_alice",
            "now": Datetime(2024, 5, 3, 11, 45, 0),
            "block_num": 16,
            "block_hash": "block16",
            "chain_id": "localnet",
        },
        "initial_state_queries": {
            "variables": [
                "r_total",
                "t_total",
                "reward_excluded_r_total",
                "reward_excluded_t_total",
                "operator",
            ],
            "hashes": [
                {"binding": "balances", "keys": ["reflect_alice"]},
                {
                    "binding": "metadata",
                    "keys": [
                        "token_name",
                        "token_symbol",
                        "operator",
                        "total_supply",
                    ],
                },
                {
                    "binding": "excluded",
                    "keys": [
                        "con_reflection_token_vm",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                    ],
                },
            ],
        },
        "call": {
            "function": "transfer",
            "kwargs": {"amount": 100.0, "to": "reflect_bob"},
        },
        "assert_state": {
            "variables": [
                "r_total",
                "t_total",
                "reward_excluded_r_total",
                "reward_excluded_t_total",
                "operator",
            ],
            "hashes": [
                {
                    "binding": "balances",
                    "keys": ["reflect_alice", "reflect_bob"],
                },
                {
                    "binding": "metadata",
                    "keys": [
                        "token_name",
                        "token_symbol",
                        "operator",
                        "total_supply",
                    ],
                },
                {
                    "binding": "excluded",
                    "keys": [
                        "con_reflection_token_vm",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                    ],
                },
            ],
        },
    },
    {
        "name": "authored_profile_channel",
        "module_name": "con_profile_registry_vm",
        "source_path": str(PROFILE_REGISTRY_SOURCE),
        "context": {
            "caller": "profile_alice",
            "signer": "profile_alice",
            "now": Datetime(2024, 5, 4, 12, 0, 0),
            "block_num": 17,
            "block_hash": "block17",
            "chain_id": "localnet",
        },
        "setup_calls": [
            {
                "function": "register_profile",
                "kwargs": {
                    "username": "Alice-One",
                    "display_name": "Alice One",
                    "metadata_uri": "ipfs://alice-profile",
                },
            },
            {
                "function": "register_profile",
                "kwargs": {
                    "username": "Bob_Two",
                    "display_name": "Bob Two",
                    "metadata_uri": "ipfs://bob-profile",
                },
                "context": {
                    "caller": "profile_bob",
                    "signer": "profile_bob",
                    "now": Datetime(2024, 5, 4, 12, 5, 0),
                },
            },
        ],
        "initial_state_queries": {
            "variables": [],
            "hashes": [
                {"binding": "metadata", "keys": ["name", "operator"]},
                {"binding": "usernames", "keys": ["alice-one", "bob_two"]},
                {
                    "binding": "profiles",
                    "keys": [
                        ("profile_alice", "username"),
                        ("profile_bob", "username"),
                    ],
                },
            ],
        },
        "call": {
            "function": "create_channel",
            "kwargs": {
                "channel_name": "Dev-Hub",
                "members": ["profile_bob"],
                "metadata_uri": "ipfs://dev-hub",
                "encryption_mode": "e2ee",
            },
        },
        "assert_state": {
            "variables": [],
            "hashes": [
                {"binding": "metadata", "keys": ["name", "operator"]},
                {"binding": "usernames", "keys": ["alice-one", "bob_two"]},
                {
                    "binding": "profiles",
                    "keys": [
                        ("profile_alice", "username"),
                        ("profile_bob", "username"),
                    ],
                },
                {
                    "binding": "channels",
                    "keys": [
                        ("dev-hub", "owner"),
                        ("dev-hub", "metadata_uri"),
                        ("dev-hub", "encryption_mode"),
                        ("dev-hub", "members"),
                    ],
                },
                {
                    "binding": "channel_members",
                    "keys": [
                        ("dev-hub", "profile_alice"),
                        ("dev-hub", "profile_bob"),
                    ],
                },
            ],
        },
    },
    {
        "name": "authored_turn_based_join",
        "module_name": "con_turn_based_games_vm",
        "source_path": str(TURN_BASED_GAMES_SOURCE),
        "constructor_args": {"operator": "player_alice"},
        "context": {
            "caller": "player_bob",
            "signer": "player_bob",
            "now": Datetime(2024, 5, 5, 9, 15, 0),
            "block_num": 18,
            "block_hash": "block18",
            "chain_id": "localnet",
        },
        "setup_calls": [
            {
                "function": "set_game_type_allowed",
                "kwargs": {"game_type": "Chess-960", "enabled": True},
                "context": {
                    "caller": "player_alice",
                    "signer": "player_alice",
                    "now": Datetime(2024, 5, 5, 9, 0, 0),
                },
            },
            {
                "function": "create_match",
                "kwargs": {
                    "game_type": "Chess-960",
                    "opponent": "player_bob",
                    "public": False,
                    "rounds": 3,
                    "metadata_uri": "ipfs://match-0",
                    "opening_state": "fen:start",
                },
                "context": {
                    "caller": "player_alice",
                    "signer": "player_alice",
                    "now": Datetime(2024, 5, 5, 9, 5, 0),
                },
            },
        ],
        "initial_state_queries": {
            "variables": ["next_match_id"],
            "hashes": [
                {"binding": "metadata", "keys": ["name", "operator"]},
                {"binding": "allowed_game_types", "keys": ["chess-960"]},
                {
                    "binding": "matches",
                    "keys": [
                        (0, "status"),
                        (0, "game_type"),
                        (0, "creator"),
                        (0, "opponent"),
                        (0, "public"),
                        (0, "rounds"),
                        (0, "current_turn"),
                        (0, "move_count"),
                        (0, "joined_at"),
                    ],
                },
            ],
        },
        "call": {
            "function": "join_match",
            "kwargs": {"match_id": 0},
        },
        "assert_state": {
            "variables": ["next_match_id"],
            "hashes": [
                {"binding": "metadata", "keys": ["name", "operator"]},
                {"binding": "allowed_game_types", "keys": ["chess-960"]},
                {
                    "binding": "matches",
                    "keys": [
                        (0, "status"),
                        (0, "game_type"),
                        (0, "creator"),
                        (0, "opponent"),
                        (0, "public"),
                        (0, "rounds"),
                        (0, "current_turn"),
                        (0, "move_count"),
                        (0, "joined_at"),
                    ],
                },
            ],
        },
    },
    {
        "name": "authored_oracle_price_info",
        "module_name": "con_oracle_vm",
        "source_path": str(ORACLE_SOURCE),
        "constructor_args": {"governor_address": "oracle_governor"},
        "context": {
            "caller": "oracle_observer",
            "signer": "oracle_observer",
            "now": Datetime(2024, 5, 6, 8, 5, 0),
            "block_num": 19,
            "block_hash": "block19",
            "chain_id": "localnet",
        },
        "setup_calls": [
            {
                "function": "set_reporter",
                "kwargs": {"account": "oracle_reporter_bob", "enabled": True},
                "context": {
                    "caller": "oracle_governor",
                    "signer": "oracle_governor",
                    "now": Datetime(2024, 5, 6, 8, 0, 0),
                },
            },
            {
                "function": "set_asset_config",
                "kwargs": {
                    "asset": "XIAN",
                    "min_reporters_required": 2,
                    "max_price_age_seconds": 600,
                },
                "context": {
                    "caller": "oracle_governor",
                    "signer": "oracle_governor",
                    "now": Datetime(2024, 5, 6, 8, 0, 30),
                },
            },
            {
                "function": "submit_price",
                "kwargs": {
                    "asset": "XIAN",
                    "price": 1.5,
                    "source": "alpha",
                },
                "context": {
                    "caller": "oracle_governor",
                    "signer": "oracle_governor",
                    "now": Datetime(2024, 5, 6, 8, 1, 0),
                },
            },
            {
                "function": "submit_price",
                "kwargs": {
                    "asset": "XIAN",
                    "price": 1.7,
                    "source": "beta",
                },
                "context": {
                    "caller": "oracle_reporter_bob",
                    "signer": "oracle_reporter_bob",
                    "now": Datetime(2024, 5, 6, 8, 2, 0),
                },
            },
        ],
        "initial_state_queries": {
            "variables": ["governor", "proposed_governor", "reporter_accounts"],
            "hashes": [
                {
                    "binding": "reporters",
                    "keys": ["oracle_governor", "oracle_reporter_bob"],
                },
                {"binding": "min_reporters", "keys": ["XIAN"]},
                {"binding": "max_age_seconds", "keys": ["XIAN"]},
                {
                    "binding": "reported_prices",
                    "keys": [
                        ("XIAN", "oracle_governor"),
                        ("XIAN", "oracle_reporter_bob"),
                    ],
                },
                {
                    "binding": "reported_at",
                    "keys": [
                        ("XIAN", "oracle_governor"),
                        ("XIAN", "oracle_reporter_bob"),
                    ],
                },
                {
                    "binding": "reported_sources",
                    "keys": [
                        ("XIAN", "oracle_governor"),
                        ("XIAN", "oracle_reporter_bob"),
                    ],
                },
            ],
        },
        "call": {
            "function": "price_info",
            "kwargs": {"asset": "XIAN"},
        },
        "assert_state": {
            "variables": ["governor", "proposed_governor", "reporter_accounts"],
            "hashes": [
                {
                    "binding": "reporters",
                    "keys": ["oracle_governor", "oracle_reporter_bob"],
                },
                {"binding": "min_reporters", "keys": ["XIAN"]},
                {"binding": "max_age_seconds", "keys": ["XIAN"]},
                {
                    "binding": "reported_prices",
                    "keys": [
                        ("XIAN", "oracle_governor"),
                        ("XIAN", "oracle_reporter_bob"),
                    ],
                },
                {
                    "binding": "reported_at",
                    "keys": [
                        ("XIAN", "oracle_governor"),
                        ("XIAN", "oracle_reporter_bob"),
                    ],
                },
                {
                    "binding": "reported_sources",
                    "keys": [
                        ("XIAN", "oracle_governor"),
                        ("XIAN", "oracle_reporter_bob"),
                    ],
                },
            ],
        },
    },
    {
        "name": "authored_members_reward_change",
        "modules": [
            {
                "module_name": "con_dao",
                "source_path": str(DAO_SOURCE),
                "initial_state_queries": {"variables": [], "hashes": []},
            },
            {
                "module_name": "con_rewards",
                "source_path": str(REWARDS_SOURCE),
                "initial_state_queries": {
                    "variables": [],
                    "hashes": [{"binding": "S", "keys": ["value"]}],
                },
            },
            {
                "module_name": "con_chi_cost",
                "source_path": str(CHI_COST_SOURCE),
                "initial_state_queries": {
                    "variables": [],
                    "hashes": [{"binding": "S", "keys": ["value"]}],
                },
            },
            {
                "module_name": "con_currency",
                "source_path": str(GENESIS_CURRENCY_SOURCE),
                "constructor_args": {"vk": "genesis_alice"},
                "initial_state_queries": {
                    "variables": [],
                    "hashes": [
                        {
                            "binding": "balances",
                            "keys": [
                                "genesis_alice",
                                "validator_bob",
                                "con_members",
                            ],
                        },
                        {
                            "binding": "approvals",
                            "keys": [("validator_bob", "con_members")],
                        },
                        {
                            "binding": "metadata",
                            "keys": [
                                "token_name",
                                "token_symbol",
                                "total_supply",
                            ],
                        },
                    ],
                },
            },
            {
                "module_name": "con_members",
                "source_path": str(MEMBERS_SOURCE),
                "source_replacements": [
                    ("import dao", "import con_dao as dao"),
                    ("import rewards", "import con_rewards as rewards"),
                    ("import chi_cost", "import con_chi_cost as chi_cost"),
                    ("import currency", "import con_currency as currency"),
                ],
                "constructor_args": {
                    "genesis_nodes": ["genesis_alice"],
                    "genesis_registration_fee": 25,
                },
                "initial_state_queries": {
                    "variables": [
                        "nodes",
                        "candidates",
                        "types",
                        "total_votes",
                        "registration_fee",
                    ],
                    "hashes": [
                        {
                            "binding": "pending_registrations",
                            "keys": ["validator_bob"],
                        },
                        {"binding": "holdings", "keys": ["validator_bob"]},
                        {"binding": "statuses", "keys": ["validator_bob"]},
                        {"binding": "reward_keys", "keys": ["validator_bob"]},
                        {"binding": "votes", "keys": [1]},
                    ],
                },
            },
        ],
        "context": {
            "caller": "genesis_alice",
            "signer": "genesis_alice",
            "now": Datetime(2024, 5, 7, 9, 0, 0),
            "block_num": 20,
            "block_hash": "block20",
            "chain_id": "localnet",
        },
        "setup_calls": [
            {
                "module": "con_currency",
                "function": "transfer",
                "kwargs": {"amount": 100.0, "to": "validator_bob"},
                "context": {
                    "caller": "genesis_alice",
                    "signer": "genesis_alice",
                    "now": Datetime(2024, 5, 7, 9, 1, 0),
                },
            },
            {
                "module": "con_currency",
                "function": "approve",
                "kwargs": {"amount": 25.0, "to": "con_members"},
                "context": {
                    "caller": "validator_bob",
                    "signer": "validator_bob",
                    "now": Datetime(2024, 5, 7, 9, 2, 0),
                },
            },
            {
                "module": "con_members",
                "function": "register",
                "kwargs": {
                    "reward_key": "validator_bob_rewards",
                    "requested_validator_power": 12,
                    "commission_bps_value": 150,
                    "moniker": "validator-bob",
                    "network_endpoint": "https://validator-bob.invalid",
                    "metadata_uri": "ipfs://validator-bob",
                },
                "context": {
                    "caller": "validator_bob",
                    "signer": "validator_bob",
                    "now": Datetime(2024, 5, 7, 9, 3, 0),
                },
            },
        ],
        "call": {
            "module": "con_members",
            "function": "propose_vote",
            "kwargs": {
                "type_of_vote": "reward_change",
                "arg": [0.25, 0.25, 0.25, 0.25],
            },
        },
        "assert_state": {
            "con_dao": {"variables": [], "hashes": []},
            "con_rewards": {
                "variables": [],
                "hashes": [{"binding": "S", "keys": ["value"]}],
            },
            "con_chi_cost": {
                "variables": [],
                "hashes": [{"binding": "S", "keys": ["value"]}],
            },
            "con_currency": {
                "variables": [],
                "hashes": [
                    {
                        "binding": "balances",
                        "keys": [
                            "genesis_alice",
                            "validator_bob",
                            "con_members",
                        ],
                    },
                    {
                        "binding": "approvals",
                        "keys": [("validator_bob", "con_members")],
                    },
                    {
                        "binding": "metadata",
                        "keys": ["token_name", "token_symbol", "total_supply"],
                    },
                ],
            },
            "con_members": {
                "variables": [
                    "nodes",
                    "candidates",
                    "total_votes",
                    "registration_fee",
                ],
                "hashes": [
                    {
                        "binding": "pending_registrations",
                        "keys": ["validator_bob"],
                    },
                    {"binding": "holdings", "keys": ["validator_bob"]},
                    {"binding": "statuses", "keys": ["validator_bob"]},
                    {"binding": "reward_keys", "keys": ["validator_bob"]},
                    {"binding": "votes", "keys": [1]},
                ],
            },
        },
    },
    {
        "name": "authored_dex_swap_path",
        "modules": [
            {
                "module_name": "con_pairs",
                "source_path": str(PAIRS_SOURCE),
                "source_replacements": [
                    ("\t\tscale *= 10", "\t\tscale = scale * 10"),
                ],
                "initial_state_queries": {
                    "variables": ["pairs_num", "feeTo", "owner", "LOCK"],
                    "hashes": [
                        {
                            "binding": "toks_to_pair",
                            "keys": [
                                (
                                    "con_currency_dex",
                                    "con_stable_dex_token",
                                )
                            ],
                        },
                        {
                            "binding": "pairs",
                            "keys": [
                                (1, "token0"),
                                (1, "token1"),
                                (1, "reserve0"),
                                (1, "reserve1"),
                                (1, "balance0"),
                                (1, "balance1"),
                                (1, "totalSupply"),
                                (1, "balances", "dex_alice"),
                            ],
                        },
                        {
                            "binding": "balances",
                            "keys": [
                                "con_currency_dex",
                                "con_stable_dex_token",
                            ],
                        },
                    ],
                },
            },
            {
                "module_name": "con_dex",
                "source_path": str(DEX_SOURCE),
                "source_replacements": [
                    ("\t\tscale *= 10", "\t\tscale = scale * 10"),
                ],
                "initial_state_queries": {"variables": ["owner"], "hashes": []},
            },
            {
                "module_name": "con_currency_dex",
                "source_path": str(GENESIS_CURRENCY_SOURCE),
                "constructor_args": {"vk": "dex_alice"},
                "initial_state_queries": {
                    "variables": [],
                    "hashes": [
                        {
                            "binding": "balances",
                            "keys": ["dex_alice", "dex_bob", "con_pairs"],
                        },
                        {
                            "binding": "approvals",
                            "keys": [
                                ("dex_alice", "con_dex"),
                                ("dex_bob", "con_dex"),
                            ],
                        },
                    ],
                },
            },
            {
                "module_name": "con_stable_dex_token",
                "source_path": str(STABLE_TOKEN_SOURCE),
                "constructor_args": {
                    "token_name": "Stable Dex",
                    "token_symbol": "SDX",
                    "token_logo_url": "https://example.invalid/sdx.png",
                    "token_logo_svg": "<svg/>",
                    "token_website": "https://example.invalid/sdx",
                    "initial_supply": 5000.0,
                    "initial_holder": "dex_alice",
                    "governor_address": "dex_governor",
                },
                "initial_state_queries": {
                    "variables": [
                        "governor",
                        "proposed_governor",
                        "total_supply",
                    ],
                    "hashes": [
                        {
                            "binding": "balances",
                            "keys": ["dex_alice", "con_pairs"],
                        },
                        {
                            "binding": "approvals",
                            "keys": [("dex_alice", "con_dex")],
                        },
                    ],
                },
            },
        ],
        "context": {
            "caller": "dex_bob",
            "signer": "dex_bob",
            "now": Datetime(2024, 5, 8, 11, 0, 0),
            "block_num": 21,
            "block_hash": "block21",
            "chain_id": "localnet",
        },
        "setup_calls": [
            {
                "module": "con_currency_dex",
                "function": "approve",
                "kwargs": {"amount": 1000.0, "to": "con_dex"},
                "context": {
                    "caller": "dex_alice",
                    "signer": "dex_alice",
                    "now": Datetime(2024, 5, 8, 10, 0, 0),
                },
            },
            {
                "module": "con_stable_dex_token",
                "function": "approve",
                "kwargs": {"amount": 2000.0, "to": "con_dex"},
                "context": {
                    "caller": "dex_alice",
                    "signer": "dex_alice",
                    "now": Datetime(2024, 5, 8, 10, 1, 0),
                },
            },
            {
                "module": "con_dex",
                "function": "addLiquidity",
                "kwargs": {
                    "tokenA": "con_currency_dex",
                    "tokenB": "con_stable_dex_token",
                    "amountADesired": 1000.0,
                    "amountBDesired": 2000.0,
                    "amountAMin": 1000.0,
                    "amountBMin": 2000.0,
                    "to": "dex_alice",
                    "deadline": Datetime(2024, 5, 8, 10, 30, 0),
                },
                "context": {
                    "caller": "dex_alice",
                    "signer": "dex_alice",
                    "now": Datetime(2024, 5, 8, 10, 2, 0),
                },
            },
            {
                "module": "con_currency_dex",
                "function": "transfer",
                "kwargs": {"amount": 50.0, "to": "dex_bob"},
                "context": {
                    "caller": "dex_alice",
                    "signer": "dex_alice",
                    "now": Datetime(2024, 5, 8, 10, 3, 0),
                },
            },
            {
                "module": "con_currency_dex",
                "function": "approve",
                "kwargs": {"amount": 25.0, "to": "con_dex"},
                "context": {
                    "caller": "dex_bob",
                    "signer": "dex_bob",
                    "now": Datetime(2024, 5, 8, 10, 4, 0),
                },
            },
        ],
        "call": {
            "module": "con_dex",
            "function": "swapExactTokenForToken",
            "kwargs": {
                "amountIn": 10.0,
                "amountOutMin": 1.0,
                "pair": 1,
                "src": "con_currency_dex",
                "to": "dex_bob",
                "deadline": Datetime(2024, 5, 8, 11, 30, 0),
            },
        },
        "assert_state": {
            "con_pairs": {
                "variables": ["pairs_num", "feeTo", "owner", "LOCK"],
                "hashes": [
                    {
                        "binding": "toks_to_pair",
                        "keys": [
                            (
                                "con_currency_dex",
                                "con_stable_dex_token",
                            )
                        ],
                    },
                    {
                        "binding": "pairs",
                        "keys": [
                            (1, "token0"),
                            (1, "token1"),
                            (1, "reserve0"),
                            (1, "reserve1"),
                            (1, "balance0"),
                            (1, "balance1"),
                            (1, "totalSupply"),
                            (1, "balances", "dex_alice"),
                        ],
                    },
                    {
                        "binding": "balances",
                        "keys": [
                            "con_currency_dex",
                            "con_stable_dex_token",
                        ],
                    },
                ],
            },
            "con_dex": {"variables": ["owner"], "hashes": []},
            "con_currency_dex": {
                "variables": [],
                "hashes": [
                    {
                        "binding": "balances",
                        "keys": ["dex_alice", "dex_bob", "con_pairs"],
                    },
                    {
                        "binding": "approvals",
                        "keys": [
                            ("dex_alice", "con_dex"),
                            ("dex_bob", "con_dex"),
                        ],
                    },
                ],
            },
            "con_stable_dex_token": {
                "variables": ["governor", "proposed_governor", "total_supply"],
                "hashes": [
                    {
                        "binding": "balances",
                        "keys": ["dex_alice", "dex_bob", "con_pairs"],
                    },
                    {
                        "binding": "approvals",
                        "keys": [("dex_alice", "con_dex")],
                    },
                ],
            },
        },
    },
]


def build_fixture(spec: dict[str, Any]) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="xian-vm-parity-") as tempdir:
        client = ContractingClient(
            signer=spec["context"]["signer"],
            storage_home=Path(tempdir),
            metering=False,
        )
        default_module_name = (
            spec["call"]["module"] if "modules" in spec else spec["module_name"]
        )
        modules = spec["modules"] if "modules" in spec else [spec]

        for module in modules:
            source = _module_source(module)
            client.submit(
                source,
                name=module["module_name"],
                owner=module.get("owner"),
                constructor_args=module.get("constructor_args", {}),
                signer=spec["context"]["signer"],
            )
            module["_resolved_source"] = source

        for module in modules:
            _set_seed_state(
                client, module["module_name"], module.get("seed", {})
            )

        for setup_call in spec.get("setup_calls", []):
            _execute_call(
                client,
                default_module_name,
                spec["context"],
                setup_call,
            )

        module_initial_states = {
            module["module_name"]: _initial_state_to_json(
                client,
                module["module_name"],
                module,
            )
            for module in modules
        }

        output = _execute_call(
            client,
            default_module_name,
            spec["context"],
            spec["call"],
        )

        fixture_modules = [
            {
                "module_name": module["module_name"],
                "owner": module.get("owner"),
                "ir": ContractingCompiler(
                    module_name=module["module_name"]
                ).lower_to_ir(module["_resolved_source"]),
                "initial_state": module_initial_states[module["module_name"]],
            }
            for module in modules
        ]

        if "modules" in spec:
            expected_state = {
                module_name: _query_state(client, module_name, module_state)
                for module_name, module_state in spec["assert_state"].items()
            }
        else:
            expected_state = {
                default_module_name: _query_state(
                    client,
                    default_module_name,
                    spec["assert_state"],
                )
            }

        return {
            "name": spec["name"],
            "modules": fixture_modules,
            "context": {
                key: _json_value(value)
                for key, value in spec["context"].items()
            },
            "call": {
                "module": default_module_name,
                "function": spec["call"]["function"],
                "args": [
                    _json_value(value) for value in spec["call"].get("args", [])
                ],
                "kwargs": {
                    key: _json_value(value)
                    for key, value in spec["call"].get("kwargs", {}).items()
                },
            },
            "expected": {
                "result": _json_value(output["result"]),
                "events": [_json_value(event) for event in output["events"]],
                "state": expected_state,
            },
        }


def main() -> None:
    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    generated = []
    for spec in FIXTURES:
        fixture = build_fixture(spec)
        target = FIXTURE_DIR / f"{spec['name']}.json"
        target.write_text(
            json.dumps(fixture, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        generated.append(target.name)

    print(json.dumps({"generated": generated}, indent=2))


if __name__ == "__main__":
    main()
