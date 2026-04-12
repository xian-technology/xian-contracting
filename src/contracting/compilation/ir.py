"""Structural IR helpers for the first Xian VM profile."""

from __future__ import annotations

from typing import Any

XIAN_IR_V1 = "xian_ir_v1"
XIAN_VM_HOST_CATALOG_V1 = "xian_vm_v1_host_v1"


def _host_binding(
    binding: str,
    identifier: str,
    *,
    kind: str,
    category: str,
) -> dict[str, str]:
    return {
        "binding": binding,
        "id": identifier,
        "kind": kind,
        "category": category,
    }


_HOST_BINDINGS = (
    _host_binding("Any", "typing.any", kind="type_marker", category="typing"),
    _host_binding(
        "Variable",
        "storage.variable.new",
        kind="syscall",
        category="storage",
    ),
    _host_binding(
        "Variable.get",
        "storage.variable.get",
        kind="syscall",
        category="storage",
    ),
    _host_binding(
        "Variable.set",
        "storage.variable.set",
        kind="syscall",
        category="storage",
    ),
    _host_binding(
        "Hash",
        "storage.hash.new",
        kind="syscall",
        category="storage",
    ),
    _host_binding(
        "Hash.__getitem__",
        "storage.hash.get",
        kind="syscall",
        category="storage",
    ),
    _host_binding(
        "Hash.__setitem__",
        "storage.hash.set",
        kind="syscall",
        category="storage",
    ),
    _host_binding(
        "ForeignVariable",
        "storage.foreign_variable.new",
        kind="syscall",
        category="storage",
    ),
    _host_binding(
        "ForeignVariable.get",
        "storage.foreign_variable.get",
        kind="syscall",
        category="storage",
    ),
    _host_binding(
        "ForeignHash",
        "storage.foreign_hash.new",
        kind="syscall",
        category="storage",
    ),
    _host_binding(
        "ForeignHash.__getitem__",
        "storage.foreign_hash.get",
        kind="syscall",
        category="storage",
    ),
    _host_binding(
        "LogEvent",
        "event.log.new",
        kind="syscall",
        category="event",
    ),
    _host_binding(
        "LogEvent.__call__",
        "event.log.emit",
        kind="syscall",
        category="event",
    ),
    _host_binding(
        "indexed",
        "event.indexed",
        kind="syscall",
        category="event",
    ),
    _host_binding(
        "__Contract",
        "contract.handle.new",
        kind="syscall",
        category="contract",
    ),
    _host_binding(
        "Contract.deploy",
        "contract.deploy",
        kind="syscall",
        category="contract",
    ),
    _host_binding(
        "Contract.get_info",
        "contract.info",
        kind="syscall",
        category="contract",
    ),
    _host_binding(
        "Contract.set_owner",
        "contract.set_owner",
        kind="syscall",
        category="contract",
    ),
    _host_binding(
        "Contract.set_developer",
        "contract.set_developer",
        kind="syscall",
        category="contract",
    ),
    _host_binding(
        "decimal",
        "numeric.decimal.new",
        kind="syscall",
        category="numeric",
    ),
    _host_binding(
        "datetime.datetime",
        "time.datetime.new",
        kind="syscall",
        category="time",
    ),
    _host_binding(
        "datetime.timedelta",
        "time.timedelta.new",
        kind="syscall",
        category="time",
    ),
    _host_binding(
        "datetime.datetime.strptime",
        "time.datetime.strptime",
        kind="syscall",
        category="time",
    ),
    _host_binding(
        "datetime.SECONDS",
        "time.seconds",
        kind="value",
        category="time",
    ),
    _host_binding(
        "datetime.MINUTES",
        "time.minutes",
        kind="value",
        category="time",
    ),
    _host_binding(
        "datetime.HOURS",
        "time.hours",
        kind="value",
        category="time",
    ),
    _host_binding(
        "datetime.DAYS",
        "time.days",
        kind="value",
        category="time",
    ),
    _host_binding(
        "datetime.WEEKS",
        "time.weeks",
        kind="value",
        category="time",
    ),
    _host_binding(
        "hashlib.sha3",
        "hash.sha3_256",
        kind="syscall",
        category="hashing",
    ),
    _host_binding(
        "hashlib.sha256",
        "hash.sha256",
        kind="syscall",
        category="hashing",
    ),
    _host_binding(
        "crypto.verify",
        "crypto.ed25519_verify",
        kind="syscall",
        category="crypto",
    ),
    _host_binding(
        "crypto.key_is_valid",
        "crypto.key_is_valid",
        kind="syscall",
        category="crypto",
    ),
    _host_binding(
        "importlib.import_module",
        "contract.import",
        kind="syscall",
        category="import",
    ),
    _host_binding(
        "importlib.exists",
        "contract.exists",
        kind="syscall",
        category="import",
    ),
    _host_binding(
        "importlib.has_export",
        "contract.has_export",
        kind="syscall",
        category="import",
    ),
    _host_binding(
        "importlib.call",
        "contract.call",
        kind="syscall",
        category="import",
    ),
    _host_binding(
        "importlib.enforce_interface",
        "contract.enforce_interface",
        kind="syscall",
        category="import",
    ),
    _host_binding(
        "importlib.owner_of",
        "contract.owner_of",
        kind="syscall",
        category="import",
    ),
    _host_binding(
        "importlib.contract_info",
        "contract.info",
        kind="syscall",
        category="import",
    ),
    _host_binding(
        "importlib.code_hash",
        "contract.code_hash",
        kind="syscall",
        category="import",
    ),
    _host_binding(
        "importlib.Func",
        "contract.interface.func",
        kind="syscall",
        category="import",
    ),
    _host_binding(
        "importlib.Var",
        "contract.interface.var",
        kind="syscall",
        category="import",
    ),
    _host_binding(
        "__contract_export__",
        "contract.export_call",
        kind="syscall",
        category="contract",
    ),
    _host_binding(
        "random.seed",
        "random.seed",
        kind="syscall",
        category="random",
    ),
    _host_binding(
        "random.shuffle",
        "random.shuffle",
        kind="syscall",
        category="random",
    ),
    _host_binding(
        "random.getrandbits",
        "random.getrandbits",
        kind="syscall",
        category="random",
    ),
    _host_binding(
        "random.randrange",
        "random.randrange",
        kind="syscall",
        category="random",
    ),
    _host_binding(
        "random.randint",
        "random.randint",
        kind="syscall",
        category="random",
    ),
    _host_binding(
        "random.choice",
        "random.choice",
        kind="syscall",
        category="random",
    ),
    _host_binding(
        "random.choices",
        "random.choices",
        kind="syscall",
        category="random",
    ),
    _host_binding(
        "zk.is_available",
        "zk.is_available",
        kind="syscall",
        category="zk",
    ),
    _host_binding(
        "zk.has_verifying_key",
        "zk.has_verifying_key",
        kind="syscall",
        category="zk",
    ),
    _host_binding(
        "zk.verify_groth16_bn254",
        "zk.verify_groth16_bn254",
        kind="syscall",
        category="zk",
    ),
    _host_binding(
        "zk.verify_groth16",
        "zk.verify_groth16",
        kind="syscall",
        category="zk",
    ),
    _host_binding(
        "zk.clear_prepared_vk_cache",
        "zk.clear_prepared_vk_cache",
        kind="syscall",
        category="zk",
    ),
    _host_binding(
        "zk.clear_verified_proof_cache",
        "zk.clear_verified_proof_cache",
        kind="syscall",
        category="zk",
    ),
    _host_binding(
        "zk.warm_verified_proofs",
        "zk.warm_verified_proofs",
        kind="syscall",
        category="zk",
    ),
    _host_binding(
        "zk.shielded_note_append_commitments",
        "zk.shielded_note_append_commitments",
        kind="syscall",
        category="zk",
    ),
    _host_binding(
        "zk.shielded_command_nullifier_digest",
        "zk.shielded_command_nullifier_digest",
        kind="syscall",
        category="zk",
    ),
    _host_binding(
        "zk.shielded_command_binding",
        "zk.shielded_command_binding",
        kind="syscall",
        category="zk",
    ),
    _host_binding(
        "zk.shielded_command_execution_tag",
        "zk.shielded_command_execution_tag",
        kind="syscall",
        category="zk",
    ),
    _host_binding(
        "zk.shielded_command_public_inputs",
        "zk.shielded_command_public_inputs",
        kind="syscall",
        category="zk",
    ),
    _host_binding(
        "zk.shielded_deposit_public_inputs",
        "zk.shielded_deposit_public_inputs",
        kind="syscall",
        category="zk",
    ),
    _host_binding(
        "zk.shielded_output_payload_hashes",
        "zk.shielded_output_payload_hashes",
        kind="syscall",
        category="zk",
    ),
    _host_binding(
        "zk.shielded_output_payload_hash",
        "zk.shielded_output_payload_hash",
        kind="syscall",
        category="zk",
    ),
    _host_binding(
        "zk.shielded_transfer_public_inputs",
        "zk.shielded_transfer_public_inputs",
        kind="syscall",
        category="zk",
    ),
    _host_binding(
        "zk.shielded_withdraw_public_inputs",
        "zk.shielded_withdraw_public_inputs",
        kind="syscall",
        category="zk",
    ),
    _host_binding(
        "ctx.caller",
        "context.caller",
        kind="context_field",
        category="context",
    ),
    _host_binding(
        "ctx.signer",
        "context.signer",
        kind="context_field",
        category="context",
    ),
    _host_binding(
        "ctx.this",
        "context.this",
        kind="context_field",
        category="context",
    ),
    _host_binding(
        "ctx.owner",
        "context.owner",
        kind="context_field",
        category="context",
    ),
    _host_binding(
        "ctx.entry",
        "context.entry",
        kind="context_field",
        category="context",
    ),
    _host_binding(
        "ctx.submission_name",
        "context.submission_name",
        kind="context_field",
        category="context",
    ),
    _host_binding(
        "now",
        "env.now",
        kind="env_value",
        category="environment",
    ),
    _host_binding(
        "block_num",
        "env.block_num",
        kind="env_value",
        category="environment",
    ),
    _host_binding(
        "block_hash",
        "env.block_hash",
        kind="env_value",
        category="environment",
    ),
    _host_binding(
        "chain_id",
        "env.chain_id",
        kind="env_value",
        category="environment",
    ),
)

HOST_BINDINGS = tuple(dict(spec) for spec in _HOST_BINDINGS)
HOST_BINDINGS_BY_PATH = {
    spec["binding"]: dict(spec) for spec in _HOST_BINDINGS
}
HOST_BINDINGS_BY_ID = {spec["id"]: dict(spec) for spec in _HOST_BINDINGS}


def resolve_host_binding(path: str | None) -> dict[str, str] | None:
    if path is None:
        return None
    spec = HOST_BINDINGS_BY_PATH.get(path)
    if spec is None:
        return None
    return dict(spec)


def resolve_host_binding_id(identifier: str | None) -> dict[str, str] | None:
    if identifier is None:
        return None
    spec = HOST_BINDINGS_BY_ID.get(identifier)
    if spec is None:
        return None
    return dict(spec)


def describe_vm_host_surface() -> dict[str, Any]:
    return {
        "catalog_version": XIAN_VM_HOST_CATALOG_V1,
        "bindings": [dict(spec) for spec in HOST_BINDINGS],
    }


def source_span(node) -> dict[str, int]:
    line = getattr(node, "lineno", 1)
    col = getattr(node, "col_offset", 0)
    end_line = getattr(node, "end_lineno", None) or line
    end_col = getattr(node, "end_col_offset", None) or col
    return {
        "line": line,
        "col": col,
        "end_line": end_line,
        "end_col": end_col,
    }


def dotted_path(node) -> str | None:
    import ast

    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted_path(node.value)
        if base is None:
            return None
        return f"{base}.{node.attr}"
    return None
