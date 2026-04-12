"""AST to structural IR lowering for Xian VM prototypes."""

from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass
from typing import Any

from contracting.compilation.ir import (
    XIAN_IR_V1,
    XIAN_VM_HOST_CATALOG_V1,
    dotted_path,
    resolve_host_binding,
    resolve_host_binding_id,
    source_span,
)

_BOOL_OPS = {
    ast.And: "and",
    ast.Or: "or",
}
_BIN_OPS = {
    ast.Add: "add",
    ast.Sub: "sub",
    ast.Mult: "mul",
    ast.Div: "div",
    ast.FloorDiv: "floordiv",
    ast.Mod: "mod",
    ast.Pow: "pow",
}
_UNARY_OPS = {
    ast.Not: "not",
    ast.USub: "neg",
    ast.UAdd: "pos",
}
_COMPARE_OPS = {
    ast.Eq: "eq",
    ast.NotEq: "not_eq",
    ast.Gt: "gt",
    ast.GtE: "gt_e",
    ast.Lt: "lt",
    ast.LtE: "lt_e",
    ast.In: "in",
    ast.NotIn: "not_in",
    ast.Is: "is",
    ast.IsNot: "is_not",
}
_STORAGE_CONSTRUCTORS = {
    "Variable": "storage.variable.new",
    "Hash": "storage.hash.new",
    "ForeignVariable": "storage.foreign_variable.new",
    "ForeignHash": "storage.foreign_hash.new",
}
_STORAGE_METHOD_SYSCALLS = {
    ("Variable", "get"): "storage.variable.get",
    ("Variable", "set"): "storage.variable.set",
    ("ForeignVariable", "get"): "storage.foreign_variable.get",
}
_STORAGE_SUBSCRIPT_READ_SYSCALLS = {
    "Hash": "storage.hash.get",
    "ForeignHash": "storage.foreign_hash.get",
}
_STORAGE_SUBSCRIPT_WRITE_SYSCALLS = {
    "Hash": "storage.hash.set",
}
_EVENT_CONSTRUCTOR = "LogEvent"
_CONTRACT_EXPORT_SYSCALL = "contract.export_call"


@dataclass(frozen=True, slots=True)
class IrLoweringError(Exception):
    message: str
    line: int
    col: int

    def __str__(self) -> str:
        return f"{self.line}:{self.col}: {self.message}"


class XianIrLowerer:
    def __init__(self, *, module_name: str, profile: str):
        self.module_name = module_name
        self.profile = profile
        self.source = ""
        self._host_dependencies: dict[str, dict[str, str]] = {}
        self._event_bindings: set[str] = set()
        self._storage_bindings: dict[str, str] = {}
        self._static_import_bindings: set[str] = set()
        self._contract_handle_factories: set[str] = set()
        self._local_contract_handles: dict[str, ast.AST] = {}

    def lower(self, tree: ast.Module, *, source: str) -> dict[str, Any]:
        self.source = source
        self._host_dependencies = {}
        self._event_bindings = set()
        self._storage_bindings = {}
        self._static_import_bindings = set()
        self._contract_handle_factories = set()
        self._local_contract_handles = {}

        body = list(tree.body)
        docstring = None
        if body and _is_docstring_expr(body[0]):
            docstring = body[0].value.value
            body = body[1:]

        self._inspect_module_bindings(body)
        self._contract_handle_factories = self._discover_contract_handle_factories(
            [node for node in body if isinstance(node, ast.FunctionDef)]
        )

        imports: list[dict[str, Any]] = []
        global_declarations: list[dict[str, Any]] = []
        functions: list[dict[str, Any]] = []
        module_body: list[dict[str, Any]] = []

        for node in body:
            if isinstance(node, ast.Import):
                imports.extend(self._lower_import(node))
                continue
            if isinstance(node, ast.Assign):
                global_declarations.append(
                    self._lower_global_declaration(node)
                )
                continue
            if isinstance(node, ast.FunctionDef):
                functions.append(self._lower_function(node))
                continue
            module_body.append(self._lower_statement(node))

        return {
            "ir_version": XIAN_IR_V1,
            "vm_profile": self.profile,
            "host_catalog_version": XIAN_VM_HOST_CATALOG_V1,
            "module_name": self.module_name,
            "source_hash": hashlib.sha256(source.encode("utf-8")).hexdigest(),
            "docstring": docstring,
            "imports": imports,
            "global_declarations": global_declarations,
            "functions": functions,
            "module_body": module_body,
            "host_dependencies": sorted(
                (
                    dict(spec)
                    for spec in self._host_dependencies.values()
                ),
                key=lambda spec: spec["id"],
            ),
        }

    def _record_host_dependency(
        self,
        node: ast.AST,
    ) -> dict[str, str] | None:
        spec = resolve_host_binding(dotted_path(node))
        if spec is None:
            return None
        self._host_dependencies[spec["id"]] = spec
        return spec

    def _record_host_dependency_id(
        self,
        identifier: str,
    ) -> dict[str, str] | None:
        spec = resolve_host_binding_id(identifier)
        if spec is None:
            return None
        self._host_dependencies[spec["id"]] = spec
        return spec

    def _node(
        self,
        node_type: str,
        ast_node: ast.AST,
        **fields: Any,
    ) -> dict[str, Any]:
        payload = {"node": node_type, "span": source_span(ast_node)}
        payload.update(fields)
        return payload

    def _raise_unsupported(self, node: ast.AST, detail: str) -> None:
        span = source_span(node)
        raise IrLoweringError(detail, span["line"], span["col"])

    def _inspect_module_bindings(self, body: list[ast.stmt]) -> None:
        for node in body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self._static_import_bindings.add(alias.asname or alias.name)
                continue
            if not isinstance(node, ast.Assign):
                continue
            if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
                continue
            target = node.targets[0].id
            if not isinstance(node.value, ast.Call):
                continue
            if isinstance(node.value.func, ast.Name):
                if node.value.func.id in _STORAGE_CONSTRUCTORS:
                    self._storage_bindings[target] = node.value.func.id
                elif node.value.func.id == _EVENT_CONSTRUCTOR:
                    self._event_bindings.add(target)

    def _discover_contract_handle_factories(
        self,
        functions: list[ast.FunctionDef],
    ) -> set[str]:
        discovered: set[str] = set()
        changed = True
        while changed:
            changed = False
            for function in functions:
                if function.name in discovered:
                    continue
                if self._function_returns_contract_handle(function, discovered):
                    discovered.add(function.name)
                    changed = True
        return discovered

    def _function_returns_contract_handle(
        self,
        function: ast.FunctionDef,
        known_factories: set[str],
    ) -> bool:
        local_bindings = self._collect_local_contract_handle_bindings(
            function,
            known_factories,
        )
        returns = [
            node.value
            for node in ast.walk(function)
            if isinstance(node, ast.Return) and node.value is not None
        ]
        if not returns:
            return False
        return all(
            self._expression_is_contract_handle(
                value,
                local_bindings=local_bindings,
                known_factories=known_factories,
            )
            for value in returns
        )

    def _collect_local_contract_handle_bindings(
        self,
        function: ast.FunctionDef,
        known_factories: set[str],
    ) -> dict[str, ast.AST]:
        bindings: dict[str, ast.AST] = {}
        pending: list[tuple[str, ast.AST]] = []
        for node in ast.walk(function):
            if not isinstance(node, ast.Assign):
                continue
            if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
                continue
            pending.append((node.targets[0].id, node.value))

        changed = True
        while changed:
            changed = False
            for name, value in pending:
                if name in bindings:
                    continue
                if self._expression_is_contract_handle(
                    value,
                    local_bindings=bindings,
                    known_factories=known_factories,
                ):
                    bindings[name] = value
                    changed = True
        return bindings

    def _expression_is_contract_handle(
        self,
        node: ast.AST,
        *,
        local_bindings: dict[str, ast.AST],
        known_factories: set[str],
    ) -> bool:
        if isinstance(node, ast.Name):
            return (
                node.id in self._static_import_bindings or node.id in local_bindings
            )
        if isinstance(node, ast.Call):
            if self._is_importlib_import_call(node):
                return True
            if isinstance(node.func, ast.Name):
                return node.func.id in known_factories
        return False

    def _is_importlib_import_call(self, node: ast.Call) -> bool:
        return (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "importlib"
            and node.func.attr == "import_module"
        )

    def _contract_target_for_expression(
        self,
        node: ast.AST,
        *,
        allow_local: bool = True,
    ) -> dict[str, Any] | None:
        if isinstance(node, ast.Name):
            if node.id in self._static_import_bindings:
                return {
                    "kind": "static_import",
                    "binding": node.id,
                    "span": source_span(node),
                }
            if allow_local and node.id in self._local_contract_handles:
                return {
                    "kind": "local_handle",
                    "binding": node.id,
                    "source": self._lower_expression(
                        self._local_contract_handles[node.id]
                    ),
                    "span": source_span(node),
                }
            return None

        if isinstance(node, ast.Call):
            if self._is_importlib_import_call(node):
                return {
                    "kind": "dynamic_import",
                    "source": self._lower_expression(node),
                    "span": source_span(node),
                }
            if isinstance(node.func, ast.Name) and (
                node.func.id in self._contract_handle_factories
            ):
                return {
                    "kind": "factory_call",
                    "factory": node.func.id,
                    "source": self._lower_expression(node),
                    "span": source_span(node),
                }
        return None

    def _storage_metadata_for_name(
        self,
        node: ast.AST,
    ) -> tuple[str, str] | None:
        if not isinstance(node, ast.Name):
            return None
        storage_type = self._storage_bindings.get(node.id)
        if storage_type is None:
            return None
        return node.id, storage_type

    def _storage_subscript_metadata(
        self,
        node: ast.Subscript,
    ) -> dict[str, str] | None:
        receiver = self._storage_metadata_for_name(node.value)
        if receiver is None:
            return None
        binding, storage_type = receiver
        read_syscall_id = _STORAGE_SUBSCRIPT_READ_SYSCALLS.get(storage_type)
        write_syscall_id = _STORAGE_SUBSCRIPT_WRITE_SYSCALLS.get(storage_type)
        if read_syscall_id is None and write_syscall_id is None:
            return None
        return {
            "binding": binding,
            "storage_type": storage_type,
            "read_syscall_id": read_syscall_id,
            "write_syscall_id": write_syscall_id,
        }

    def _lower_import(self, node: ast.Import) -> list[dict[str, Any]]:
        imports = []
        for alias in node.names:
            imports.append(
                self._node(
                    "import",
                    node,
                    module=alias.name,
                    alias=alias.asname,
                )
            )
        return imports

    def _lower_global_declaration(
        self,
        node: ast.Assign,
    ) -> dict[str, Any]:
        if len(node.targets) != 1:
            self._raise_unsupported(
                node,
                "multi-target module assignments are not supported in Xian IR",
            )

        target = node.targets[0]
        if not isinstance(target, ast.Name):
            self._raise_unsupported(
                target,
                "module-level declarations must assign into a named binding",
            )

        if isinstance(node.value, ast.Call):
            callee_path = dotted_path(node.value.func)
            if callee_path in _STORAGE_CONSTRUCTORS:
                syscall_id = _STORAGE_CONSTRUCTORS[callee_path]
                self._record_host_dependency(node.value.func)
                return self._node(
                    "storage_decl",
                    node,
                    name=target.id,
                    storage_type=callee_path,
                    syscall_id=syscall_id,
                    args=[self._lower_expression(arg) for arg in node.value.args],
                    keywords=[
                        self._lower_keyword(keyword)
                        for keyword in node.value.keywords
                    ],
                )
            if callee_path == _EVENT_CONSTRUCTOR:
                self._record_host_dependency(node.value.func)
                self._event_bindings.add(target.id)
                event_name, params = self._extract_log_event_parts(node.value)
                return self._node(
                    "event_decl",
                    node,
                    name=target.id,
                    syscall_id="event.log.new",
                    event_name=event_name,
                    params=self._lower_expression(params),
                )

        return self._node(
            "binding_decl",
            node,
            name=target.id,
            value=self._lower_expression(node.value),
        )

    def _extract_log_event_parts(
        self,
        node: ast.Call,
    ) -> tuple[str, ast.AST]:
        if len(node.args) >= 2:
            event_node = node.args[0]
            params_node = node.args[1]
        else:
            values = {keyword.arg: keyword.value for keyword in node.keywords}
            event_node = values.get("event")
            params_node = values.get("params")

        if not isinstance(event_node, ast.Constant) or not isinstance(
            event_node.value, str
        ):
            self._raise_unsupported(
                node,
                "LogEvent declarations must use a constant string event name",
            )
        if params_node is None:
            self._raise_unsupported(
                node,
                "LogEvent declarations must include a params schema",
            )
        return event_node.value, params_node

    def _lower_function(self, node: ast.FunctionDef) -> dict[str, Any]:
        body = list(node.body)
        docstring = None
        if body and _is_docstring_expr(body[0]):
            docstring = body[0].value.value
            body = body[1:]

        decorator = self._lower_decorator(node)
        previous_local_contract_handles = self._local_contract_handles
        self._local_contract_handles = self._collect_local_contract_handle_bindings(
            node,
            self._contract_handle_factories,
        )
        try:
            lowered_body = [self._lower_statement(statement) for statement in body]
        finally:
            self._local_contract_handles = previous_local_contract_handles
        return self._node(
            "function",
            node,
            name=node.name,
            visibility=decorator["visibility"],
            decorator=decorator["decorator"],
            docstring=docstring,
            parameters=self._lower_parameters(node.args),
            returns=self._lower_annotation(node.returns),
            body=lowered_body,
        )

    def _lower_decorator(self, node: ast.FunctionDef) -> dict[str, Any]:
        if not node.decorator_list:
            return {"visibility": "private", "decorator": None}

        decorator = node.decorator_list[0]
        if isinstance(decorator, ast.Name):
            return {
                "visibility": decorator.id,
                "decorator": self._node(
                    "decorator",
                    decorator,
                    name=decorator.id,
                    args=[],
                    keywords=[],
                ),
            }

        if isinstance(decorator, ast.Call) and isinstance(
            decorator.func, ast.Name
        ):
            return {
                "visibility": decorator.func.id,
                "decorator": self._node(
                    "decorator",
                    decorator,
                    name=decorator.func.id,
                    args=[
                        self._lower_expression(arg) for arg in decorator.args
                    ],
                    keywords=[
                        self._lower_keyword(keyword)
                        for keyword in decorator.keywords
                    ],
                ),
            }

        self._raise_unsupported(
            decorator,
            "complex decorators are not supported in Xian IR",
        )

    def _lower_parameters(self, arguments: ast.arguments) -> list[dict[str, Any]]:
        parameters: list[dict[str, Any]] = []

        if arguments.posonlyargs:
            self._raise_unsupported(
                arguments.posonlyargs[0],
                "positional-only arguments are not supported in Xian IR",
            )

        defaults = [None] * (len(arguments.args) - len(arguments.defaults))
        defaults.extend(arguments.defaults)
        for arg, default in zip(arguments.args, defaults, strict=True):
            parameters.append(
                self._lower_parameter(
                    arg,
                    kind="positional_or_keyword",
                    default=default,
                )
            )

        for arg, default in zip(
            arguments.kwonlyargs,
            arguments.kw_defaults,
            strict=True,
        ):
            parameters.append(
                self._lower_parameter(
                    arg,
                    kind="keyword_only",
                    default=default,
                )
            )

        if arguments.vararg is not None:
            parameters.append(
                self._lower_parameter(
                    arguments.vararg,
                    kind="vararg",
                    default=None,
                )
            )
        if arguments.kwarg is not None:
            parameters.append(
                self._lower_parameter(
                    arguments.kwarg,
                    kind="kwarg",
                    default=None,
                )
            )

        return parameters

    def _lower_parameter(
        self,
        node: ast.arg,
        *,
        kind: str,
        default: ast.AST | None,
    ) -> dict[str, Any]:
        return {
            "name": node.arg,
            "kind": kind,
            "annotation": self._lower_annotation(node.annotation),
            "default": (
                self._lower_expression(default) if default is not None else None
            ),
            "span": source_span(node),
        }

    def _lower_annotation(self, node: ast.AST | None) -> str | None:
        if node is None:
            return None
        self._record_host_dependency(node)
        return ast.unparse(node)

    def _lower_keyword(self, node: ast.keyword) -> dict[str, Any]:
        if node.arg is None:
            self._raise_unsupported(
                node,
                "keyword unpacking is not supported in Xian IR",
            )
        return {
            "arg": node.arg,
            "value": self._lower_expression(node.value),
            "span": source_span(node),
        }

    def _lower_statement(self, node: ast.stmt) -> dict[str, Any]:
        if isinstance(node, ast.Assign):
            if len(node.targets) == 1 and isinstance(node.targets[0], ast.Subscript):
                storage_meta = self._storage_subscript_metadata(node.targets[0])
                if storage_meta is not None and storage_meta["write_syscall_id"] is not None:
                    self._record_host_dependency_id(storage_meta["write_syscall_id"])
                    if storage_meta["read_syscall_id"] is not None:
                        self._record_host_dependency_id(storage_meta["read_syscall_id"])
                    return self._node(
                        "storage_set",
                        node,
                        binding=storage_meta["binding"],
                        storage_type=storage_meta["storage_type"],
                        syscall_id=storage_meta["write_syscall_id"],
                        key=self._lower_subscript_slice(node.targets[0].slice),
                        value=self._lower_expression(node.value),
                    )
            return self._node(
                "assign",
                node,
                targets=[self._lower_target(target) for target in node.targets],
                value=self._lower_expression(node.value),
            )
        if isinstance(node, ast.AugAssign):
            if isinstance(node.target, ast.Subscript):
                storage_meta = self._storage_subscript_metadata(node.target)
                if storage_meta is not None and storage_meta["write_syscall_id"] is not None:
                    self._record_host_dependency_id(storage_meta["write_syscall_id"])
                    if storage_meta["read_syscall_id"] is not None:
                        self._record_host_dependency_id(storage_meta["read_syscall_id"])
                    return self._node(
                        "storage_mutate",
                        node,
                        binding=storage_meta["binding"],
                        storage_type=storage_meta["storage_type"],
                        read_syscall_id=storage_meta["read_syscall_id"],
                        write_syscall_id=storage_meta["write_syscall_id"],
                        key=self._lower_subscript_slice(node.target.slice),
                        operator=_operator_name(_BIN_OPS, node.op, node),
                        value=self._lower_expression(node.value),
                    )
            return self._node(
                "aug_assign",
                node,
                operator=_operator_name(_BIN_OPS, node.op, node),
                target=self._lower_target(node.target),
                value=self._lower_expression(node.value),
            )
        if isinstance(node, ast.Return):
            return self._node(
                "return",
                node,
                value=(
                    self._lower_expression(node.value)
                    if node.value is not None
                    else None
                ),
            )
        if isinstance(node, ast.Expr):
            return self._node(
                "expr",
                node,
                value=self._lower_expression(node.value),
            )
        if isinstance(node, ast.If):
            return self._node(
                "if",
                node,
                test=self._lower_expression(node.test),
                body=[self._lower_statement(stmt) for stmt in node.body],
                orelse=[self._lower_statement(stmt) for stmt in node.orelse],
            )
        if isinstance(node, ast.For):
            return self._node(
                "for",
                node,
                target=self._lower_target(node.target),
                iter=self._lower_expression(node.iter),
                body=[self._lower_statement(stmt) for stmt in node.body],
                orelse=[self._lower_statement(stmt) for stmt in node.orelse],
            )
        if isinstance(node, ast.Assert):
            return self._node(
                "assert",
                node,
                test=self._lower_expression(node.test),
                message=(
                    self._lower_expression(node.msg)
                    if node.msg is not None
                    else None
                ),
            )
        if isinstance(node, ast.Break):
            return self._node("break", node)
        if isinstance(node, ast.Continue):
            return self._node("continue", node)
        if isinstance(node, ast.Pass):
            return self._node("pass", node)

        self._raise_unsupported(
            node,
            f"unsupported statement node '{type(node).__name__}' in Xian IR",
        )

    def _lower_target(self, node: ast.AST) -> dict[str, Any]:
        if isinstance(node, ast.Tuple):
            return self._node(
                "tuple_target",
                node,
                elements=[self._lower_target(element) for element in node.elts],
            )
        if isinstance(node, ast.List):
            return self._node(
                "list_target",
                node,
                elements=[self._lower_target(element) for element in node.elts],
            )
        if isinstance(node, ast.Name):
            host = self._record_host_dependency(node)
            return self._node(
                "name",
                node,
                id=node.id,
                host_binding_id=(host["id"] if host is not None else None),
            )
        if isinstance(node, ast.Attribute):
            host = self._record_host_dependency(node)
            return self._node(
                "attribute",
                node,
                value=self._lower_expression(node.value),
                attr=node.attr,
                path=dotted_path(node),
                host_binding_id=(host["id"] if host is not None else None),
            )
        if isinstance(node, ast.Subscript):
            return self._node(
                "subscript",
                node,
                value=self._lower_expression(node.value),
                slice=self._lower_subscript_slice(node.slice),
            )
        self._raise_unsupported(
            node,
            f"unsupported assignment target '{type(node).__name__}' in Xian IR",
        )

    def _lower_expression(self, node: ast.AST) -> dict[str, Any]:
        if isinstance(node, ast.Name):
            host = self._record_host_dependency(node)
            return self._node(
                "name",
                node,
                id=node.id,
                host_binding_id=(host["id"] if host is not None else None),
            )
        if isinstance(node, ast.Constant):
            return self._lower_constant(node)
        if isinstance(node, ast.List):
            return self._node(
                "list",
                node,
                elements=[self._lower_expression(element) for element in node.elts],
            )
        if isinstance(node, ast.Tuple):
            return self._node(
                "tuple",
                node,
                elements=[self._lower_expression(element) for element in node.elts],
            )
        if isinstance(node, ast.Dict):
            entries = []
            for key, value in zip(node.keys, node.values, strict=True):
                if key is None:
                    self._raise_unsupported(
                        node,
                        "dict unpacking is not supported in Xian IR",
                    )
                entries.append(
                    {
                        "key": self._lower_expression(key),
                        "value": self._lower_expression(value),
                    }
                )
            return self._node("dict", node, entries=entries)
        if isinstance(node, ast.Attribute):
            host = self._record_host_dependency(node)
            return self._node(
                "attribute",
                node,
                value=self._lower_expression(node.value),
                attr=node.attr,
                path=dotted_path(node),
                host_binding_id=(host["id"] if host is not None else None),
            )
        if isinstance(node, ast.Subscript):
            storage_meta = self._storage_subscript_metadata(node)
            if storage_meta is not None and storage_meta["read_syscall_id"] is not None:
                self._record_host_dependency_id(storage_meta["read_syscall_id"])
                return self._node(
                    "storage_get",
                    node,
                    binding=storage_meta["binding"],
                    storage_type=storage_meta["storage_type"],
                    syscall_id=storage_meta["read_syscall_id"],
                    key=self._lower_subscript_slice(node.slice),
                )
            return self._node(
                "subscript",
                node,
                value=self._lower_expression(node.value),
                slice=self._lower_subscript_slice(node.slice),
            )
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                receiver = self._storage_metadata_for_name(node.func.value)
                if receiver is not None:
                    binding, storage_type = receiver
                    syscall_id = _STORAGE_METHOD_SYSCALLS.get(
                        (storage_type, node.func.attr)
                    )
                    if syscall_id is not None:
                        self._record_host_dependency_id(syscall_id)
                        return self._node(
                            "call",
                            node,
                            func=self._lower_expression(node.func),
                            args=[
                                self._lower_expression(arg)
                                for arg in node.args
                            ],
                            keywords=[
                                self._lower_keyword(keyword)
                                for keyword in node.keywords
                            ],
                            syscall_id=syscall_id,
                            receiver_binding=binding,
                            receiver_type=storage_type,
                            method=node.func.attr,
                        )

                contract_target = self._contract_target_for_expression(
                    node.func.value
                )
                if contract_target is not None:
                    self._record_host_dependency_id(_CONTRACT_EXPORT_SYSCALL)
                    return self._node(
                        "call",
                        node,
                        func=self._lower_expression(node.func),
                        args=[
                            self._lower_expression(arg) for arg in node.args
                        ],
                        keywords=[
                            self._lower_keyword(keyword)
                            for keyword in node.keywords
                        ],
                        syscall_id=_CONTRACT_EXPORT_SYSCALL,
                        contract_target=contract_target,
                        function_name=node.func.attr,
                    )
            host = self._record_host_dependency(node.func)
            event_emit = None
            if (
                host is None
                and isinstance(node.func, ast.Name)
                and node.func.id in self._event_bindings
            ):
                event_emit = resolve_host_binding("LogEvent.__call__")
                if event_emit is not None:
                    self._host_dependencies[event_emit["id"]] = event_emit
            return self._node(
                "call",
                node,
                func=self._lower_expression(node.func),
                args=[self._lower_expression(arg) for arg in node.args],
                keywords=[
                    self._lower_keyword(keyword) for keyword in node.keywords
                ],
                syscall_id=(
                    host["id"]
                    if host is not None and host["kind"] == "syscall"
                    else (
                        event_emit["id"]
                        if event_emit is not None
                        else None
                    )
                ),
                event_binding=(
                    node.func.id if event_emit is not None else None
                ),
            )
        if isinstance(node, ast.Compare):
            return self._node(
                "compare",
                node,
                left=self._lower_expression(node.left),
                operators=[
                    _operator_name(_COMPARE_OPS, operator, node)
                    for operator in node.ops
                ],
                comparators=[
                    self._lower_expression(comparator)
                    for comparator in node.comparators
                ],
            )
        if isinstance(node, ast.BoolOp):
            return self._node(
                "bool_op",
                node,
                operator=_operator_name(_BOOL_OPS, node.op, node),
                values=[self._lower_expression(value) for value in node.values],
            )
        if isinstance(node, ast.BinOp):
            return self._node(
                "bin_op",
                node,
                operator=_operator_name(_BIN_OPS, node.op, node),
                left=self._lower_expression(node.left),
                right=self._lower_expression(node.right),
            )
        if isinstance(node, ast.UnaryOp):
            return self._node(
                "unary_op",
                node,
                operator=_operator_name(_UNARY_OPS, node.op, node),
                operand=self._lower_expression(node.operand),
            )
        if isinstance(node, ast.IfExp):
            return self._node(
                "if_expr",
                node,
                test=self._lower_expression(node.test),
                body=self._lower_expression(node.body),
                orelse=self._lower_expression(node.orelse),
            )
        if isinstance(node, ast.JoinedStr):
            return self._node(
                "f_string",
                node,
                values=[self._lower_expression(value) for value in node.values],
            )
        if isinstance(node, ast.FormattedValue):
            return self._node(
                "formatted_value",
                node,
                value=self._lower_expression(node.value),
                conversion=(
                    None if node.conversion == -1 else chr(node.conversion)
                ),
                format_spec=(
                    self._lower_expression(node.format_spec)
                    if node.format_spec is not None
                    else None
                ),
            )

        self._raise_unsupported(
            node,
            f"unsupported expression node '{type(node).__name__}' in Xian IR",
        )

    def _lower_subscript_slice(self, node: ast.AST) -> dict[str, Any]:
        if isinstance(node, ast.Slice):
            return self._node(
                "slice",
                node,
                lower=(
                    self._lower_expression(node.lower)
                    if node.lower is not None
                    else None
                ),
                upper=(
                    self._lower_expression(node.upper)
                    if node.upper is not None
                    else None
                ),
                step=(
                    self._lower_expression(node.step)
                    if node.step is not None
                    else None
                ),
            )
        return self._lower_expression(node)

    def _lower_constant(self, node: ast.Constant) -> dict[str, Any]:
        value = node.value
        if value is None:
            return self._node("constant", node, value_type="none", value=None)
        if isinstance(value, bool):
            return self._node("constant", node, value_type="bool", value=value)
        if isinstance(value, int):
            if -(2**63) <= value <= 2**63 - 1:
                return self._node("constant", node, value_type="int", value=value)
            return self._node("constant", node, value_type="int", value=str(value))
        if isinstance(value, float):
            literal = ast.get_source_segment(self.source, node) or repr(value)
            return self._node(
                "constant",
                node,
                value_type="float",
                value=value,
                literal=literal,
            )
        if isinstance(value, str):
            return self._node("constant", node, value_type="str", value=value)
        self._raise_unsupported(
            node,
            f"unsupported constant '{type(value).__name__}' in Xian IR",
        )


def _is_docstring_expr(node: ast.stmt) -> bool:
    return isinstance(node, ast.Expr) and isinstance(
        getattr(node, "value", None), ast.Constant
    ) and isinstance(node.value.value, str)


def _operator_name(mapping, node, source_node: ast.AST) -> str:
    for operator_type, name in mapping.items():
        if isinstance(node, operator_type):
            return name
    span = source_span(source_node)
    raise IrLoweringError(
        f"unsupported operator '{type(node).__name__}' in Xian IR",
        span["line"],
        span["col"],
    )
