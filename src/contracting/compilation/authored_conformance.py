"""Authored-contract coverage audit against the conformance matrix."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from contracting.compilation.conformance import (
    CONFORMANCE_BUILTIN_EXCLUSIONS,
    CONFORMANCE_ENV_EXCLUSIONS,
    CONTRACT_LANGUAGE_MANIFEST,
    covered_conformance_surface,
)
from contracting.compilation.python_compatibility import (
    iter_authored_contract_sources,
    module_name_from_path,
)


AUTHORED_CONFORMANCE_FEATURE_EXCLUSIONS: dict[str, str] = {}
_EXACT_STRING_METHOD_FEATURES = {
    "endswith": "methods.string.endswith",
    "find": "methods.string.find",
    "isalnum": "methods.string.isalnum",
    "join": "methods.string.join",
    "lower": "methods.string.lower",
    "replace": "methods.string.replace",
    "split": "methods.string.split",
    "startswith": "methods.string.startswith",
    "strip": "methods.string.strip",
    "upper": "methods.string.upper",
}
_EXACT_LIST_METHOD_FEATURES = {
    "append": "methods.list.append",
    "clear": "methods.list.clear",
    "copy": "methods.list.copy",
    "count": "methods.list.count",
    "extend": "methods.list.extend",
    "index": "methods.list.index",
    "insert": "methods.list.insert",
    "remove": "methods.list.remove",
}


def _root_name(node: ast.AST) -> str | None:
    current = node
    while isinstance(current, ast.Attribute):
        current = current.value
    if isinstance(current, ast.Name):
        return current.id
    return None


class _AuthoredConformanceVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.used_builtins: set[str] = set()
        self.used_env: set[str] = set()
        self.used_features: set[str] = set()
        self._allowed_builtins = set(
            CONTRACT_LANGUAGE_MANIFEST["python_contracting"]["allowed_builtins"]
        )
        self._public_env = set(
            CONTRACT_LANGUAGE_MANIFEST["python_contracting"]["public_env_surface"]
        )

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Load) and node.id in self._public_env:
            self.used_env.add(node.id)
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        self.used_features.add("imports.static")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        self.used_features.add("imports.static")
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Name) and decorator.id == "construct":
                self.used_features.add("decorators.construct")
            elif isinstance(decorator, ast.Name) and decorator.id == "export":
                self.used_features.add("decorators.export")
            elif isinstance(decorator, ast.Call):
                if isinstance(decorator.func, ast.Name) and decorator.func.id == "export":
                    self.used_features.add("decorators.export")
                    if any(
                        keyword.arg == "typecheck"
                        and isinstance(keyword.value, ast.Constant)
                        and keyword.value.value is True
                        for keyword in decorator.keywords
                    ):
                        self.used_features.add("decorators.export.typecheck")
        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert) -> None:
        self.used_features.add("syntax.assert")
        self.generic_visit(node)

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self.used_features.add("syntax.dict_comp")
        self.generic_visit(node)

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self.used_features.add("syntax.list_comp")
        self.generic_visit(node)

    def visit_Raise(self, node: ast.Raise) -> None:
        self.used_features.add("syntax.raise")
        self.generic_visit(node)

    def visit_While(self, node: ast.While) -> None:
        self.used_features.add("syntax.while")
        if node.orelse:
            self.used_features.add("syntax.loop_else")
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        if node.orelse:
            self.used_features.add("syntax.loop_else")
        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp) -> None:
        if isinstance(node.op, ast.BitAnd | ast.BitOr | ast.BitXor | ast.LShift | ast.RShift):
            self.used_features.add("syntax.bitwise")
        self.generic_visit(node)

    def visit_UnaryOp(self, node: ast.UnaryOp) -> None:
        if isinstance(node.op, ast.Invert):
            self.used_features.add("syntax.bitwise")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if any(keyword.arg is None for keyword in node.keywords):
            self.used_features.add("syntax.keyword_unpack")

        if isinstance(node.func, ast.Name):
            name = node.func.id
            if name in self._allowed_builtins:
                self.used_builtins.add(name)
            if name in self._public_env:
                self.used_env.add(name)
            if name == "Variable":
                self.used_features.add("storage.variable")
            elif name == "Hash":
                self.used_features.add("storage.hash")
            elif name in {"ForeignHash", "ForeignVariable"}:
                self.used_features.add("storage.foreign")
            elif name in {"LogEvent", "indexed"}:
                self.used_features.add("events.log")
            elif name in {"set", "frozenset"}:
                self.used_features.add("values.sets")
            elif name in {"bytes", "bytearray"}:
                self.used_features.add("values.binary")
            elif name in {"map", "filter"}:
                self.used_features.add("helpers.higher_order")
        else:
            root = _root_name(node.func)
            if root in self._public_env:
                self.used_env.add(root)
            if root == "ctx":
                self.used_features.add("context.ctx")
            elif root == "importlib":
                self.used_features.add("modules.importlib")
            elif root == "Contract":
                self.used_features.add("modules.contract")
            elif root == "decimal":
                self.used_features.add("modules.decimal")
            elif root == "datetime":
                self.used_features.add("modules.datetime")
            elif root == "hashlib":
                self.used_features.add("modules.hashlib")
            elif root == "crypto":
                self.used_features.add("modules.crypto")
            elif root == "random":
                self.used_features.add("modules.random")
            elif root == "zk":
                self.used_features.add("modules.zk")

            if isinstance(node.func, ast.Attribute):
                if exact := _EXACT_STRING_METHOD_FEATURES.get(node.func.attr):
                    self.used_features.add("methods.string")
                    self.used_features.add(exact)
                elif exact := _EXACT_LIST_METHOD_FEATURES.get(node.func.attr):
                    self.used_features.add("methods.collection")
                    self.used_features.add(exact)

        self.generic_visit(node)


@dataclass(frozen=True, slots=True)
class AuthoredConformanceReport:
    path: str
    module_name: str
    used_builtins: tuple[str, ...]
    used_env: tuple[str, ...]
    used_features: tuple[str, ...]
    missing_builtins: tuple[str, ...]
    missing_env: tuple[str, ...]
    missing_features: tuple[str, ...]

    @property
    def compatible(self) -> bool:
        return not (
            self.missing_builtins or self.missing_env or self.missing_features
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "module_name": self.module_name,
            "compatible": self.compatible,
            "used_builtins": list(self.used_builtins),
            "used_env": list(self.used_env),
            "used_features": list(self.used_features),
            "missing_builtins": list(self.missing_builtins),
            "missing_env": list(self.missing_env),
            "missing_features": list(self.missing_features),
        }


class AuthoredConformanceAuditor:
    def __init__(self) -> None:
        covered = covered_conformance_surface()
        self._covered_builtins = covered["builtins"]
        self._covered_env = covered["env"]
        self._covered_features = covered["features"]

    def check(
        self,
        source: str,
        *,
        module_name: str,
        path: str = "<memory>",
    ) -> AuthoredConformanceReport:
        tree = ast.parse(source)
        visitor = _AuthoredConformanceVisitor()
        visitor.visit(tree)

        missing_builtins = sorted(
            value
            for value in visitor.used_builtins
            if value not in self._covered_builtins
            and value not in CONFORMANCE_BUILTIN_EXCLUSIONS
        )
        missing_env = sorted(
            value
            for value in visitor.used_env
            if value not in self._covered_env
            and value not in CONFORMANCE_ENV_EXCLUSIONS
        )
        missing_features = sorted(
            value
            for value in visitor.used_features
            if value not in self._covered_features
            and value not in AUTHORED_CONFORMANCE_FEATURE_EXCLUSIONS
        )

        return AuthoredConformanceReport(
            path=path,
            module_name=module_name,
            used_builtins=tuple(sorted(visitor.used_builtins)),
            used_env=tuple(sorted(visitor.used_env)),
            used_features=tuple(sorted(visitor.used_features)),
            missing_builtins=tuple(missing_builtins),
            missing_env=tuple(missing_env),
            missing_features=tuple(missing_features),
        )

    def audit_paths(self, paths: list[Path]) -> list[AuthoredConformanceReport]:
        reports: list[AuthoredConformanceReport] = []
        for path in iter_authored_contract_sources(paths):
            reports.append(
                self.check(
                    path.read_text(encoding="utf-8"),
                    module_name=module_name_from_path(path),
                    path=str(path),
                )
            )
        return reports
