"""VM-profile compatibility checks for Xian contracts."""

from __future__ import annotations

import ast
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from contracting.compilation.linter import ErrorCode, LintError, Linter

XIAN_VM_V1_PROFILE = "xian_vm_v1"
SUPPORTED_VM_PROFILES = (XIAN_VM_V1_PROFILE,)

_TRACKED_CALL_FEATURES = {
    "all",
    "any",
    "dict",
    "len",
    "list",
    "max",
    "min",
    "range",
    "reversed",
    "sorted",
    "sum",
    "zip",
}
_DISALLOWED_CALLS = {
    "frozenset",
    "set",
}
_COMPREHENSION_NAMES = {
    ast.DictComp: "dict comprehension",
    ast.GeneratorExp: "generator expression",
    ast.ListComp: "list comprehension",
    ast.SetComp: "set comprehension",
}
XIAN_VM_V1_TRACKED_CALL_FEATURES = frozenset(_TRACKED_CALL_FEATURES)
XIAN_VM_V1_DISALLOWED_CALLS = frozenset(_DISALLOWED_CALLS)
XIAN_VM_V1_RESTRICTED_SYNTAX = frozenset(
    {
        "dict comprehension",
        "generator expression",
        "set comprehension",
        "set literal",
    }
)


def _build_error(
    code: ErrorCode,
    node: ast.AST,
    *,
    message: str,
) -> LintError:
    line = getattr(node, "lineno", 1)
    col = getattr(node, "col_offset", 0)
    end_line = getattr(node, "end_lineno", None) or line
    end_col = getattr(node, "end_col_offset", None) or col
    return LintError(
        code=code,
        message=message,
        line=line,
        col=col,
        end_line=end_line,
        end_col=end_col,
    )


@dataclass(frozen=True, slots=True)
class VmCompatibilityReport:
    profile: str
    errors: tuple[LintError, ...]
    feature_counts: dict[str, int]

    @property
    def compatible(self) -> bool:
        return not self.errors

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile": self.profile,
            "compatible": self.compatible,
            "errors": [error.to_dict() for error in self.errors],
            "feature_counts": dict(self.feature_counts),
        }


class VmCompatibilityError(Exception):
    def __init__(self, report: VmCompatibilityReport):
        self.report = report
        super().__init__([str(error) for error in report.errors])


class _VmCompatibilityVisitor(ast.NodeVisitor):
    def __init__(self, profile: str) -> None:
        self.profile = profile
        self.errors: list[LintError] = []
        self.feature_counts: Counter[str] = Counter()

    def add_syntax_error(self, node: ast.AST, *, construct: str) -> None:
        self.errors.append(
            _build_error(
                ErrorCode.E022,
                node,
                message=(
                    "Syntax "
                    f"'{construct}' is not supported by validation profile "
                    f"'{self.profile}'"
                ),
            )
        )

    def add_builtin_error(self, node: ast.AST, *, name: str) -> None:
        self.errors.append(
            _build_error(
                ErrorCode.E023,
                node,
                message=(
                    f"Built-in '{name}' is not supported by validation "
                    f"profile '{self.profile}'"
                ),
            )
        )

    def visit_While(self, node: ast.While) -> None:
        self.feature_counts["while_loops"] += 1
        self.generic_visit(node)

    def visit_Raise(self, node: ast.Raise) -> None:
        self.feature_counts["raise_statements"] += 1
        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp) -> None:
        bitwise_names = {
            ast.BitAnd: "bitand_ops",
            ast.BitOr: "bitor_ops",
            ast.BitXor: "bitxor_ops",
            ast.LShift: "lshift_ops",
            ast.RShift: "rshift_ops",
        }
        for operator_type, feature_name in bitwise_names.items():
            if isinstance(node.op, operator_type):
                self.feature_counts[feature_name] += 1
                break
        self.generic_visit(node)

    def visit_UnaryOp(self, node: ast.UnaryOp) -> None:
        if isinstance(node.op, ast.Invert):
            self.feature_counts["invert_ops"] += 1
        self.generic_visit(node)

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self.feature_counts["list_comprehensions"] += 1
        self.generic_visit(node)

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self.feature_counts["dict_comprehensions"] += 1
        self.add_syntax_error(node, construct="dict comprehension")
        self.generic_visit(node)

    def visit_SetComp(self, node: ast.SetComp) -> None:
        self.feature_counts["set_comprehensions"] += 1
        self.add_syntax_error(node, construct="set comprehension")
        self.generic_visit(node)

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        self.feature_counts["generator_expressions"] += 1
        self.add_syntax_error(node, construct="generator expression")
        self.generic_visit(node)

    def visit_List(self, node: ast.List) -> None:
        self.feature_counts["list_literals"] += 1
        self.generic_visit(node)

    def visit_Dict(self, node: ast.Dict) -> None:
        self.feature_counts["dict_literals"] += 1
        self.generic_visit(node)

    def visit_Set(self, node: ast.Set) -> None:
        self.feature_counts["set_literals"] += 1
        self.add_syntax_error(node, construct="set literal")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Name):
            name = node.func.id
            if name in _TRACKED_CALL_FEATURES:
                self.feature_counts[f"{name}_calls"] += 1
            if name in _DISALLOWED_CALLS:
                self.feature_counts[f"{name}_calls"] += 1
                self.add_builtin_error(node, name=name)
        if any(keyword.arg is None for keyword in node.keywords):
            self.feature_counts["keyword_unpack_calls"] += 1
        self.generic_visit(node)


class VmCompatibilityChecker:
    def __init__(self, linter: Linter | None = None) -> None:
        self.linter = linter or Linter()

    def check(
        self,
        source_or_tree: str | ast.AST,
        *,
        profile: str = XIAN_VM_V1_PROFILE,
    ) -> VmCompatibilityReport:
        if profile not in SUPPORTED_VM_PROFILES:
            raise ValueError(
                f"vm profile must be one of {sorted(SUPPORTED_VM_PROFILES)}"
            )

        tree, parse_errors = self._parse(source_or_tree)
        errors: list[LintError] = list(parse_errors)
        feature_counts: Counter[str] = Counter()
        if tree is None:
            return VmCompatibilityReport(
                profile=profile,
                errors=tuple(errors),
                feature_counts=dict(feature_counts),
            )

        lint_input: str | ast.AST = (
            source_or_tree if isinstance(source_or_tree, str) else tree
        )
        base_errors = self.linter.check(lint_input)
        if base_errors:
            errors.extend(base_errors)

        visitor = _VmCompatibilityVisitor(profile)
        visitor.visit(tree)
        errors.extend(visitor.errors)
        feature_counts.update(visitor.feature_counts)
        errors.sort(key=lambda error: (error.line, error.col, error.code.value))
        return VmCompatibilityReport(
            profile=profile,
            errors=tuple(errors),
            feature_counts=dict(feature_counts),
        )

    def check_raise(
        self,
        source_or_tree: str | ast.AST,
        *,
        profile: str = XIAN_VM_V1_PROFILE,
    ) -> None:
        report = self.check(source_or_tree, profile=profile)
        if not report.compatible:
            raise VmCompatibilityError(report)

    @staticmethod
    def _parse(
        source_or_tree: str | ast.AST,
    ) -> tuple[ast.AST | None, list[LintError]]:
        if isinstance(source_or_tree, ast.AST):
            return source_or_tree, []

        try:
            return ast.parse(source_or_tree), []
        except SyntaxError as exc:
            return None, [
                LintError(
                    code=ErrorCode.E020,
                    message=f"Syntax error: {exc.msg}",
                    line=exc.lineno or 1,
                    col=(exc.offset or 1) - 1,
                    end_line=exc.lineno or 1,
                    end_col=(exc.offset or 1) - 1,
                )
            ]


def iter_contract_sources(paths: list[Path]) -> list[Path]:
    discovered: list[Path] = []
    for path in paths:
        if path.is_file():
            if _is_contract_source(path):
                discovered.append(path)
            continue
        for candidate in sorted(path.rglob("*.py")):
            if _is_contract_source(candidate):
                discovered.append(candidate)
    return discovered


def _is_contract_source(path: Path) -> bool:
    name = path.name
    return name.endswith(".s.py") or (
        name.startswith("con_") and name.endswith(".py")
    )
