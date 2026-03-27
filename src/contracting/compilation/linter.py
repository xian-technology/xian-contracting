"""Smart contract linter for Xian."""

from __future__ import annotations

import ast
import sys
from dataclasses import dataclass
from enum import Enum
from typing import Any

from contracting import constants
from contracting.compilation.whitelists import (
    ALLOWED_ANNOTATION_TYPES,
    ILLEGAL_AST_TYPES,
    ILLEGAL_BUILTINS,
)


class ErrorCode(str, Enum):
    E001 = "E001"
    E002 = "E002"
    E003 = "E003"
    E004 = "E004"
    E005 = "E005"
    E006 = "E006"
    E007 = "E007"
    E008 = "E008"
    E009 = "E009"
    E010 = "E010"
    E011 = "E011"
    E012 = "E012"
    E013 = "E013"
    E014 = "E014"
    E015 = "E015"
    E016 = "E016"
    E017 = "E017"
    E018 = "E018"
    E019 = "E019"
    E020 = "E020"
    E021 = "E021"


_MESSAGES = {
    ErrorCode.E001: "Illegal syntax: {detail}",
    ErrorCode.E002: "Name '{name}' must not start or end with underscore",
    ErrorCode.E003: "Imports are not allowed inside functions",
    ErrorCode.E004: "'from ... import' is not allowed; use 'import' instead",
    ErrorCode.E005: "Cannot import stdlib module '{name}'",
    ErrorCode.E006: "Class definitions are not allowed",
    ErrorCode.E007: "Async functions are not allowed",
    ErrorCode.E008: "Invalid decorator '{name}'; must be 'export' or 'construct'",
    ErrorCode.E009: "Multiple @construct decorators found; only one allowed",
    ErrorCode.E010: "Functions may have at most one decorator",
    ErrorCode.E011: "Cannot pass '{kwarg}' to {orm}; it is set automatically",
    ErrorCode.E012: "Tuple unpacking on ORM assignment is not allowed",
    ErrorCode.E013: "Contract must have at least one @export function",
    ErrorCode.E014: "'{name}' is not allowed in smart contracts",
    ErrorCode.E015: "Argument '{name}' shadows ORM variable defined at module level",
    ErrorCode.E016: "Type annotation '{annotation}' is not allowed; use one of: {allowed}",
    ErrorCode.E017: "All @export function arguments must have type annotations",
    ErrorCode.E018: "Return type annotation '{annotation}' is not allowed; use one of: {allowed}",
    ErrorCode.E019: "Nested function definitions are not allowed",
    ErrorCode.E020: "Syntax error: {detail}",
    ErrorCode.E021: "Invalid decorator arguments for '{name}': {detail}",
}


@dataclass(frozen=True, slots=True)
class LintError:
    code: ErrorCode
    message: str
    line: int
    col: int
    end_line: int
    end_col: int

    def __str__(self) -> str:
        return f"{self.line}:{self.col}: {self.code.value} {self.message}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code.value,
            "message": self.message,
            "line": self.line,
            "col": self.col,
            "end_line": self.end_line,
            "end_col": self.end_col,
        }


class LintingError(Exception):
    def __init__(self, errors: list[LintError]):
        self.errors = tuple(errors)
        super().__init__([str(error) for error in errors])


def _make_error(
    code: ErrorCode,
    node: ast.AST | None = None,
    *,
    line: int = 1,
    col: int = 0,
    end_line: int | None = None,
    end_col: int | None = None,
    **kwargs: Any,
) -> LintError:
    if node is not None:
        line = getattr(node, "lineno", line)
        col = getattr(node, "col_offset", col)
        end_line = getattr(node, "end_lineno", None) or line
        end_col = getattr(node, "end_col_offset", None) or col
    else:
        end_line = end_line or line
        end_col = end_col or col

    message = _MESSAGES[code].format(**kwargs) if kwargs else _MESSAGES[code]
    return LintError(
        code=code,
        message=message,
        line=line,
        col=col,
        end_line=end_line,
        end_col=end_col,
    )


class _LintVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.errors: list[LintError] = []
        self.orm_names: set[str] = set()
        self.export_args: list[tuple[str, ast.AST]] = []
        self.arg_annotations: list[tuple[str | None, ast.AST]] = []
        self.return_annotations: list[tuple[str | None, ast.AST]] = []
        self.has_export = False
        self.has_construct = False
        self.in_function = False

    def add(self, code: ErrorCode, node: ast.AST | None = None, **kwargs: Any):
        self.errors.append(_make_error(code, node, **kwargs))

    def visit_Name(self, node: ast.Name) -> None:
        self._check_name(node.id, node)
        ast.NodeVisitor.generic_visit(self, node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        self._check_name(node.attr, node)
        ast.NodeVisitor.generic_visit(self, node)

    def _check_name(self, name: str, node: ast.AST) -> None:
        if name == "rt":
            self.add(ErrorCode.E014, node, name="rt")
        elif name.startswith("_") or name.endswith("_"):
            self.add(ErrorCode.E002, node, name=name)

    def visit_Import(self, node: ast.Import) -> None:
        if self.in_function:
            self.add(ErrorCode.E003, node)
            return

        for alias in node.names:
            if (
                alias.name in sys.stdlib_module_names
                or alias.name in sys.builtin_module_names
            ):
                self.add(ErrorCode.E005, node, name=alias.name)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        self.add(ErrorCode.E004, node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.add(ErrorCode.E006, node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.add(ErrorCode.E007, node)
        ast.NodeVisitor.generic_visit(self, node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        if self.in_function:
            self.add(ErrorCode.E019, node)
            return

        decorators = node.decorator_list
        if len(decorators) > 1:
            self.add(ErrorCode.E010, node)

        decorator_name = None
        if decorators:
            decorator = decorators[0]
            if isinstance(decorator, ast.Name):
                decorator_name = decorator.id
            elif isinstance(decorator, ast.Call) and isinstance(
                decorator.func, ast.Name
            ):
                decorator_name = decorator.func.id
            if decorator_name not in constants.VALID_DECORATORS:
                self.add(
                    ErrorCode.E008,
                    decorator,
                    name=decorator_name or "<complex>",
                )
                decorator_name = None
            elif isinstance(decorator, ast.Call):
                self._check_decorator_args(decorator, decorator_name)

        if decorator_name == constants.INIT_DECORATOR_STRING:
            if self.has_construct:
                self.add(ErrorCode.E009, node)
            self.has_construct = True

        if decorator_name == constants.EXPORT_DECORATOR_STRING:
            self.has_export = True
            self._check_export_args(node)

        self.in_function = True
        ast.NodeVisitor.generic_visit(self, node)
        self.in_function = False

    def _check_decorator_args(
        self, decorator: ast.Call, decorator_name: str
    ) -> None:
        if decorator_name == constants.INIT_DECORATOR_STRING:
            if decorator.args or decorator.keywords:
                self.add(
                    ErrorCode.E021,
                    decorator,
                    name=decorator_name,
                    detail="@construct does not accept arguments",
                )
            return

        if decorator_name != constants.EXPORT_DECORATOR_STRING:
            return

        if decorator.args:
            self.add(
                ErrorCode.E021,
                decorator,
                name=decorator_name,
                detail="@export accepts keyword arguments only",
            )

        for keyword in decorator.keywords:
            if keyword.arg != "typecheck":
                self.add(
                    ErrorCode.E021,
                    keyword,
                    name=decorator_name,
                    detail="only 'typecheck' is supported",
                )
                continue

            if not (
                isinstance(keyword.value, ast.Constant)
                and isinstance(keyword.value.value, bool)
            ):
                self.add(
                    ErrorCode.E021,
                    keyword.value,
                    name=decorator_name,
                    detail="'typecheck' must be True or False",
                )

    def _check_export_args(self, node: ast.FunctionDef) -> None:
        for arg in node.args.args:
            self.export_args.append((arg.arg, arg))
            if arg.annotation is None:
                self.arg_annotations.append((None, arg))
            else:
                self.arg_annotations.append(
                    (self._resolve_annotation(arg.annotation), arg)
                )

        if node.returns is not None:
            self.return_annotations.append(
                (self._resolve_annotation(node.returns), node)
            )

    @staticmethod
    def _resolve_annotation(node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            return f"{node.value.id}.{node.attr}"
        if isinstance(node, ast.Subscript):
            base = _LintVisitor._resolve_annotation(node.value)
            if base is None:
                return None
            return f"{base}[{ast.unparse(node.slice).replace(' ', '')}]"
        if isinstance(node, ast.Constant):
            return str(node.value)
        return None

    @staticmethod
    def _annotation_base(annotation: str) -> str:
        return annotation.split("[", 1)[0]

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Call) and isinstance(
            node.value.func, ast.Name
        ):
            func_name = node.value.func.id
            if func_name in constants.ORM_CLASS_NAMES:
                self._check_orm_assign(node, func_name)
        elif (
            isinstance(node.value, ast.Name)
            and node.value.id in constants.ORM_CLASS_NAMES
        ):
            self.add(ErrorCode.E014, node, name=node.value.id)

        ast.NodeVisitor.generic_visit(self, node)

    def _check_orm_assign(self, node: ast.Assign, orm_name: str) -> None:
        for target in node.targets:
            if isinstance(target, ast.Tuple):
                self.add(ErrorCode.E012, node)
                return

        if orm_name in {"Variable", "Hash", "LogEvent"}:
            for keyword in node.value.keywords:
                if keyword.arg in {"contract", "name"}:
                    self.add(
                        ErrorCode.E011,
                        keyword,
                        kwarg=keyword.arg,
                        orm=orm_name,
                    )

        if node.targets and isinstance(node.targets[0], ast.Name):
            self.orm_names.add(node.targets[0].id)

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Name) and node.func.id in ILLEGAL_BUILTINS:
            self.add(ErrorCode.E014, node, name=node.func.id)
        ast.NodeVisitor.generic_visit(self, node)

    def generic_visit(self, node: ast.AST) -> None:
        if type(node) in ILLEGAL_AST_TYPES:
            self.add(ErrorCode.E001, node, detail=type(node).__name__)
        ast.NodeVisitor.generic_visit(self, node)


class Linter:
    def check(self, source_or_tree: str | ast.AST) -> list[LintError] | None:
        tree: ast.AST
        if isinstance(source_or_tree, ast.AST):
            tree = source_or_tree
        else:
            try:
                tree = ast.parse(source_or_tree)
            except SyntaxError as exc:
                return [
                    _make_error(
                        ErrorCode.E020,
                        line=exc.lineno or 1,
                        col=(exc.offset or 1) - 1,
                        detail=exc.msg,
                    )
                ]

        visitor = _LintVisitor()
        visitor.visit(tree)
        self._final_checks(visitor, tree)

        if not visitor.errors:
            return None

        visitor.errors.sort(key=lambda error: (error.line, error.col))
        return visitor.errors

    def check_raise(self, source_or_tree: str | ast.AST) -> None:
        errors = self.check(source_or_tree)
        if errors:
            raise LintingError(errors)

    def _final_checks(self, visitor: _LintVisitor, tree: ast.AST) -> None:
        if not visitor.has_export:
            first_func = next(
                (
                    node
                    for node in ast.walk(tree)
                    if isinstance(node, ast.FunctionDef)
                ),
                None,
            )
            visitor.add(ErrorCode.E013, first_func)

        for name, arg_node in visitor.export_args:
            if name in visitor.orm_names:
                visitor.add(ErrorCode.E015, arg_node, name=name)

        allowed = ", ".join(sorted(ALLOWED_ANNOTATION_TYPES))
        for annotation_name, arg_node in visitor.arg_annotations:
            if annotation_name is None:
                visitor.add(ErrorCode.E017, arg_node)
            elif (
                visitor._annotation_base(annotation_name)
                not in ALLOWED_ANNOTATION_TYPES
            ):
                visitor.add(
                    ErrorCode.E016,
                    arg_node,
                    annotation=annotation_name,
                    allowed=allowed,
                )

        for annotation_name, func_node in visitor.return_annotations:
            if (
                annotation_name is not None
                and visitor._annotation_base(annotation_name)
                not in ALLOWED_ANNOTATION_TYPES
            ):
                visitor.add(
                    ErrorCode.E018,
                    func_node,
                    annotation=annotation_name,
                    allowed=allowed,
                )
