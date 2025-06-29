import ast
import astor
from typing import Set

from contracting import constants
from contracting.compilation.linter import Linter


class ContractingCompiler(ast.NodeTransformer):
    def __init__(self, module_name='__main__', linter=Linter()):
        self.module_name = module_name
        self.linter = linter
        self.lint_alerts = None
        self.constructor_visited = False
        self.private_names: Set[str] = set()
        self.orm_names: Set[str] = set()

    def parse(self, source: str, lint=True):
        self.constructor_visited = False
        self.private_names.clear()
        self.orm_names.clear()

        tree = ast.parse(source)

        if lint:
            self.lint_alerts = self.linter.check(tree)

        # Two-pass approach: collect names first, then transform
        self._collect_names(tree)
        tree = self.visit(tree)

        if self.lint_alerts is not None:
            raise Exception(self.lint_alerts)

        ast.fix_missing_locations(tree)
        return tree

    def _collect_names(self, tree: ast.AST) -> None:
        """First pass: collect private and ORM names without transformation."""

        class NameCollector(ast.NodeVisitor):
            def __init__(self, compiler):
                self.compiler = compiler

            def visit_FunctionDef(self, node):
                if not node.decorator_list:
                    self.compiler.private_names.add(node.name)
                self.generic_visit(node)

            def visit_Assign(self, node):
                # Match original logic exactly: Call with non-Attribute func
                if (isinstance(node.value, ast.Call) and not
                isinstance(node.value.func, ast.Attribute) and
                        hasattr(node.value.func, 'id') and
                        node.value.func.id in constants.ORM_CLASS_NAMES):

                    # Handle multiple assignment targets like original
                    try:
                        self.compiler.orm_names.add(node.targets[0].id)
                    except (IndexError, AttributeError):
                        pass  # Skip if target structure is unexpected
                self.generic_visit(node)

        NameCollector(self).visit(tree)

    @staticmethod
    def privatize(s: str) -> str:
        return f'{constants.PRIVATE_METHOD_PREFIX}{s}'

    def compile(self, source: str, lint=True):
        tree = self.parse(source, lint=lint)
        return compile(tree, '<compilation>', 'exec')

    def parse_to_code(self, source: str, lint=True) -> str:
        tree = self.parse(source, lint=lint)
        return astor.to_source(tree)

    def _create_decimal_call(self, float_value: float) -> ast.Call:
        """Create decimal() call from float value."""
        return ast.Call(
            func=ast.Name(id='decimal', ctx=ast.Load()),
            args=[ast.Str(str(float_value))],
            keywords=[]
        )

    def _convert_float_defaults(self, defaults: list[ast.expr]) -> list[ast.expr]:
        """Convert float literals in parameter defaults to decimal calls."""
        return [
            self._create_decimal_call(
                default.n if isinstance(default, ast.Num) else default.value
            ) if (
                    (isinstance(default, ast.Num) and isinstance(default.n, float)) or
                    (isinstance(default, ast.Constant) and isinstance(default.value, float))
            ) else default
            for default in defaults
        ]

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        # Handle decorators
        if node.decorator_list:
            decorator = node.decorator_list.pop()

            if decorator.id == constants.INIT_DECORATOR_STRING:
                node.name = '____'
            elif decorator.id == constants.EXPORT_DECORATOR_STRING:
                decorator.id = f'__{constants.EXPORT_DECORATOR_STRING}'
                node.decorator_list.append(ast.Call(
                    func=decorator,
                    args=[ast.Str(s=self.module_name)],
                    keywords=[]
                ))
        else:
            # Apply privatization immediately (name already collected)
            node.name = self.privatize(node.name)

        # Convert float defaults
        if node.args.defaults:
            node.args.defaults = self._convert_float_defaults(node.args.defaults)

        if hasattr(node.args, 'kw_defaults') and node.args.kw_defaults:
            node.args.kw_defaults = [
                self._create_decimal_call(
                    default.n if isinstance(default, ast.Num) else default.value
                ) if default is not None and (
                        (isinstance(default, ast.Num) and isinstance(default.n, float)) or
                        (isinstance(default, ast.Constant) and isinstance(default.value, float))
                ) else default
                for default in node.args.kw_defaults
            ]

        self.generic_visit(node)
        return node

    def visit_Assign(self, node: ast.Assign) -> ast.Assign:
        # Match original logic exactly: Call with non-Attribute func
        if (isinstance(node.value, ast.Call) and not
        isinstance(node.value.func, ast.Attribute) and
                hasattr(node.value.func, 'id') and
                node.value.func.id in constants.ORM_CLASS_NAMES):
            node.value.keywords.extend([
                ast.keyword('contract', ast.Str(self.module_name)),
                ast.keyword('name', ast.Str(node.targets[0].id))
            ])

        self.generic_visit(node)
        return node

    def visit_Name(self, node: ast.Name) -> ast.Name:
        # Apply privatization immediately using pre-collected names
        if node.id in self.private_names or node.id in self.orm_names:
            node.id = self.privatize(node.id)
        return node

    def visit_Num(self, node: ast.Num) -> ast.Call | ast.Num:
        if isinstance(node.n, float):
            return self._create_decimal_call(node.n)
        return node

    def visit_Constant(self, node: ast.Constant) -> ast.Call | ast.Constant:
        if isinstance(node.value, float):
            return self._create_decimal_call(node.value)
        return node