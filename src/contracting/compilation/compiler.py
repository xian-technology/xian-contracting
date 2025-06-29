import ast
import astor

from contracting import constants
from contracting.compilation.linter import Linter


class ContractingCompiler(ast.NodeTransformer):
    def __init__(self, module_name='__main__', linter=Linter()):
        self.module_name = module_name
        self.linter = linter
        self.lint_alerts = None
        self.constructor_visited = False
        self.private_names = set()
        self.orm_names = set()
        self.visited_names = set()  # store the method visits

    def parse(self, source: str, lint=True):
        self.constructor_visited = False

        tree = ast.parse(source)

        if lint:
            self.lint_alerts = self.linter.check(tree)
            # compilation.fix_missing_locations(tree)

        tree = self.visit(tree)

        if self.lint_alerts is not None:
            raise Exception(self.lint_alerts)

        # check all visited nodes and see if they are actually private

        # An Expr node can have a value func of compilation.Name, or compilation.
        # Attribute which you much access the value of.
        # TODO: This code branching is not ideal and should be investigated for simplicity.
        for node in self.visited_names:
            if node.id in self.private_names or node.id in self.orm_names:
                node.id = self.privatize(node.id)

        ast.fix_missing_locations(tree)

        # reset state
        self.private_names = set()
        self.orm_names = set()
        self.visited_names = set()

        return tree

    @staticmethod
    def privatize(s):
        return '{}{}'.format(constants.PRIVATE_METHOD_PREFIX, s)

    def compile(self, source: str, lint=True):
        tree = self.parse(source, lint=lint)

        compiled_code = compile(tree, '<compilation>', 'exec')

        return compiled_code

    def parse_to_code(self, source, lint=True):
        tree = self.parse(source, lint=lint)
        code = astor.to_source(tree)
        return code

    def _convert_float_to_decimal_call(self, float_value):
        """Helper method to create a decimal() call from a float value."""
        return ast.Call(
            func=ast.Name(id='decimal', ctx=ast.Load()),
            args=[ast.Str(str(float_value))],
            keywords=[]
        )

    def visit_FunctionDef(self, node):

        # Presumes all decorators are valid, as caught by linter.
        if node.decorator_list:
            # Presumes that a single decorator is passed. This is caught by the linter.
            decorator = node.decorator_list.pop()

            # change the name of the init function to '____' so it is uncallable except once
            if decorator.id == constants.INIT_DECORATOR_STRING:
                node.name = '____'

            elif decorator.id == constants.EXPORT_DECORATOR_STRING:
                # Transform @export decorators to @__export(contract_name) decorators
                decorator.id = '{}{}'.format('__', constants.EXPORT_DECORATOR_STRING)

                new_node = ast.Call(
                    func=decorator,
                    args=[ast.Str(s=self.module_name)],
                    keywords=[]
                )

                node.decorator_list.append(new_node)

        else:
            self.private_names.add(node.name)
            node.name = self.privatize(node.name)

        # Handle float literals in function parameter defaults
        if node.args.defaults:
            new_defaults = []
            for default in node.args.defaults:
                # Handle both ast.Num (Python < 3.8) and ast.Constant (Python 3.8+)
                if isinstance(default, ast.Num) and isinstance(default.n, float):
                    new_defaults.append(self._convert_float_to_decimal_call(default.n))
                elif isinstance(default, ast.Constant) and isinstance(default.value, float):
                    new_defaults.append(self._convert_float_to_decimal_call(default.value))
                else:
                    new_defaults.append(default)
            node.args.defaults = new_defaults

        # Handle float literals in keyword-only defaults (Python 3+)
        if hasattr(node.args, 'kw_defaults') and node.args.kw_defaults:
            new_kw_defaults = []
            for default in node.args.kw_defaults:
                if default is None:
                    new_kw_defaults.append(default)
                elif isinstance(default, ast.Num) and isinstance(default.n, float):
                    new_kw_defaults.append(self._convert_float_to_decimal_call(default.n))
                elif isinstance(default, ast.Constant) and isinstance(default.value, float):
                    new_kw_defaults.append(self._convert_float_to_decimal_call(default.value))
                else:
                    new_kw_defaults.append(default)
            node.args.kw_defaults = new_kw_defaults

        self.generic_visit(node)

        return node

    def visit_Assign(self, node):
        if (isinstance(node.value, ast.Call) and not
            isinstance(node.value.func, ast.Attribute) and
            node.value.func.id in constants.ORM_CLASS_NAMES):

            node.value.keywords.append(ast.keyword('contract', ast.Str(self.module_name)))
            node.value.keywords.append(ast.keyword('name', ast.Str(node.targets[0].id)))
            self.orm_names.add(node.targets[0].id)

        self.generic_visit(node)

        return node

    def visit_Name(self, node):
        self.visited_names.add(node)
        return node

    def visit_Expr(self, node):
        self.generic_visit(node)
        return node

    def visit_Num(self, node):
        if isinstance(node.n, float):
            return ast.Call(func=ast.Name(id='decimal', ctx=ast.Load()),
                            args=[ast.Str(str(node.n))], keywords=[])
        return node

    def visit_Constant(self, node):
        # Python 3.8+ uses ast.Constant instead of ast.Num for literals
        if isinstance(node.value, float):
            return ast.Call(func=ast.Name(id='decimal', ctx=ast.Load()),
                            args=[ast.Str(str(node.value))], keywords=[])
        return node