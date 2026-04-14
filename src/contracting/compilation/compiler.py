import ast
import json

from contracting import constants
from contracting.compilation.linter import Linter, LintingError
from contracting.compilation.lowering import XianIrLowerer
from contracting.compilation.vm import (
    XIAN_VM_V1_PROFILE,
    VmCompatibilityChecker,
)


class ContractingCompiler(ast.NodeTransformer):
    def __init__(self, module_name="__main__", linter=None, vm_checker=None):
        self.module_name = module_name
        self.linter = linter or Linter()
        self.vm_checker = vm_checker or VmCompatibilityChecker()
        self.lint_alerts = None
        self.source = None
        self.constructor_visited = False
        self.private_names = set()
        self.orm_names = set()
        self.visited_names = set()  # store the method visits

    def parse(self, source: str, lint=True, vm_profile: str | None = None):
        self.constructor_visited = False
        self.source = source

        tree = ast.parse(source)

        if lint:
            self.lint_alerts = self.linter.check(tree)
        else:
            self.lint_alerts = None
        vm_report = None
        if vm_profile is not None:
            vm_report = self.vm_checker.check(tree, profile=vm_profile)

        tree = self.visit(tree)

        if self.lint_alerts is not None:
            raise LintingError(self.lint_alerts)
        if vm_report is not None and not vm_report.compatible:
            from contracting.compilation.vm import VmCompatibilityError

            raise VmCompatibilityError(vm_report)

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
        self.lint_alerts = None
        self.source = None

        return tree

    @staticmethod
    def privatize(s):
        return "{}{}".format(constants.PRIVATE_METHOD_PREFIX, s)

    def compile(self, source: str, lint=True, vm_profile: str | None = None):
        tree = self.parse(source, lint=lint, vm_profile=vm_profile)

        compiled_code = compile(tree, "<compilation>", "exec")

        return compiled_code

    def normalize_source(
        self, source: str, lint=True, vm_profile: str | None = None
    ):
        tree = ast.parse(source)

        if lint:
            lint_alerts = self.linter.check(tree)
            if lint_alerts is not None:
                raise LintingError(lint_alerts)
        if vm_profile is not None:
            self.vm_checker.check_raise(tree, profile=vm_profile)

        ast.fix_missing_locations(tree)
        return ast.unparse(tree)

    def parse_to_code(self, source, lint=True, vm_profile: str | None = None):
        tree = self.parse(source, lint=lint, vm_profile=vm_profile)
        return ast.unparse(tree)

    def check_vm_compatibility(self, source: str, profile: str):
        return self.vm_checker.check(source, profile=profile)

    def lower_to_ir(
        self,
        source: str,
        lint=True,
        vm_profile: str | None = XIAN_VM_V1_PROFILE,
    ):
        tree = ast.parse(source)

        if lint:
            lint_alerts = self.linter.check(source)
            if lint_alerts is not None:
                raise LintingError(lint_alerts)

        selected_profile = vm_profile or XIAN_VM_V1_PROFILE
        self.vm_checker.check_raise(source, profile=selected_profile)

        lowerer = XianIrLowerer(
            module_name=self.module_name,
            profile=selected_profile,
        )
        return lowerer.lower(tree, source=source)

    def lower_to_ir_json(
        self,
        source: str,
        lint=True,
        vm_profile: str | None = XIAN_VM_V1_PROFILE,
        *,
        indent: int | None = 2,
        sort_keys: bool = True,
    ) -> str:
        return json.dumps(
            self.lower_to_ir(
                source,
                lint=lint,
                vm_profile=vm_profile,
            ),
            indent=indent,
            sort_keys=sort_keys,
        )

    def visit_FunctionDef(self, node):

        # Presumes all decorators are valid, as caught by linter.
        if node.decorator_list:
            # Presumes that a single decorator is passed. This is caught by the linter.
            decorator = node.decorator_list.pop()
            decorator_name = None
            decorator_keywords = []

            if isinstance(decorator, ast.Name):
                decorator_name = decorator.id
            elif isinstance(decorator, ast.Call) and isinstance(
                decorator.func, ast.Name
            ):
                decorator_name = decorator.func.id
                decorator_keywords = decorator.keywords

            # change the name of the init function to '____' so it is uncallable except once
            if decorator_name == constants.INIT_DECORATOR_STRING:
                node.name = "____"

            elif decorator_name == constants.EXPORT_DECORATOR_STRING:
                # Transform @export decorators to @__export(contract_name) decorators
                new_node = ast.Call(
                    func=ast.Name(
                        id="{}{}".format(
                            "__", constants.EXPORT_DECORATOR_STRING
                        ),
                        ctx=ast.Load(),
                    ),
                    args=[ast.Constant(value=self.module_name)],
                    keywords=decorator_keywords,
                )

                node.decorator_list.append(new_node)

        else:
            self.private_names.add(node.name)
            node.name = self.privatize(node.name)

        self.generic_visit(node)

        return node

    def visit_Assign(self, node):
        if (
            isinstance(node.value, ast.Call)
            and not isinstance(node.value.func, ast.Attribute)
            and node.value.func.id in constants.ORM_CLASS_NAMES
        ):
            node.value.keywords.append(
                ast.keyword(
                    arg="contract",
                    value=ast.Constant(value=self.module_name),
                )
            )
            node.value.keywords.append(
                ast.keyword(
                    arg="name",
                    value=ast.Constant(value=node.targets[0].id),
                )
            )
            self.orm_names.add(node.targets[0].id)

        self.generic_visit(node)

        return node

    def visit_Name(self, node):
        self.visited_names.add(node)
        return node

    def visit_Expr(self, node):
        self.generic_visit(node)
        return node

    def visit_Constant(self, node):
        if isinstance(node.value, float):
            literal = ast.get_source_segment(self.source, node) or str(
                node.value
            )
            return ast.Call(
                func=ast.Name(id="decimal", ctx=ast.Load()),
                args=[ast.Constant(value=literal)],
                keywords=[],
            )
        return node
