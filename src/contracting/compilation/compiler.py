import ast
import json

from contracting import constants
from contracting.compilation.attribute_guards import guard_attribute_targets
from contracting.compilation.linter import Linter, LintingError
from contracting.compilation.lowering import XianIrLowerer
from contracting.compilation.vm import (
    XIAN_VM_V2_PROFILE,
    VmCompatibilityChecker,
    VmCompatibilityError,
)


def _orm_declaration_call(call, module_name, storage_name, helper_name="__xian_orm_declaration__"):
    return ast.copy_location(
        ast.Call(
            func=ast.Name(id=helper_name, ctx=ast.Load()),
            args=[
                call.func,
                ast.Constant(value=module_name),
                ast.Constant(value=storage_name),
                *call.args,
            ],
            keywords=call.keywords,
        ),
        call,
    )


def _legacy_orm_assignment(node):
    if not isinstance(node, ast.Assign) or len(node.targets) != 1:
        return False
    if not isinstance(node.targets[0], ast.Name) or not isinstance(node.value, ast.Call):
        return False
    return isinstance(node.value.func, ast.Name) and node.value.func.id in constants.ORM_CLASS_NAMES


def _legacy_orm_metadata(call, module_name):
    keywords = {keyword.arg: keyword.value for keyword in call.keywords}
    if None in keywords or len(keywords) != len(call.keywords):
        return None
    contract, name = keywords.get("contract"), keywords.get("name")
    if not isinstance(contract, ast.Constant) or contract.value != module_name:
        return None
    if not isinstance(name, ast.Constant) or not isinstance(name.value, str):
        return None
    return name.value


def _legacy_orm_name(node, module_name):
    if not _legacy_orm_assignment(node):
        return None
    name = _legacy_orm_metadata(node.value, module_name)
    if name is None or node.targets[0].id != constants.PRIVATE_METHOD_PREFIX + name:
        return None
    return name


def _module_declaration_ids(tree):
    return {id(node) for node in tree.body if isinstance(node, ast.Assign)}


def guard_legacy_orm_declarations(tree, module_name):
    """Bind old compiler declarations only when their ownership is verifiable."""
    for node in tree.body:
        storage_name = _legacy_orm_name(node, module_name)
        if storage_name is not None:
            node.value.keywords = [
                keyword
                for keyword in node.value.keywords
                if keyword.arg not in ("contract", "name")
            ]
            node.value = _orm_declaration_call(node.value, module_name, storage_name)
    return guard_attribute_targets(tree)


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
        self.module_declarations = set()

    def parse(self, source: str, lint=True, vm_profile: str | None = XIAN_VM_V2_PROFILE):
        if vm_profile in (None, XIAN_VM_V2_PROFILE):
            raise ValueError(
                "Python AST cannot represent exact V2 literals; use normalize_source or lower_to_ir"
            )
        return self._parse_host_ast(source, lint, vm_profile)

    def parse_legacy_runtime(self, source: str, *, lint: bool = True):
        """Transform CPython compatibility source that may predate native admission."""
        return self._parse_host_ast(source, lint, vm_profile=None)

    def _parse_host_ast(self, source: str, lint: bool, vm_profile: str | None):
        self.constructor_visited = False
        self.source = source

        tree = ast.parse(source)
        self.module_declarations = _module_declaration_ids(tree)

        try:
            if lint:
                self.lint_alerts = self.linter.check(tree)
            vm_report = None
            if vm_profile is not None:
                vm_report = self.vm_checker.check(tree, profile=vm_profile)

            tree = self.visit(tree)

            if self.lint_alerts is not None:
                raise LintingError(self.lint_alerts)
            if vm_report is not None and not vm_report.compatible:
                raise VmCompatibilityError(vm_report)

            # References to private functions and ORM instances may appear
            # before their definitions, so they are rewritten in a second
            # pass once visiting has collected the full name sets.
            for node in self.visited_names:
                if node.id in self.private_names or node.id in self.orm_names:
                    node.id = self.privatize(node.id)

            return guard_attribute_targets(tree)
        finally:
            # Reset on every exit so a failed parse cannot leak one
            # contract's names into the next parse on this instance.
            self.private_names = set()
            self.orm_names = set()
            self.visited_names = set()
            self.module_declarations = set()
            self.lint_alerts = None
            self.source = None

    @staticmethod
    def privatize(s):
        return "{}{}".format(constants.PRIVATE_METHOD_PREFIX, s)

    def _guarded_mul_call(
        self,
        left: ast.expr,
        right: ast.expr,
        location: ast.AST,
    ) -> ast.Call:
        return ast.copy_location(
            ast.Call(
                func=ast.Name(id="__xian_mul__", ctx=ast.Load()),
                args=[left, right],
                keywords=[],
            ),
            location,
        )

    def _guarded_binary_call(
        self,
        helper_name: str,
        left: ast.expr,
        right: ast.expr,
        location: ast.AST,
    ) -> ast.Call:
        return ast.copy_location(
            ast.Call(
                func=ast.Name(id=helper_name, ctx=ast.Load()),
                args=[left, right],
                keywords=[],
            ),
            location,
        )

    def compile(self, source: str, lint=True, vm_profile: str | None = XIAN_VM_V2_PROFILE):
        tree = self.parse(source, lint=lint, vm_profile=vm_profile)

        compiled_code = compile(tree, "<compilation>", "exec", optimize=0)

        return compiled_code

    def normalize_source(self, source: str, lint=True, vm_profile: str | None = XIAN_VM_V2_PROFILE):
        if vm_profile in (None, XIAN_VM_V2_PROFILE):
            import xian_compiler_core

            return xian_compiler_core.normalize_source(
                self.module_name, source, vm_profile=XIAN_VM_V2_PROFILE, lint=lint
            )
        tree = ast.parse(source)

        if lint:
            lint_alerts = self.linter.check(tree)
            if lint_alerts is not None:
                raise LintingError(lint_alerts)
        if vm_profile is not None:
            self.vm_checker.check_raise(tree, profile=vm_profile)

        ast.fix_missing_locations(tree)
        return ast.unparse(tree)

    def parse_to_code(self, source, lint=True, vm_profile: str | None = XIAN_VM_V2_PROFILE):
        if vm_profile in (None, XIAN_VM_V2_PROFILE):
            return self.normalize_source(source, lint=lint, vm_profile=vm_profile)
        tree = self.parse(source, lint=lint, vm_profile=vm_profile)
        return ast.unparse(tree)

    def check_vm_compatibility(self, source: str, profile: str = XIAN_VM_V2_PROFILE):
        return self.vm_checker.check(source, profile=profile)

    def lower_to_ir(
        self,
        source: str,
        lint=True,
        vm_profile: str | None = XIAN_VM_V2_PROFILE,
    ):
        if vm_profile in (None, XIAN_VM_V2_PROFILE):
            import xian_compiler_core

            return json.loads(
                xian_compiler_core.lower_source_to_ir_json(
                    self.module_name, source, vm_profile=XIAN_VM_V2_PROFILE, lint=lint
                )
            )
        tree = ast.parse(source)

        if lint:
            lint_alerts = self.linter.check(source)
            if lint_alerts is not None:
                raise LintingError(lint_alerts)

        selected_profile = vm_profile
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
        vm_profile: str | None = XIAN_VM_V2_PROFILE,
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
            elif isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Name):
                decorator_name = decorator.func.id
                decorator_keywords = decorator.keywords

            # change the name of the init function to '____' so it is uncallable except once
            if decorator_name == constants.INIT_DECORATOR_STRING:
                node.name = "____"

            elif decorator_name == constants.EXPORT_DECORATOR_STRING:
                # Transform @export decorators to @__export(contract_name) decorators
                new_node = ast.Call(
                    func=ast.Name(
                        id="{}{}".format("__", constants.EXPORT_DECORATOR_STRING),
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
            and isinstance(node.value.func, ast.Name)
            and node.value.func.id in constants.ORM_CLASS_NAMES
        ):
            storage_name = node.targets[0].id
            if id(node) in self.module_declarations:
                node.value = _orm_declaration_call(node.value, self.module_name, storage_name)
            elif node.value.func.id in ("ForeignVariable", "ForeignHash"):
                node.value = _orm_declaration_call(
                    node.value, self.module_name, storage_name, "__xian_foreign_declaration__"
                )
            else:
                node.value.keywords.extend(
                    [
                        ast.keyword(arg="contract", value=ast.Constant(value=self.module_name)),
                        ast.keyword(arg="name", value=ast.Constant(value=storage_name)),
                    ]
                )
            self.orm_names.add(storage_name)

        self.generic_visit(node)
        return node

    def visit_BinOp(self, node):
        self.generic_visit(node)
        if isinstance(node.op, ast.Mult):
            return self._guarded_mul_call(node.left, node.right, node)
        if isinstance(node.op, ast.Pow):
            return self._guarded_binary_call(
                "__xian_pow__",
                node.left,
                node.right,
                node,
            )
        if isinstance(node.op, ast.LShift):
            return self._guarded_binary_call(
                "__xian_lshift__",
                node.left,
                node.right,
                node,
            )
        if isinstance(node.op, ast.RShift):
            return self._guarded_binary_call(
                "__xian_rshift__",
                node.left,
                node.right,
                node,
            )
        return node

    def visit_Call(self, node):
        self.generic_visit(node)
        if isinstance(node.func, ast.Name) and node.func.id == "int":
            node.func.id = "__xian_int__"
        elif isinstance(node.func, ast.Name) and node.func.id == "pow":
            node.func.id = "__xian_pow__"
        return node

    def visit_Name(self, node):
        self.visited_names.add(node)
        return node

    def visit_Expr(self, node):
        self.generic_visit(node)
        return node

    def visit_Constant(self, node):
        if isinstance(node.value, float):
            literal = ast.get_source_segment(self.source, node) or str(node.value)
            return ast.Call(
                func=ast.Name(id="decimal", ctx=ast.Load()),
                args=[ast.Constant(value=literal)],
                keywords=[],
            )
        return node
