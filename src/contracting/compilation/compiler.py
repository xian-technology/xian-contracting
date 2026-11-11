"""Source analysis and IR compilation for native execution profiles."""

import ast
import json

from contracting.compilation.linter import Linter, LintingError
from contracting.compilation.lowering import XianIrLowerer
from contracting.compilation.vm import XIAN_VM_V2_PROFILE, VmCompatibilityChecker


class ContractingCompiler:
    def __init__(self, module_name="__main__", linter=None, vm_checker=None):
        self.module_name = module_name
        self.linter = linter or Linter()
        self.vm_checker = vm_checker or VmCompatibilityChecker()

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
        """Return normalized authored source; native execution consumes IR."""
        return self.normalize_source(source, lint=lint, vm_profile=vm_profile)

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
