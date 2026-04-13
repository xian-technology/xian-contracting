"""Python VM compatibility checks for authored Xian contracts."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from contracting.compilation.compiler import ContractingCompiler
from contracting.compilation.vm import iter_contract_sources


@dataclass(frozen=True, slots=True)
class PythonVmCompatibilityIssue:
    stage: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {
            "stage": self.stage,
            "message": self.message,
        }


@dataclass(frozen=True, slots=True)
class PythonVmCompatibilityReport:
    module_name: str
    issues: tuple[PythonVmCompatibilityIssue, ...]

    @property
    def compatible(self) -> bool:
        return not self.issues

    def to_dict(self) -> dict[str, Any]:
        return {
            "module_name": self.module_name,
            "compatible": self.compatible,
            "issues": [issue.to_dict() for issue in self.issues],
        }


def module_name_from_path(path: Path) -> str:
    name = path.name
    if name.endswith(".s.py"):
        return name[: -len(".s.py")]
    if name.endswith(".py"):
        return name[: -len(".py")]
    return path.stem


class PythonVmCompatibilityChecker:
    def check(
        self,
        source: str,
        *,
        module_name: str,
    ) -> PythonVmCompatibilityReport:
        issues: list[PythonVmCompatibilityIssue] = []
        compiler = ContractingCompiler(module_name=module_name)

        try:
            normalized_source = compiler.normalize_source(source, lint=True)
        except Exception as exc:
            issues.append(
                PythonVmCompatibilityIssue(
                    stage="normalize_source",
                    message=str(exc),
                )
            )
            return PythonVmCompatibilityReport(
                module_name=module_name,
                issues=tuple(issues),
            )

        try:
            runtime_code = compiler.parse_to_code(
                normalized_source,
                lint=False,
            )
        except Exception as exc:
            issues.append(
                PythonVmCompatibilityIssue(
                    stage="parse_to_code",
                    message=str(exc),
                )
            )
            return PythonVmCompatibilityReport(
                module_name=module_name,
                issues=tuple(issues),
            )

        try:
            compile(runtime_code, module_name, "exec")
        except Exception as exc:
            issues.append(
                PythonVmCompatibilityIssue(
                    stage="compile_runtime_code",
                    message=str(exc),
                )
            )

        return PythonVmCompatibilityReport(
            module_name=module_name,
            issues=tuple(issues),
        )


def iter_authored_contract_sources(paths: list[Path]) -> list[Path]:
    return [
        path
        for path in iter_contract_sources(paths)
        if "__pycache__" not in path.parts
    ]
