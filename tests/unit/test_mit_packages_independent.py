"""The MIT packages under packages/ never need the GPL contracting package at runtime.

`src/contracting` (``xian-tech-contracting``) is GPL-3.0-only; every package in
``packages/`` is MIT (``xian-vm-core``: MIT AND OLDAP-2.8). A runtime
dependency or import from an MIT package on contracting would pull GPL code
into the MIT SDK stack, so none may exist. Test and development dependencies
(dependency groups, ``tests/`` folders) are fine.
"""

import ast
import json
import re
import tomllib
from pathlib import Path

PACKAGES = Path(__file__).resolve().parents[2] / "packages"
GPL_DISTRIBUTIONS = {"xian-tech-contracting", "contracting"}
NOT_RUNTIME = {
    "tests",
    "test",
    "examples",
    "benches",
    "benchmarks",
    "target",
    ".venv",
    "node_modules",
}
RUST_IMPORT = re.compile(r"""import(?:_bound)?\(\s*py\s*,\s*"contracting(?:\.|")""")


def _requirement_name(requirement: str) -> str:
    name = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", requirement).group(1)
    return re.sub(r"[-_.]+", "-", name).lower()


def _runtime_requirements(package: Path) -> list[str]:
    requirements = []
    pyproject = package / "pyproject.toml"
    if pyproject.is_file():
        project = tomllib.loads(pyproject.read_text()).get("project", {})
        requirements += project.get("dependencies", [])
        for extra in project.get("optional-dependencies", {}).values():
            requirements += extra
    for manifest in package.rglob("package.json"):
        if NOT_RUNTIME.isdisjoint(manifest.relative_to(package).parts):
            data = json.loads(manifest.read_text())
            requirements += list(data.get("dependencies", {})) + list(
                data.get("peerDependencies", {})
            )
    return requirements


def _runtime_sources(package: Path, suffix: str):
    for path in sorted(package.rglob(f"*{suffix}")):
        if NOT_RUNTIME.isdisjoint(path.relative_to(package).parts):
            yield path


def _imports_contracting(source: Path) -> bool:
    for node in ast.walk(ast.parse(source.read_text(), filename=str(source))):
        names = []
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names = [node.module]
        if any(name == "contracting" or name.startswith("contracting.") for name in names):
            return True
    return False


def gpl_runtime_links(packages: Path) -> list[str]:
    """Every runtime dependency or import of contracting under ``packages``."""
    found = []
    for package in sorted(p for p in packages.iterdir() if p.is_dir()):
        found += [
            f"{package.name}: depends on {requirement}"
            for requirement in _runtime_requirements(package)
            if _requirement_name(requirement) in GPL_DISTRIBUTIONS
        ]
        found += [
            f"{source.relative_to(packages)}: imports contracting"
            for source in _runtime_sources(package, ".py")
            if _imports_contracting(source)
        ]
        found += [
            f"{source.relative_to(packages)}: imports contracting from Rust"
            for source in _runtime_sources(package, ".rs")
            if RUST_IMPORT.search(source.read_text())
        ]
    return found


def test_mit_packages_have_no_runtime_link_to_contracting():
    assert sorted(p.name for p in PACKAGES.iterdir() if (p / "LICENSE").is_file())
    assert gpl_runtime_links(PACKAGES) == []


def test_the_check_finds_dependencies_and_imports(tmp_path):
    package = tmp_path / "xian-example"
    (package / "src" / "example").mkdir(parents=True)
    (package / "tests").mkdir()
    (package / "src" / "lib").mkdir()
    (package / "pyproject.toml").write_text(
        '[project]\nname = "xian-example"\ndependencies = ["pynacl>=1.5"]\n'
        '[project.optional-dependencies]\nnode = ["Xian_Tech.Contracting>=1.0"]\n'
        '[dependency-groups]\ndev = ["xian-tech-contracting"]\n'
    )
    (package / "src" / "example" / "a.py").write_text("from contracting.storage import driver\n")
    (package / "src" / "example" / "b.py").write_text("import json\nimport contracting_tools\n")
    (package / "src" / "lib" / "c.rs").write_text('PyModule::import(py, "contracting.stdlib")?;\n')
    (package / "tests" / "test_x.py").write_text("import contracting\n")
    assert gpl_runtime_links(tmp_path) == [
        "xian-example: depends on Xian_Tech.Contracting>=1.0",
        "xian-example/src/example/a.py: imports contracting",
        "xian-example/src/lib/c.rs: imports contracting from Rust",
    ]
