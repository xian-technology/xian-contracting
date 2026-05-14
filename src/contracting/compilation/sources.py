"""Helpers for discovering authored Xian contract sources."""

from __future__ import annotations

from pathlib import Path

from contracting.compilation.vm import iter_contract_sources


def module_name_from_path(path: Path) -> str:
    name = path.name
    if name.endswith(".s.py"):
        return name[: -len(".s.py")]
    if name.endswith(".py"):
        return name[: -len(".py")]
    return path.stem


def iter_authored_contract_sources(paths: list[Path]) -> list[Path]:
    return [
        path
        for path in iter_contract_sources(paths)
        if "__pycache__" not in path.parts
    ]
