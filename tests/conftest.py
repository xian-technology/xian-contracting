from __future__ import annotations

import os
from pathlib import Path

import pytest

TEST_HOME = Path(__file__).resolve().parents[1] / ".tmp-home"
TEST_HOME.mkdir(parents=True, exist_ok=True)
os.environ["HOME"] = str(TEST_HOME)


@pytest.fixture(autouse=True)
def isolate_default_contract_storage(tmp_path, monkeypatch):
    from contracting import constants

    monkeypatch.setattr(constants, "STORAGE_HOME", tmp_path / "xian")
