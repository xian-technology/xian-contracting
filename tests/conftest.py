from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

import pytest


def pytest_configure(config):
    # Imports during collection must not resolve defaults inside the user's home
    # or another pytest process's node directory.
    home = TemporaryDirectory(prefix="xian-contracting-collection-")
    environment = pytest.MonkeyPatch()
    environment.setenv("HOME", home.name)
    config.add_cleanup(home.cleanup)
    config.add_cleanup(environment.undo)


@pytest.fixture
def test_home(tmp_path):
    return tmp_path / "home"


@pytest.fixture
def node_home(test_home):
    home = test_home / ".cometbft"
    home.mkdir(parents=True)
    return home


@pytest.fixture(autouse=True)
def isolate_default_contract_storage(test_home, node_home, monkeypatch):
    from contracting import constants

    monkeypatch.setenv("HOME", str(test_home))
    monkeypatch.setattr(constants, "STORAGE_HOME", node_home / "xian")
    # Record the original directory even when a test calls os.chdir directly.
    monkeypatch.chdir(Path.cwd())
