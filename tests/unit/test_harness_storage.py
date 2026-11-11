"""Test processes and the code they spawn must share only their own test state."""

import os
import subprocess
import sys
from pathlib import Path

from contracting.storage.driver import Driver


def test_default_storage_is_visible_to_a_fresh_process():
    with Driver() as driver:
        driver.set("con_isolation.value", 42)
        driver.commit()
        child = subprocess.run(
            [
                sys.executable,
                "-c",
                """
import sys
from pathlib import Path
from contracting import constants
from contracting.storage.driver import Driver

assert constants.STORAGE_HOME == Path(sys.argv[1]), constants.STORAGE_HOME
with Driver() as driver:
    assert driver.get("con_isolation.value") == 42
""",
                str(driver.storage_home),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
    assert child.returncode == 0, child.stderr


def test_home_files_can_be_written_without_leaking_to_another_test():
    marker = Path.home() / f"pytest-isolation-{os.getpid()}"
    marker.write_text("belongs to this test")
    assert marker.read_text() == "belongs to this test"


def test_home_files_from_another_test_are_absent():
    marker = Path.home() / f"pytest-isolation-{os.getpid()}"
    try:
        assert not marker.exists(), f"another test leaked its home into {marker.parent}"
    finally:
        marker.unlink(missing_ok=True)
