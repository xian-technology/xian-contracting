from __future__ import annotations

import os
from pathlib import Path


TEST_HOME = Path(__file__).resolve().parents[1] / ".tmp-home"
TEST_HOME.mkdir(parents=True, exist_ok=True)
os.environ["HOME"] = str(TEST_HOME)
