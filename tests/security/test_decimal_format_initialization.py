"""Decimal's lazy host fallback must initialize before restricted execution."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PROCESS_PROBE = """
import json
from pathlib import Path
import sys
from tests.compatibility.runner import run_case

expression, directory = sys.argv[1:]
case = {'id': 'cold_decimal_format', 'source': '@export\\ndef probe():\\n    return ' + expression + '\\n'}
result = run_case(case, Path(directory) / 'contract')

# Even after the trusted fallback is available, contract imports stay restricted.
from contracting.execution.module import install_contract_module_loader, restricted_import
from contracting.storage.driver import Driver
install_contract_module_loader(Driver(storage_home=Path(directory) / 'private_import'))
try:
    restricted_import('_pydecimal', {'__contract__': True})
except ImportError as error:
    private_import = str(error)
else:
    private_import = None
print(json.dumps({'result': result, 'private_import': private_import}))
"""


class TestDecimalFormatInitialization(unittest.TestCase):
    def test_first_authored_decimal_format_in_fresh_process(self):
        expressions = [
            "format(round(decimal('-0.001'), 3), 'z.2f')",
            "'{:z.2f}'.format(round(decimal('-0.001'), 3))",
            "f\"{round(decimal('-0.001'), 3):z.2f}\"",
        ]
        for expression in expressions:
            with self.subTest(expression=expression), tempfile.TemporaryDirectory() as directory:
                environment = dict(os.environ, HOME=str(Path(directory) / "home"))
                process = subprocess.run(
                    [sys.executable, "-c", PROCESS_PROBE, expression, directory],
                    env=environment,
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=30,
                )
                observation = json.loads(process.stdout)
                actual = observation["result"]
                self.assertEqual(actual["admission"], "accepted", actual)
                self.assertEqual(actual["status_code"], 0, actual)
                self.assertEqual(actual["result"], ["str", "0.00"])
                self.assertEqual(actual["writes"], ["dict", []])
                self.assertEqual(actual["events"], ["list", []])
                self.assertIn(
                    "cannot be imported in a smart contract", observation["private_import"]
                )
