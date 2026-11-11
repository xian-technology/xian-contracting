"""Compiler metadata must not import an executable Python contract environment."""

import subprocess
import sys


def test_offline_compilation_needs_no_retired_execution_modules():
    code = """
import builtins
import importlib.abc
import sys

retired = {
    'contracting.execution.executor', 'contracting.execution.module',
    'contracting.execution.python_tracer', 'contracting.execution.tracer',
    'contracting.execution.sandbox', 'contracting.stdlib.env',
    'contracting.stdlib.builtins', 'contracting.stdlib.bridge.access',
    'contracting.stdlib.bridge.imports', 'contracting.stdlib.bridge.orm',
}
class BlockRetired(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname in retired:
            raise AssertionError('Retired contract environment imported: ' + fullname)

sys.meta_path.insert(0, BlockRetired())
original_import = builtins.__import__
original_finders = tuple(sys.meta_path)
from contracting.artifacts import compile_contract_source
from contracting.compilation.conformance import build_contract_language_manifest

artifact = compile_contract_source(
    module_name='con_offline', source='@export\\ndef read():\\n    return 42\\n'
)
assert artifact['source'].endswith('return 42')
manifest = build_contract_language_manifest()
surface = manifest['python_contracting']['public_env_surface']
assert 'call' in surface['importlib']['exports']
surface['importlib']['exports'].clear()
fresh = build_contract_language_manifest()['python_contracting']['public_env_surface']
assert 'call' in fresh['importlib']['exports']
assert not retired.intersection(sys.modules)
assert builtins.__import__ is original_import
assert tuple(sys.meta_path) == original_finders
"""
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
