"""Public class checks preserve Python's ordered classinfo and wrapper policies."""

import pytest

from contracting.execution.executor import Executor
from contracting.storage.driver import Driver

pytestmark = pytest.mark.optional_native

CASES = [
    ('str(Exception("problem"))', "problem"),
    ("str(Exception())", ""),
    ('str(Exception("problem", 3))', "('problem', 3)"),
    ('str(Exception(["problem", 3]))', "['problem', 3]"),
    ('str(Exception(Exception("problem")))', "problem"),
    ('ascii(Exception("problem"))', "Exception('problem')"),
    ('format(Exception("problem"))', "problem"),
    ("format(Exception())", ""),
    ('isinstance(Exception("problem"), Exception)', True),
    ("isinstance(1, ())", False),
    ("isinstance(1, ((), int))", True),
    ("isinstance(1, (int, abs))", True),
    ('isinstance("a", (int, (str, abs)))', True),
    ("isinstance(1, (int, Any))", True),
    ("isinstance([], (int, str))", False),
    ("issubclass(int, ())", False),
    ("issubclass(1, ())", False),
    ("issubclass((int,), ((),))", False),
    ("issubclass(int, (int, abs))", True),
    ("issubclass(bool, (str, (int, abs)))", True),
    ("issubclass(int, Any)", False),
    ("issubclass(Any, Any)", True),
    ("issubclass(Any, int)", False),
    ("issubclass(bool, int)", True),
    ("issubclass(int, bool)", False),
    ("issubclass(bytes, bytes)", True),
    ("issubclass(bytearray, bytearray)", True),
    ("isinstance(map(abs, []), map)", True),
    ("isinstance(filter(None, []), filter)", True),
    ("isinstance(zip([], []), zip)", True),
    ("isinstance(map(abs, []), filter)", False),
    ("isinstance(reversed([]), reversed)", False),
    ('isinstance(reversed("ab"), reversed)', True),
    ("isinstance(reversed((1,)), reversed)", True),
    ("isinstance(reversed(bytes([1])), reversed)", True),
    ("isinstance(reversed(bytearray([1])), reversed)", True),
    ("isinstance(reversed(range(2)), reversed)", False),
    ("isinstance(reversed({1: 2}), reversed)", False),
    ("issubclass(map, map)", True),
    ("issubclass(filter, map)", False),
    ("isinstance(v, Variable)", True),
    ("isinstance(h, Hash)", True),
    ("isinstance(v, Hash)", False),
    ("isinstance(fv, ForeignVariable)", True),
    ("isinstance(fh, ForeignHash)", True),
    ("isinstance(fv, Variable)", False),
    ("issubclass(ForeignVariable, Variable)", False),
]

INVALID = [
    "isinstance(1, 1)",
    "isinstance(1, abs)",
    "isinstance(1, (abs, int))",
    'isinstance("a", (int, (abs, str)))',
    "isinstance(1, Any)",
    "isinstance(1, (Any, int))",
    "isinstance(range(1), range)",
    "issubclass((int,), int)",
    "issubclass(abs, int)",
    "issubclass(range, range)",
    "issubclass(int, abs)",
    "issubclass(int, (abs, int))",
    "issubclass(1, (int, abs))",
    "issubclass(1, Any)",
    'format(Exception("problem"), "x")',
]


def execute_expression(home, expression, native):
    source = (
        "v = Variable()\nh = Hash()\n"
        'fv = ForeignVariable(foreign_contract="con_type_checks", foreign_name="v")\n'
        'fh = ForeignHash(foreign_contract="con_type_checks", foreign_name="h")\n'
        f"@export\ndef probe():\n    return {expression}\n"
    )
    with Driver(storage_home=home) as driver:
        driver.set_contract_from_source("con_type_checks", source, owner=None)
        driver.commit()
        if native:
            from xian_vm_core import execute_contract

            output = execute_contract(
                driver=driver,
                contract_name="con_type_checks",
                function_name="probe",
                kwargs={},
                context={"caller": "alice", "signer": "alice", "this": "con_type_checks"},
                meter=False,
            )
            return output.status_code, output.result
        output = Executor(driver=driver, metering=False).execute(
            sender="alice",
            contract_name="con_type_checks",
            function_name="probe",
            kwargs={},
            metering=False,
        )
        return output["status_code"], output["result"]


@pytest.mark.parametrize("native", [False, True], ids=["python", "native"])
@pytest.mark.parametrize(("expression", "expected"), CASES)
def test_public_type_checks_and_exception_text(tmp_path, expression, expected, native):
    status, result = execute_expression(tmp_path, expression, native)
    assert status == 0, result
    assert type(result) is type(expected)
    assert result == expected


@pytest.mark.parametrize("native", [False, True], ids=["python", "native"])
@pytest.mark.parametrize("expression", INVALID)
def test_public_type_checks_reject_invalid_descriptors(tmp_path, expression, native):
    status, result = execute_expression(tmp_path, expression, native)
    assert status == 1, result
