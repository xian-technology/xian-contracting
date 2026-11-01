"""Metadata callbacks cannot acquire or transfer live contract capabilities."""

import pytest

from tests.compatibility.runner import encode, run_case

ENGINES = [False, pytest.param(True, marks=pytest.mark.optional_native)]
TARGET = """balance = Variable(default_value=0)
@export
def transfer(amount: int, to: str):
    balance.set(amount)
    return True
@export
def read():
    return balance.get()
"""
RECEIVER = """touched = Variable(default_value=0)
@export
def consume(value: Any):
    touched.set(99)
    return True
@export
def read():
    return touched.get()
"""
PREFIX = """import con_subject_target
import con_subject_receiver
state = Variable(default_value=0)
Notice = LogEvent(event='Notice', params={'value': int})
retained = []
payload = []
def capture_default(value=payload):
    return value[0]
def capture_keyword(*, value=payload):
    return value[0]
@export
def capture_export(value: Any = payload):
    return value[0]
def capture_metadata(value=payload):
    return [value[0].kind, value[0].name, value[0].args]
"""


def execute(tmp_path, native, *, callback, after="return True", descriptor=None):
    descriptor = descriptor or "importlib.Func('transfer', ('amount', 'to'))"
    source = (
        PREFIX
        + "\ndef inspect(subject):\n"
        + "".join("    " + line + "\n" for line in callback.splitlines())
        + "\n@export\ndef probe():\n"
        + "    state.set(1)\n    Notice({'value': 1})\n"
        + f"    check = {descriptor}\n"
        + "    check.is_of = inspect\n"
        + "    matched = importlib.enforce_interface(con_subject_target, [check])\n"
        + "".join("    " + line + "\n" for line in after.splitlines())
    )
    return run_case(
        {
            "id": "subject_boundary",
            "source": source,
            "dependencies": {
                "con_subject_target": TARGET,
                "con_subject_receiver": RECEIVER,
            },
        },
        tmp_path,
        native=native,
    )


def assert_rolled_back(actual):
    assert actual["admission"] == "accepted", actual
    assert actual["status_code"] == 1, actual
    assert actual["writes"] == encode({}), actual
    assert actual["events"] == encode([]), actual


@pytest.mark.parametrize("native", ENGINES)
@pytest.mark.parametrize(
    ("descriptor", "expected"),
    [
        (
            "importlib.Func('transfer', ('amount', 'to'))",
            ["function", "transfer", ("amount", "to"), None],
        ),
        ("importlib.Var('balance', Variable)", ["storage", "__balance", None, "Variable"]),
    ],
)
def test_subject_fields_are_plain_metadata_and_do_not_call_target(
    tmp_path, native, descriptor, expected
):
    actual = execute(
        tmp_path,
        native,
        descriptor=descriptor,
        callback="retained.append([subject.kind, subject.name, subject.args, subject.storage_type])\nreturn True",
        after="return [matched, retained[0], con_subject_target.read(), con_subject_receiver.read()]",
    )
    assert actual["status_code"] == 0, actual
    assert actual["result"] == encode([True, expected, 0, 0]), actual
    assert actual["writes"] == encode({"baseline_subject_boundary.state": 1}), actual


@pytest.mark.parametrize("native", ENGINES)
@pytest.mark.parametrize(
    "mutation",
    [
        "subject.name = 'other'",
        "subject.kind = 'storage'",
        "subject.args = ()",
        "subject.storage_type = 'Hash'",
        "subject.extra = 1",
        "subject.name += 'suffix'",
    ],
)
def test_subject_attributes_are_readonly(tmp_path, native, mutation):
    actual = execute(tmp_path, native, callback=mutation + "\nreturn True")
    assert_rolled_back(actual)


@pytest.mark.parametrize("native", ENGINES)
@pytest.mark.parametrize(
    "call",
    [
        "subject(99, 'alice')",
        "subject.get()",
        "subject.set(99)",
        "subject.is_of(con_subject_target.transfer)",
        "subject.contract",
    ],
)
def test_subject_has_no_callable_or_storage_authority(tmp_path, native, call):
    actual = execute(tmp_path, native, callback=call + "\nreturn True")
    assert_rolled_back(actual)


@pytest.mark.parametrize("native", ENGINES)
@pytest.mark.parametrize(
    "capture",
    [
        "retained.append(subject)",
        "retained.append({'nested': [subject]})",
        "payload.append(subject)\nretained.append(capture_export)",
        "payload.append(subject)\nretained.append(capture_default)",
        "payload.append(subject)\nretained.append(capture_keyword)",
        "holder = importlib.Func('holder')\nholder.extra = subject\nretained.append(holder)",
        "retained.append(map(str, [subject]))",
    ],
)
@pytest.mark.parametrize(
    "escape",
    [
        "return retained[0]",
        "state.set(retained[0])\nreturn True",
        "return con_subject_receiver.consume(retained[0])",
    ],
)
def test_nested_subjects_cannot_escape_execution(tmp_path, native, capture, escape):
    actual = execute(tmp_path, native, callback=capture + "\nreturn True", after=escape)
    assert_rolled_back(actual)


@pytest.mark.parametrize("native", ENGINES)
def test_foreign_callback_cannot_receive_a_subject(tmp_path, native):
    # The callback itself crosses the boundary, rather than forwarding from inspect.
    source = (
        PREFIX
        + """
@export
def probe():
    state.set(1)
    Notice({'value': 1})
    check = importlib.Func('transfer', ('amount', 'to'))
    check.is_of = con_subject_receiver.consume
    return importlib.enforce_interface(con_subject_target, [check])
"""
    )
    actual = run_case(
        {
            "id": "subject_foreign_callback",
            "source": source,
            "dependencies": {"con_subject_target": TARGET, "con_subject_receiver": RECEIVER},
        },
        tmp_path,
        native=native,
    )
    assert_rolled_back(actual)


@pytest.mark.parametrize("native", ENGINES)
def test_same_execution_default_capture_is_allowed(tmp_path, native):
    actual = execute(
        tmp_path,
        native,
        callback="payload.append(subject)\nretained.append(capture_metadata)\nreturn True",
        after="return [matched, retained[0](), con_subject_target.read()]",
    )
    assert actual["status_code"] == 0, actual
    assert actual["result"] == encode([True, ["function", "transfer", ("amount", "to")], 0])


@pytest.mark.parametrize("native", ENGINES)
@pytest.mark.parametrize("fail", [False, True])
def test_callee_cannot_inject_subject_into_caller_mutable_input(tmp_path, native, fail):
    injector = """import con_subject_target
state = Variable(default_value=0)
inputs = []
def inject(subject):
    inputs[0].append({'nested': subject})
    return True
@export
def mutate(values: Any, fail: bool):
    inputs.append(values)
    state.set(99)
    check = importlib.Func('transfer', ('amount', 'to'))
    check.is_of = inject
    importlib.enforce_interface(con_subject_target, [check])
    assert not fail, 'callee failed after injection'
    return True
"""
    source = (
        PREFIX
        + """
import con_subject_injector
@export
def probe():
    state.set(1)
    Notice({'value': 1})
    values = []
    con_subject_injector.mutate(values, FAIL)
    return len(values)
""".replace("FAIL", repr(fail))
    )
    actual = run_case(
        {
            "id": "subject_input_injection",
            "source": source,
            "dependencies": {
                "con_subject_target": TARGET,
                "con_subject_receiver": RECEIVER,
                "con_subject_injector": injector,
            },
        },
        tmp_path,
        native=native,
    )
    assert_rolled_back(actual)


def test_subject_type_factory_is_not_an_authored_surface(tmp_path):
    actual = execute(tmp_path, False, callback="factory = type(subject)\nreturn True")
    assert actual == {"admission": "rejected", "diagnostic": "LintingError"}
