"""Native failures remain bounded and follow their profile's error categories."""

import pytest
from xian_vm_core import native_error_result, _native_exception_from_repr, execute_contract

from contracting.execution.errors import classify_execution_error
from contracting.storage.driver import Driver


@pytest.mark.parametrize(
    "text,kind,args",
    [
        ("opaque failure", None, None),
        ("x" * len("Contract metadata changes are restricted to submission."), None, None),
        ("Contract metadata changes are restricted to submission.extra", None, None),
        (": AssertionError('stop')", AssertionError, ("stop",)),
        ("ValueError(1)#)", ValueError, (1,)),
        (
            "Contract metadata changes are restricted to submission.",
            AssertionError,
            ("Contract metadata changes are restricted to submission.",),
        ),
        ("AssertionError()", AssertionError, ()),
        ("ValueError('invalid')", ValueError, ("invalid",)),
        ("TypeError('bad', 2)", TypeError, ("bad", 2)),
        ("KeyError('key')", KeyError, ("key",)),
        ("IndexError(3)", IndexError, (3,)),
        ("RuntimeError: stop", RuntimeError, ("stop",)),
        ("Exception: unknown: stop", Exception, ("unknown: stop",)),
        ("unknown: RuntimeError('inner')", RuntimeError, ("inner",)),
        ("AssertionError('ValueError: stop')", AssertionError, ("ValueError: stop",)),
        ("AssertionError('ValueError: ValueError: stop')", ValueError, ("stop')",)),
        ("AssertionError('prefix: stop')", AssertionError, ("prefix: stop",)),
        (
            "prefix: Contract metadata changes are restricted to submission.",
            AssertionError,
            ("Contract metadata changes are restricted to submission.",),
        ),
        ("ValueError: no-colon", ValueError, ("no-colon",)),
        ("ValueError('unterminated)", ValueError, ("'unterminated",)),
        ("ValueError(a=1)", ValueError, ("a=1",)),
        ("Bogus('value')", None, None),
        ("TypeError: ValueError: nested", ValueError, ("nested",)),
    ],
)
def test_existing_failure_representations_keep_types_arguments_and_categories(text, kind, args):
    error = _native_exception_from_repr(text)
    if kind is None:
        assert error is None
    else:
        assert type(error) is kind
        assert error.args == args
        expected = "contract_assertion" if kind is AssertionError else "contract_error"
        assert classify_execution_error(error) == expected


@pytest.mark.parametrize(
    "text,kind,args",
    [
        ("AssertionError('" + "ValueError: " * 1500 + "stop')", ValueError, ("stop')",)),
        ("unknown: " * 1500 + "AssertionError('stop')", AssertionError, ("stop",)),
        ("unknown: " * 1500 + "opaque", None, None),
    ],
    ids=["typed-message", "host-prefixes", "opaque-message"],
)
def test_long_error_messages_do_not_recurse_through_host_stack(text, kind, args):
    error = _native_exception_from_repr(text)
    assert type(error) is kind if kind is not None else error is None
    if error is not None:
        assert error.args == args


@pytest.mark.parametrize("profile", ["xian_vm_v1", "xian_vm_v2"])
def test_long_native_failure_is_returned_without_writes_and_next_call_succeeds(tmp_path, profile):
    source = """stored = Variable()
@export
def fail():
    stored.set(99)
    assert False, 'ValueError: ' * 1500
@export
def good():
    return 7
"""
    with Driver(storage_home=tmp_path / "native", vm_profile=profile) as driver:
        driver.set_contract_from_source(name="con_error", source=source)
        driver.set_var("con_error", "stored", value=1)
        driver.commit()

        def execute(function):
            return execute_contract(
                driver=driver,
                contract_name="con_error",
                function_name=function,
                kwargs={},
                context={"caller": "alice", "signer": "alice"},
                vm_profile=profile,
            )

        failed = execute("fail")
        assert failed.status_code == 1
        expected_type = ValueError if profile == "xian_vm_v1" else AssertionError
        expected_category = "contract_error" if profile == "xian_vm_v1" else "contract_assertion"
        assert type(failed.result) is expected_type
        assert classify_execution_error(failed.result) == expected_category
        if profile == "xian_vm_v2":
            assert failed.result.args == ("ValueError: " * 1500,)
        assert failed.writes == {}
        assert failed.events == []
        assert driver.get_var("con_error", "stored") == 1
        followup = execute("good")
        assert followup.status_code == 0
        assert followup.result == 7


@pytest.mark.parametrize("profile", ["xian_vm_v1", "xian_vm_v2"])
@pytest.mark.parametrize(
    "status,value",
    [(0, "AssertionError('ordinary result')"), (1, RuntimeError("typed failure")), (0, None)],
)
def test_failure_coercion_preserves_success_values_and_existing_exception_objects(
    profile, status, value
):
    assert native_error_result(status, value, vm_profile=profile) is value
