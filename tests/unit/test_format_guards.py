"""The Python module loader routes formatting at value lookup/evaluation time."""

import ast
import builtins

import pytest

from contracting.execution.module import _compile_contract_runtime_source

FORMAT_ATTRIBUTE_HELPER = "__xian_format_attribute__"
FORMAT_FSTRING_HELPER = "__xian_format_fstring__"


def test_runtime_fstring_preserves_nested_spec_before_conversion_order():
    events = []

    class Value:
        def __repr__(self):
            events.append("repr")
            return "shown"

    def value():
        events.append("value")
        return Value()

    def width():
        events.append("width")
        return 8

    def guarded(value, spec, conversion):
        events.append(f"guard:{conversion}:{spec}")
        if conversion == ord("r"):
            value = repr(value)
        return builtins.format(value, spec)

    namespace = {"value": value, "width": width, FORMAT_FSTRING_HELPER: guarded}
    code = _compile_contract_runtime_source("format_order", 'result = f"{value()!r:{width()}}"')
    exec(code, namespace)
    assert events == ["value", "width", "guard:-1:", "guard:114:8", "repr"]
    assert namespace["result"] == "shown   "


@pytest.mark.parametrize("conversion", ["", "!s", "!r", "!a"])
def test_runtime_fstring_passes_original_conversion_and_empty_default_spec(conversion):
    calls = []

    def guarded(value, spec, code):
        calls.append((value, spec, code))
        return "guarded"

    namespace = {"value": "é", FORMAT_FSTRING_HELPER: guarded}
    code = _compile_contract_runtime_source("format_conversion", f'result = f"{{value{conversion}}}"')
    exec(code, namespace)
    assert calls == [("é", "", ord(conversion[-1]) if conversion else -1)]
    assert namespace["result"] == "guarded"


def test_runtime_routes_format_attribute_values_before_call_arguments():
    events = []

    def receiver():
        events.append("receiver")
        return "{}"

    def argument():
        events.append("argument")
        return 7

    def attribute(value, name):
        events.append(f"lookup:{name}")

        def invoke(*args, **kwargs):
            events.append("invoke")
            return getattr(value, name)(*args, **kwargs)

        return invoke

    namespace = {"receiver": receiver, "argument": argument, FORMAT_ATTRIBUTE_HELPER: attribute}
    source = "bound = receiver().format\nresult = bound(argument())\n"
    exec(_compile_contract_runtime_source("format_alias_order", source), namespace)
    assert events == ["receiver", "lookup:format", "argument", "invoke"]
    assert namespace["result"] == "7"


def test_runtime_routes_unbound_aliases_and_map_callbacks():
    lookups = []

    def attribute(value, name):
        lookups.append((value, name))
        return getattr(value, name)

    namespace = {FORMAT_ATTRIBUTE_HELPER: attribute}
    source = (
        "unbound = str.format\n"
        "mapping = str.format_map\n"
        "bound = '{}'.format\n"
        "results = [unbound('{}', 7), mapping('{x}', {'x': 8}), list(map(bound, [9, 10]))]\n"
    )
    exec(_compile_contract_runtime_source("format_callback", source), namespace)
    assert lookups == [(str, "format"), (str, "format_map"), ("{}", "format")]
    assert namespace["results"] == ["7", "8", ["9", "10"]]


def test_runtime_does_not_intercept_other_attribute_loads():
    def unexpected(*args):
        pytest.fail("non-format attribute was intercepted")

    namespace = {FORMAT_ATTRIBUTE_HELPER: unexpected}
    exec(_compile_contract_runtime_source("ordinary_attribute", "result = 'ABC'.lower()"), namespace)
    assert namespace["result"] == "abc"


def test_format_guard_transform_is_idempotent():
    from contracting.compilation.format_guards import guard_formatting

    source = 'result = f"{str.format(\'{}\', 7):>{3}}"'
    tree = guard_formatting(ast.parse(source))
    first = ast.dump(tree, include_attributes=True)
    second = ast.dump(guard_formatting(tree), include_attributes=True)
    assert first == second


def test_format_guard_preserves_attribute_assignment_and_deletion():
    from contracting.compilation.format_guards import guard_formatting

    class Receiver:
        pass

    receiver = Receiver()
    tree = guard_formatting(ast.parse("receiver.format = 7\ndel receiver.format\n"))
    exec(compile(tree, "format_mutation", "exec"), {"receiver": receiver})
    assert not hasattr(receiver, "format")


def test_sandbox_and_public_namespace_share_guarded_builtin_identity():
    from contracting.execution.format_policy import contract_format
    from contracting.execution.sandbox import build_contract_builtins
    from contracting.stdlib import env

    sandbox = build_contract_builtins(None)
    assert sandbox["format"] is env.gather()["format"] is contract_format
    namespace = {"__builtins__": sandbox}
    source = "result = [format(7, '04'), '{}'.format(8), f'{9:04}']"
    exec(_compile_contract_runtime_source("sandbox_formatting", source), namespace)
    assert namespace["result"] == ["0007", "8", "0009"]


def test_catalog_admits_guarded_class_aliases_without_admitting_bound_methods():
    from contracting.execution.format_policy import contract_format, format_attribute
    from contracting.execution.module_access import admitted_public_callable

    assert admitted_public_callable(contract_format)
    for name in ("format", "format_map"):
        assert admitted_public_callable(format_attribute(str, name))
        assert not admitted_public_callable(format_attribute("{}", name))
