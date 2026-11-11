"""All admitted formatting call paths use the VM's deterministic public policy."""

import pytest

from tests.compatibility.runner import encode, run_case

ENGINES = [False, pytest.param(True, marks=pytest.mark.optional_native)]
ROUTES = {
    "builtin": "return format(value, spec)",
    "builtin_alias": "render = format\nreturn render(value, spec)",
    "builtin_callback": "return list(map(format, [value], [spec]))[0]",
    "bound": "return positional.format(value)",
    "bound_alias": "render = positional.format\nreturn render(value)",
    "unbound_alias": "render = str.format\nreturn render(positional, value)",
    "bound_callback": "return list(map(positional.format, [value]))[0]",
    "unbound_callback": "return list(map(str.format, [positional], [value]))[0]",
    "mapping": "return named.format_map({'value': value})",
    "mapping_alias": "render = named.format_map\nreturn render({'value': value})",
    "unbound_mapping_alias": "render = str.format_map\nreturn render(named, {'value': value})",
    "mapping_callback": "return list(map(named.format_map, [{'value': value}]))[0]",
    "unbound_mapping_callback": "return list(map(str.format_map, [named], [{'value': value}]))[0]",
    "fstring": "return f'{value:{spec}}'",
}


def probe(tmp_path, native, body, prefix="", dependencies=None):
    source = (
        prefix
        + "\n@export\ndef probe():\n"
        + "".join("    " + line + "\n" for line in body.splitlines())
    )
    actual = run_case(
        {"id": "public_format_policy", "source": source, "dependencies": dependencies or {}},
        tmp_path,
        native=native,
    )
    assert actual["admission"] == "accepted", actual
    return actual


@pytest.mark.parametrize("native", ENGINES, ids=["python", "native"])
@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize(
    "spec,expected",
    [
        ("z.2f", "0.00"),
        ("#>8.2f", "###-0.00"),
        ("_>8.2f", "___-0.00"),
        ("#.2f", None),
        ("_.2f", None),
    ],
    ids=[
        "positive_zero",
        "hash_fill",
        "underscore_fill",
        "alternate_rejected",
        "grouping_rejected",
    ],
)
def test_raw_decimal_policy_across_call_paths(tmp_path, native, route, spec, expected):
    body = (
        "value = round(decimal('-0.004'), 3)\n"
        f"spec = {spec!r}\n"
        "positional = '{0:' + spec + '}'\n"
        "named = '{value:' + spec + '}'\n"
        "state.set('pending')\n" + ROUTES[route]
    )
    actual = probe(tmp_path, native, body, "state = Variable()\n")
    if expected is None:
        assert actual["status_code"] == 1, actual
        assert any(
            message in actual["diagnostic"].lower()
            for message in (
                "invalid or unsupported format specification",
                "invalid decimal operation or range",
            )
        ), actual
        assert actual["writes"] == encode({})
        assert actual["events"] == encode([])
    else:
        assert actual["status_code"] == 0, actual
        assert actual["result"] == encode(expected), actual


@pytest.mark.parametrize("native", ENGINES, ids=["python", "native"])
def test_nondecimal_numeric_flags_and_decimal_comma_grouping(tmp_path, native):
    actual = probe(
        tmp_path,
        native,
        "return [format(65536, '#_x'), format(float('12345.25'), '_.2f'), "
        "format(float('12'), '#.4g'), format(round(decimal('1234.5'), 1), ',.1f')]",
    )
    assert actual["status_code"] == 0, actual
    assert actual["result"] == encode(["0x1_0000", "12_345.25", "12.00", "1,234.5"])


@pytest.mark.parametrize("native", ENGINES, ids=["python", "native"])
@pytest.mark.parametrize("conversion", ["s", "r", "a"])
def test_fstring_specification_is_evaluated_once_before_conversion(tmp_path, native, conversion):
    prefix = """values = ['é']
trace = []
def value():
    trace.append('value')
    return values
def specification():
    trace.append('specification')
    values.append('猫')
    return ''
"""
    actual = probe(
        tmp_path,
        native,
        f"result = f'{{value()!{conversion}:{{specification()}}}}'\nreturn [result, trace]",
        prefix,
    )
    expected = "['\\xe9', '\\u732b']" if conversion == "a" else "['é', '猫']"
    assert actual["status_code"] == 0, actual
    assert actual["result"] == encode([expected, ["value", "specification"]])


@pytest.mark.parametrize("native", ENGINES, ids=["python", "native"])
def test_nested_fstring_width_precision_evaluation_order(tmp_path, native):
    prefix = """trace = []
def number():
    trace.append('number')
    return round(decimal('2.125'), 3)
def width():
    trace.append('width')
    return 8
def precision():
    trace.append('precision')
    return 2
"""
    actual = probe(
        tmp_path,
        native,
        "result = f'{number():0{width()}.{precision()}f}'\nreturn [result, trace]",
        prefix,
    )
    assert actual["status_code"] == 0, actual
    assert actual["result"] == encode(["00002.12", ["number", "width", "precision"]])


@pytest.mark.parametrize("native", ENGINES, ids=["python", "native"])
@pytest.mark.parametrize(
    "expression",
    [
        "len(format('x', '131073s'))",
        "len('{0:131073s}'.format('x'))",
        "len('{value:131073s}'.format_map({'value': 'x'}))",
        "len(f'{\"x\":131073s}')",
    ],
)
def test_formatting_allocation_guard_cannot_be_hidden_by_len(tmp_path, native, expression):
    actual = probe(
        tmp_path, native, f"state.set('pending')\nreturn {expression}", "state = Variable()\n"
    )
    assert actual["status_code"] == 1, actual
    assert actual["writes"] == encode({})
    assert actual["events"] == encode([])


@pytest.mark.parametrize("native", ENGINES, ids=["python", "native"])
@pytest.mark.parametrize(
    "expression",
    [
        "'{0.__class__}'.format(datetime.datetime(2026, 1, 1))",
        "'{value._datetime}'.format_map({'value': datetime.datetime(2026, 1, 1)})",
        "'{0._hidden}'.format(importlib.import_module('con_format_target'))",
    ],
)
def test_format_fields_do_not_open_private_attributes(tmp_path, native, expression):
    actual = probe(
        tmp_path,
        native,
        f"state.set('pending')\nreturn {expression}",
        "state = Variable()\n",
        {"con_format_target": "@export\ndef visible():\n    return 1\n"},
    )
    assert actual["status_code"] == 1, actual
    assert actual["writes"] == encode({})


@pytest.mark.parametrize("native", ENGINES, ids=["python", "native"])
def test_private_decimal_implementation_is_not_an_import_surface(tmp_path, native):
    actual = run_case(
        {
            "id": "format_private_module",
            "source": "import _pydecimal\n@export\ndef probe():\n    return 1\n",
        },
        tmp_path,
        native=native,
    )
    assert actual["admission"] == "rejected", actual


@pytest.mark.parametrize("warm", [False, True], ids=["cold", "fallback_preloaded"])
@pytest.mark.parametrize("spec", ["#.2f", "_.2f"])
def test_python_decimal_rejection_does_not_depend_on_import_cache(tmp_path, warm, spec):
    import json
    import os
    import subprocess
    import sys
    from pathlib import Path

    program = """import json, sys
from pathlib import Path
if sys.argv[1] == 'warm':
    import decimal
    try:
        format(decimal.Decimal('1.25'), sys.argv[2])
    except ValueError:
        pass
from tests.compatibility.runner import run_case
source = '@export\\ndef probe():\\n    return format(round(decimal("1.25"), 2), ' + repr(sys.argv[2]) + ')\\n'
result = run_case({'id':'isolated_decimal_policy', 'source':source}, Path(sys.argv[3]))
print(json.dumps(result))
"""
    completed = subprocess.run(
        [sys.executable, "-c", program, "warm" if warm else "cold", spec, str(tmp_path / "state")],
        cwd=Path(__file__).resolve().parents[2],
        env=dict(os.environ, HOME=str(tmp_path)),
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    actual = json.loads(completed.stdout)
    assert actual["admission"] == "accepted", actual
    assert actual["status_code"] == 1, actual
    assert "invalid or unsupported format specification" in actual["diagnostic"], actual
    assert actual["writes"] == encode({})


@pytest.mark.parametrize("native", ENGINES, ids=["python", "native"])
@pytest.mark.parametrize("route", ["render", "positional", "mapping"])
@pytest.mark.parametrize("spec,expected", [("z.2f", "0.00"), ("#.2f", None), ("_.2f", None)])
def test_imported_public_format_aliases_use_same_policy(tmp_path, native, route, spec, expected):
    dependency = """render = format
positional = str.format
mapping = str.format_map
@export
def anchor():
    return 1
"""
    calls = {
        "render": "module.render(value, spec)",
        "positional": "module.positional('{0:' + spec + '}', value)",
        "mapping": "module.mapping('{value:' + spec + '}', {'value':value})",
    }
    actual = probe(
        tmp_path,
        native,
        "module = importlib.import_module('con_format_aliases')\n"
        "value = round(decimal('-0.004'), 3)\n"
        f"spec = {spec!r}\nreturn " + calls[route],
        dependencies={"con_format_aliases": dependency},
    )
    if expected is None:
        assert actual["status_code"] == 1, actual
        assert any(
            text in actual["diagnostic"]
            for text in (
                "invalid or unsupported format specification",
                "invalid decimal operation or range",
            )
        ), actual
        assert actual["writes"] == encode({})
    else:
        assert actual["status_code"] == 0, actual
        assert actual["result"] == encode(expected)


@pytest.mark.parametrize("native", ENGINES, ids=["python", "native"])
def test_guarded_format_callable_identity_preserves_method_behavior(tmp_path, native):
    actual = probe(
        tmp_path,
        native,
        "template = '{0}'\nheld = template.format\n"
        "return [format is format, str.format is str.format, "
        "str.format_map is str.format_map, template.format is template.format, "
        "template.format == template.format, held is held]",
    )
    assert actual["status_code"] == 0, actual
    assert actual["result"] == encode([True, True, True, False, True, True])


def execute_format_call(driver, function, native):
    from xian_runtime_types.time import Datetime

    name = "con_format_rollback"
    context = dict(
        signer="alice",
        caller="alice",
        this=name,
        owner=None,
        entry=(name, function),
        now=Datetime(2026, 11, 3),
    )
    if native:
        from xian_vm_core import execute_contract

        result = execute_contract(
            driver=driver,
            contract_name=name,
            function_name=function,
            kwargs={},
            context=context,
            meter=False,
            vm_profile=driver.vm_profile,
        )
        return result.status_code, result.result, result.writes, result.events
    from contracting.execution.executor import Executor

    result = Executor(driver=driver, metering=False).execute(
        sender="alice",
        contract_name=name,
        function_name=function,
        kwargs={},
        environment=context,
        metering=False,
    )
    return result["status_code"], result["result"], result["writes"], result["events"]


@pytest.mark.parametrize("native", ENGINES, ids=["python", "native"])
def test_failed_format_rolls_back_event_and_state_then_followup_succeeds(tmp_path, native):
    from contracting.storage.driver import Driver

    source = """state = Variable()
Changed = LogEvent('Changed', {'value': {'type': int}})
@export
def fail():
    state.set(99)
    Changed({'value':99})
    render = '{0:#.2f}'.format
    return render(round(decimal('1.25'), 2))
@export
def recover():
    return [state.get(), format(round(decimal('-0.004'), 3), 'z.2f')]
"""
    with Driver(storage_home=tmp_path, vm_profile="xian_vm_v1") as driver:
        driver.set_contract_from_source("con_format_rollback", source, owner=None)
        driver.set("con_format_rollback.state", 7)
        driver.commit()
        status, diagnostic, writes, events = execute_format_call(driver, "fail", native)
        assert status == 1, diagnostic
        assert writes == {} and events == []
        assert driver.get("con_format_rollback.state") == 7
        status, result, writes, events = execute_format_call(driver, "recover", native)
        assert status == 0, result
        assert result == [7, "0.00"]
        assert writes == {} and events == []
