"""Historical decimal formatting is exercised through the retained native V1 VM."""

import pytest

from contracting.storage.driver import Driver


def execute_expression(tmp_path, expression):
    from xian_vm_core import execute_contract

    source = "state = Variable()\n@export\ndef probe():\n    state.set('pending')\n"
    source += f"    return {expression}\n"
    with Driver(storage_home=tmp_path, vm_profile="xian_vm_v1") as driver:
        driver.set_contract_from_source("con_decimal_format", source, owner=None)
        driver.commit()
        output = execute_contract(
            driver=driver,
            contract_name="con_decimal_format",
            function_name="probe",
            kwargs={},
            context={"caller": "alice", "signer": "alice", "this": "con_decimal_format"},
            meter=False,
            vm_profile="xian_vm_v1",
        )
        if output.status_code:
            assert output.writes == {}
            assert output.events == []
            assert driver.get_var("con_decimal_format", "state") is None
        return output


@pytest.mark.parametrize(
    "value, places, specification, expected",
    [
        ("-0.001", 3, "z.2f", "0.00"),
        ("-0.001", 3, "010,.2f", "-00,000.00"),
        ("-0.001", 3, "#>8.2f", "###-0.00"),
        ("-0.001", 3, "_>8.2f", "___-0.00"),
        ("-0.001", 3, "🦊>8.2f", "🦊🦊🦊-0.00"),
        ("-0.001", 3, "*>010.2f", "-000000.00"),
        ("1234.50", 2, "n", "1234.50"),
        ("1.23456", 5, ".3f", "1.234"),
        ("-0.00", 2, "+z.2f", "+0.00"),
    ],
)
def test_native_decimal_format_policy(tmp_path, value, places, specification, expected):
    output = execute_expression(
        tmp_path, f"format(round(decimal({value!r}), {places}), {specification!r})"
    )
    assert output.status_code == 0, output.result
    assert output.result == expected


@pytest.mark.parametrize("value", ["-NaN42", "Infinity"])
def test_native_profile_rejects_nonfinite_decimal_inputs(tmp_path, value):
    output = execute_expression(tmp_path, f"round(decimal({value!r}), 0)")
    assert output.status_code == 1
    assert "invalid decimal literal" in str(output.result)


@pytest.mark.parametrize("specification", ["#.0f", "z#.0f", "_.2f", ".2_f", ",n", ".f", "١f"])
def test_invalid_native_decimal_grammar(tmp_path, specification):
    output = execute_expression(tmp_path, f"format(round(decimal('-0.001'), 3), {specification!r})")
    assert output.status_code == 1, output.result


@pytest.mark.parametrize("specification", ["131073f", "🦊>32770f", ".131072f", "9" * 100 + "f"])
def test_limits_precede_decimal_padding(tmp_path, specification):
    output = execute_expression(tmp_path, f"format(round(decimal('1'), 0), {specification!r})")
    assert output.status_code == 1, output.result


@pytest.mark.parametrize(
    "expression",
    [
        "len(format(round(decimal('1'), 0), '131072f'))",
        "len('{0}{0}'.format('a' * 65536))",
        "len(format('x', '131072s'))",
    ],
)
def test_exact_scalar_and_aggregate_allocation_limit(tmp_path, expression):
    output = execute_expression(tmp_path, expression)
    assert output.status_code == 0, output.result
    assert output.result == 131072


@pytest.mark.parametrize(
    "expression",
    [
        "'{0}{0}'.format('a' * 65537)",
        "format('x', '131073s')",
    ],
)
def test_aggregate_and_scalar_excess_roll_back(tmp_path, expression):
    output = execute_expression(tmp_path, expression)
    assert output.status_code == 1, output.result


@pytest.mark.parametrize(
    "expression",
    [
        "'{x:z.2f}'.format(x=round(decimal('-0.001'), 3))",
        "str.format('{x:z.2f}', x=round(decimal('-0.001'), 3))",
        "'{x:z.2f}'.format_map({'x': round(decimal('-0.001'), 3)})",
        "str.format_map('{x:z.2f}', {'x': round(decimal('-0.001'), 3)})",
    ],
)
def test_bound_and_unbound_template_routes_use_same_policy(tmp_path, expression):
    output = execute_expression(tmp_path, expression)
    assert output.status_code == 0, output.result
    assert output.result == "0.00"


def test_nested_format_lookup_and_conversion(tmp_path):
    expression = "'{x[0]:{width}.2f}|{x[0]!s}'.format(x=[round(decimal('-0.001'), 3)], width=7)"
    output = execute_expression(tmp_path, expression)
    assert output.status_code == 0, output.result
    assert output.result == "  -0.00|-0.001"


@pytest.mark.parametrize(
    "expression",
    [
        "'{x.__class__}'.format(x=round(decimal('1'), 0))",
        "str.format()",
        "str.format(7)",
        "'{x}'.format_map({}, {})",
        "'{x}'.format_map(mapping={'x': 1})",
        "'{} {0}'.format(1)",
        "'{0}'.format_map({0: 1})",
    ],
)
def test_format_arity_numbering_and_private_lookup_guards(tmp_path, expression):
    output = execute_expression(tmp_path, expression)
    assert output.status_code == 1, output.result


@pytest.mark.parametrize(
    "expression, expected",
    [
        ("f'{round(decimal(\"-0.001\"), 3)!s:>9}'", "   -0.001"),
        ("f'{\"é\"!a}'", "'\\xe9'"),
        ("f'{round(decimal(\"-0.001\"), 3):z.2f}'", "0.00"),
    ],
)
def test_fstring_conversion_uses_string_formatting_after_conversion(tmp_path, expression, expected):
    output = execute_expression(tmp_path, expression)
    assert output.status_code == 0, output.result
    assert output.result == expected


@pytest.mark.parametrize("value, specification", [("1", "🦊>32769f"), ("-1", "🦊>32770f")])
def test_utf8_padding_counts_body_and_sign_before_allocation(tmp_path, value, specification):
    output = execute_expression(
        tmp_path, f"format(round(decimal({value!r}), 0), {specification!r})"
    )
    assert output.status_code == 1, output.result
