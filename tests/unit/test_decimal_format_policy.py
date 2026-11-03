from decimal import ROUND_DOWN, Decimal, localcontext

import pytest

from contracting.execution.decimal_format_policy import format_decimal


@pytest.mark.parametrize(
    "value,specification,expected",
    [
        ("-0.001", "z.2f", "0.00"),
        ("-0.001", "010,.2f", "-00,000.00"),
        ("-0.001", "#>8.2f", "###-0.00"),
        ("-0.001", "_>8.2f", "___-0.00"),
        ("-0.001", "🦊>8.2f", "🦊🦊🦊-0.00"),
        ("-0.001", "*>010.2f", "-000000.00"),
        ("1234.50", "n", "1234.50"),
        ("1.23456", ".3f", "1.234"),
        ("-NaN42", "+010f", "    -NaN42"),
        ("Infinity", "010%", " Infinity%"),
        ("-0.00", "+z.2f", "+0.00"),
    ],
)
def test_native_decimal_format_policy(value, specification, expected):
    with localcontext() as context:
        context.rounding = ROUND_DOWN
        assert format_decimal(Decimal(value), specification) == expected


@pytest.mark.parametrize("specification", ["#.0f", "z#.0f", "_.2f", ".2_f", ",n", ".f", "١f"])
def test_invalid_native_decimal_grammar(specification):
    with pytest.raises(ValueError, match="format specification"):
        format_decimal(Decimal("-0.001"), specification)


def test_limits_precede_decimal_padding():
    assert len(format_decimal(Decimal("1"), "131072f")) == 131072
    for specification in ["131073f", "🦊>32770f", ".131072f", "9" * 100 + "f"]:
        with pytest.raises(ValueError):
            format_decimal(Decimal("1"), specification)


@pytest.mark.parametrize("method", ["format", "format_map"])
def test_guarded_string_aliases_and_class_identity(method):
    from contracting.execution.format_policy import format_attribute

    template = "{x:z.2f}"
    first = format_attribute(template, method)
    second = format_attribute(template, method)
    assert first is not second
    assert first == second
    assert hash(first) == hash(second)
    unbound = format_attribute(str, method)
    assert unbound is format_attribute(str, method)
    arguments = {"x": Decimal("-0.001")}
    if method == "format":
        assert first(**arguments) == unbound(template, **arguments) == "0.00"
    else:
        assert first(arguments) == unbound(template, arguments) == "0.00"


def test_nested_format_lookup_and_conversion():
    from contracting.execution.format_policy import format_attribute

    output = format_attribute("{x[0]:{width}.2f}|{x[0]!s}", "format")(
        x=[Decimal("-0.001")], width=7
    )
    assert output == "  -0.00|-0.001"
    with pytest.raises(AttributeError):
        format_attribute("{x.__class__}", "format")(x=Decimal("1"))


def test_format_allocation_and_map_lookup_count():
    from contracting.execution.format_policy import format_attribute

    seen = []

    class Mapping:
        def __getitem__(self, key):
            seen.append(key)
            return Decimal("-0.001")

    assert format_attribute("{x:z.2f}", "format_map")(Mapping()) == "0.00"
    assert seen == ["x"]
    with pytest.raises(ValueError, match="allocation limit"):
        format_attribute("{0}{0}", "format")("a" * 65537)


def test_exact_aggregate_limit_and_scalar_limit():
    from contracting.execution.format_policy import contract_format, format_attribute

    assert len(format_attribute("{0}{0}", "format")("a" * 65536)) == 131072
    assert len(contract_format("x", "131072s")) == 131072
    with pytest.raises(ValueError, match="allocation limit"):
        contract_format("x", "131073s")


def test_callable_arity_and_numbering_guards():
    from contracting.execution.format_policy import format_attribute

    with pytest.raises(TypeError):
        format_attribute(str, "format")()
    with pytest.raises(TypeError):
        format_attribute(str, "format")(7)
    with pytest.raises(TypeError):
        format_attribute("{x}", "format_map")({}, {})
    with pytest.raises(TypeError):
        format_attribute("{x}", "format_map")(mapping={"x": 1})
    with pytest.raises(ValueError):
        format_attribute("{} {0}", "format")(1)
    with pytest.raises(ValueError):
        format_attribute("{0}", "format_map")({0: 1})


def test_fstring_conversion_uses_string_formatting_after_conversion():
    from contracting.execution.format_policy import format_fstring

    assert format_fstring(Decimal("-0.001"), ">9", ord("s")) == "   -0.001"
    assert format_fstring("é", "", ord("a")) == "'\\xe9'"
    assert format_fstring(Decimal("-0.001"), "z.2f") == "0.00"


@pytest.mark.parametrize("value,specification", [("1", "🦊>32769f"), ("-1", "🦊>32770f")])
def test_utf8_padding_counts_body_and_sign_before_allocation(value, specification):
    with pytest.raises(ValueError, match="allocation limit"):
        format_decimal(Decimal(value), specification)
