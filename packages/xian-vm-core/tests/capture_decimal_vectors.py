#!/usr/bin/env python3
"""Capture the pinned historical Decimal oracle without invoking the Rust VM."""

import argparse
import decimal
import hashlib
import json
import random
import sys
from pathlib import Path

CONTEXT_SEED = 71031
POWER_SEED = 171031
CONTEXT_OPERATIONS = (
    ("add", 2),
    ("sub", 2),
    ("mul", 2),
    ("div", 2),
    ("divint", 2),
    ("rem", 2),
    ("pow", 2),
    ("sqrt", 1),
    ("exp", 1),
    ("ln", 1),
    ("log10", 1),
    ("plus", 1),
    ("minus", 1),
    ("abs", 1),
    ("normalize", 1),
    ("compare", 2),
    ("compare_signal", 2),
    ("compare_total", 2),
    ("compare_total_mag", 2),
    ("max", 2),
    ("min", 2),
    ("max_mag", 2),
    ("min_mag", 2),
    ("next_plus", 1),
    ("next_minus", 1),
    ("next_toward", 2),
    ("quantize", 2),
    ("scaleb", 2),
    ("shift", 2),
    ("rotate", 2),
    ("logical_and", 2),
    ("logical_or", 2),
    ("logical_xor", 2),
    ("logical_invert", 1),
    ("fma", 3),
    ("remainder_near", 2),
    ("copy_abs", 1),
    ("copy_negate", 1),
    ("copy_sign", 2),
    ("logb", 1),
    ("to_integral_value", 1),
    ("to_integral_exact", 1),
)
CONTEXT_NAMES = {
    "sub": "subtract",
    "mul": "multiply",
    "div": "divide",
    "divint": "divide_int",
    "rem": "remainder",
    "pow": "power",
}


def context_inputs():
    """Preserve the original deterministic sampling order and 24 cases per op."""
    rng = random.Random(CONTEXT_SEED)
    values = [
        "0",
        "-0.000",
        "1",
        "-1",
        "Infinity",
        "-Infinity",
        "NaN",
        "-NaN123",
        "sNaN9",
        "0.5",
        "1E100",
        "1E-190",
        "1E-1074",
        "1.0000000000000000000000000000000000000001",
    ]
    values.extend(f"{rng.randint(-(10**20), 10**20)}E{rng.randint(-210, 100)}" for _ in range(30))
    for operation, arity in CONTEXT_OPERATIONS:
        for _ in range(24):
            yield operation, rng.choices(values, k=arity)


def power_inputs():
    """Add finite fractional powers and near-one/long-coefficient probes."""
    rng = random.Random(POWER_SEED)
    for _ in range(1200):
        base = f"{rng.randint(1, 10**20)}E-20"
        exponent = f"{rng.randint(-10000, 10000)}E-3"
        yield "pow", [base, exponent]
    for places in (1, 10, 50, 90, 120, 512, 1074):
        base = "1." + "0" * (places - 1) + "1"
        for exponent in ("0.5", "0.123", "1.2345", "-3.14159", "1E50"):
            yield "pow", [base, exponent]
        for operation in ("sqrt", "exp", "ln", "log10"):
            yield operation, [base]


def evaluate(context, operation, arguments):
    function = getattr(context, CONTEXT_NAMES.get(operation, operation))
    try:
        return [0, str(function(*map(decimal.Decimal, arguments)))]
    except decimal.InvalidOperation:
        return [1, ""]
    except decimal.DivisionByZero:
        return [2, ""]
    except decimal.Overflow:
        return [3, ""]


def capture():
    context = decimal.Context(
        prec=91,
        rounding=decimal.ROUND_DOWN,
        Emin=-100,
        Emax=100,
        capitals=1,
        clamp=0,
        traps=[decimal.InvalidOperation, decimal.DivisionByZero, decimal.Overflow],
    )
    vectors = []
    with decimal.localcontext(context) as active:
        for operation, arguments in (*context_inputs(), *power_inputs()):
            # The original corpus excluded precisely five long power operands
            # beyond the final resource cap; other operations retain them.
            if operation == "pow" and any(
                len(decimal.Decimal(value).as_tuple().digits) > 1024 for value in arguments
            ):
                continue
            vectors.append([operation, arguments, evaluate(active, operation, arguments)])
    assert len(vectors) == 2266
    rows = (json.dumps(vector, separators=(",", ":")) for vector in vectors)
    return ("[\n" + ",\n".join(rows) + "\n]\n").encode("ascii")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="compare without writing")
    parser.add_argument(
        "--output", type=Path, default=Path(__file__).with_name("decimal_vectors.json")
    )
    args = parser.parse_args()
    if sys.version_info[:3] != (3, 12, 10) or decimal.__libmpdec_version__ != "4.0.0":
        parser.error("requires historical CPython 3.12.10 with libmpdec 4.0.0")
    captured = capture()
    if args.check:
        if args.output.read_bytes() != captured:
            parser.error("captured oracle differs from the checked-in corpus")
    else:
        args.output.write_bytes(captured)
    print(f"2266 cases; SHA256 {hashlib.sha256(captured).hexdigest()}")


if __name__ == "__main__":
    main()
