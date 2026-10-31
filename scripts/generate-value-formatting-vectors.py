"""Independent CPython 3.12.10 format observations; deterministic seeded inputs."""

import argparse
import json
import math
import random
import struct
import sys
from pathlib import Path

assert sys.version_info[:3] == (3, 12, 10), sys.version
specs = [
    "",
    ".0f",
    ".2f",
    ".17g",
    ".6g",
    ".2e",
    "+.6E",
    "#.0f",
    "#.4g",
    "020,.2f",
    "_.2f",
    "z.2f",
    ".2%",
    ".4",
    ">18.7g",
    "*^24.5g",
    "n",
    "+08F",
    "#",
    "0=+20.3f",
    "020,.2e",
    "010_g",
    "z.0g",
    " >018.2f",
    "*>018.2f",
    "^018.2f",
    "#.0g",
    ".0",
    "_.0%",
    "+z.0e",
]
values = [
    0.0,
    -0.0,
    1.0,
    -1.0,
    2.675,
    2.5,
    3.5,
    1e-4,
    1e-5,
    1e15,
    1e16,
    999.5,
    9.995,
    1.7976931348623157e308,
    5e-324,
    math.inf,
    -math.inf,
    math.nan,
]
rng = random.Random(81025)
values += [struct.unpack(">d", rng.randbytes(8))[0] for _ in range(96)]
rows = []
for value in values:
    for spec in specs:
        rows.append(
            {
                "kind": "float",
                "value": struct.pack(">d", value).hex(),
                "spec": spec,
                "result": format(value, spec),
            }
        )
for value in [0, 1, -1, 42, -255, 0xDEADBEEF, 10**30, 2**255 - 1]:
    for spec in [
        "",
        "d",
        "+08d",
        "_d",
        ",d",
        "010,d",
        "#010_x",
        "#_b",
        "#o",
        "^40X",
        ".2f",
        ".6g",
        "0=+14d",
        "n",
        " >08d",
        "*>08d",
        "^08d",
        "0=10,d",
        "020_x",
        "020_b",
    ]:
        rows.append(
            {"kind": "int", "value": str(value), "spec": spec, "result": format(value, spec)}
        )
for value in ["", "a", "猫é", "abc\n", "e\u0301"]:
    for spec in ["", "s", "05", "^8", "*^9", ".1s", ">6.2s", "0<6s", " <08s", ">08s", "猫^10.3s"]:
        rows.append({"kind": "str", "value": value, "spec": spec, "result": format(value, spec)})
output = (
    Path(__file__).resolve().parents[1]
    / "packages/xian-vm-core/tests/vectors/value_formatting.json"
)
rendered = (
    json.dumps({"python": "3.12.10", "seed": 81025, "vectors": rows}, ensure_ascii=True, indent=2)
    + "\n"
)
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--check", action="store_true")
arguments = parser.parse_args()
if arguments.check:
    assert output.read_text() == rendered, "historical formatting vectors differ"
else:
    output.write_text(rendered)
print(f"Verified {len(rows)} historical formatting vectors")
