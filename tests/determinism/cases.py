"""Bounded generated programs with semantic anchors independent of VM output.

Host generation uses a private seeded RNG and fixed arithmetic contexts. Contract
source templates are fixed; generated data enters only through Python literals.
"""

import datetime
import decimal
import random
import textwrap

DEFAULT_SEED = 0x5849414E
MAX_CASES = 4096


def _probe(body, expected, prefix=""):
    return {
        "source": prefix + "@export\ndef probe():\n" + textwrap.indent(body, "    ") + "\n",
        "expected_result": expected,
    }


def _integers(rng, index):
    bits = rng.choice([1, 31, 53, 64, 127, 255])
    a = rng.getrandbits(bits) * rng.choice([-1, 1])
    b = rng.randint(1, 997) * rng.choice([-1, 1])
    exponent = rng.randrange(1, 13)
    expected = [a + b, a - b, a * b, a // b, a % b, a ^ b, pow(abs(a) % 101, exponent, 103)]
    return _probe(
        f"a = {a!r}\nb = {b!r}\n"
        f"return [a+b, a-b, a*b, a//b, a%b, a^b, pow(abs(a)%101, {exponent}, 103)]",
        expected,
    )


def _aliases(rng, index):
    values = [rng.randint(-50, 50) for _ in range(rng.randrange(1, 9))]
    added = rng.randint(100, 200)
    copied = values + [added]
    final = copied[1:]
    return _probe(
        f"values = {values!r}\nalias = values\nalias.append({added!r})\n"
        "copied = values.copy()\nvalues.pop(0)\n"
        "return [values, copied, alias is values, copied is values, list(reversed(values))]",
        [final, copied, True, False, list(reversed(final))],
    )


def _dictionary_order(rng, index):
    keys = rng.sample(["alpha", "é", "猫", "z", "0", "a:b", "quoted'key", "\\"], 5)
    values = {key: rng.randrange(100) for key in keys}
    replacement = rng.randrange(100, 200)
    final = dict(values)
    final.pop(keys[1])
    final[keys[1]] = replacement
    return _probe(
        f"values = {values!r}\nview = values.keys()\nalias = values\n"
        f"alias.pop({keys[1]!r})\nalias[{keys[1]!r}] = {replacement!r}\n"
        "return [list(view), list(values.values()), [list(item) for item in values.items()], alias is values]",
        [list(final), list(final.values()), [list(item) for item in final.items()], True],
    )


def _set_order(rng, index):
    values = [rng.randint(-20, 20) for _ in range(12)]
    expected = sorted(set(values))
    return _probe(
        f"values = {values!r}\nwrapped = set(values)\nfrozen = frozenset(values)\n"
        "view_set = dict.fromkeys(values).keys() | []\n"
        "return [list(wrapped), list(frozen), list(view_set), list(reversed(sorted(values)))]",
        [list(expected), list(expected), list(expected), list(reversed(sorted(values)))],
    )


def _unicode(rng, index):
    alphabet = ["a", "é", "猫", "ß", "Ω", "🙂", "\n", "'", '"', "\\", "\x00"]
    value = "".join(rng.choice(alphabet) for _ in range(8))
    separator = rng.choice(alphabet[:5])
    return _probe(
        f"value = {value!r}\nseparator = {separator!r}\n"
        "return [len(value), value[::-1], value.encode('utf-8').hex(), "
        "[ord(char) for char in value], value.replace(separator, 'X'), value.split(separator)]",
        [
            len(value),
            value[::-1],
            value.encode().hex(),
            [ord(char) for char in value],
            value.replace(separator, "X"),
            value.split(separator),
        ],
    )


def _numeric(rng, index):
    if index % 2:
        return _raw_decimal(rng)
    numerator = rng.randint(-(1 << 53), 1 << 53)
    value = numerator / (1 << rng.randrange(0, 40))
    literal = value.hex()
    return _probe(
        f"value = float.fromhex({literal!r})\n"
        "return [value.hex(), list(value.as_integer_ratio()), value.is_integer(), format(value, '.6e')]",
        [literal, list(value.as_integer_ratio()), value.is_integer(), format(value, ".6e")],
    )


def _raw_decimal(rng):
    amount = f"{rng.randint(-9999, 9999)}.{rng.randrange(1_000_000):06d}"
    places = rng.randrange(0, 7)
    context = decimal.Context(prec=91, rounding=decimal.ROUND_DOWN, Emin=-100, Emax=100)
    with decimal.localcontext(context):
        value = decimal.Decimal(amount).quantize(decimal.Decimal((0, (1,), -places)))
        expected = [
            str(value),
            list(value.as_tuple().digits),
            value.as_tuple().exponent,
            format(value, ".3f"),
        ]
    return _probe(
        f"value = round(decimal({amount!r}), {places})\nparts = value.as_tuple()\n"
        "return [str(value), list(parts.digits), parts.exponent, format(value, '.3f')]",
        expected,
    )


def _time(rng, index):
    base = rng.choice(
        [
            datetime.datetime(1999, 12, 31),
            datetime.datetime(2000, 2, 28),
            datetime.datetime(2024, 2, 29),
            datetime.datetime(2100, 3, 1),
        ]
    )
    days, seconds = rng.randint(-366, 366), rng.randint(-90000, 90000)
    value = base + datetime.timedelta(days=days, seconds=seconds)
    return _probe(
        f"start = datetime.datetime({base.year}, {base.month}, {base.day})\n"
        f"value = start + datetime.timedelta(days={days}, seconds={seconds})\n"
        "return [str(value), value.year, value.month, value.day, value.hour, value.minute, value.second]",
        [str(value), value.year, value.month, value.day, value.hour, value.minute, value.second],
    )


def _random_stream(rng, index):
    salt = f"seed-{rng.getrandbits(64):016x}"
    values = [rng.randrange(100) for _ in range(9)]
    return _probe(
        f"salt = {salt!r}\nrandom.seed(salt)\nfirst = random.getrandbits(97)\n"
        "random.seed(salt)\nsecond = random.getrandbits(97)\n"
        f"values = {values!r}\nalias = values\nrandom.shuffle(values)\n"
        "stream.set([first, second, values, random.random(), random.choices(values, 3)])\n"
        "return [first == second, alias is values, sorted(values)]",
        [True, True, sorted(values)],
        "stream = Variable()\n",
    )


def _sequence(rng, index):
    values = [rng.randrange(-100, 100) for _ in range(4)]
    source = f"""state = Variable()
items = Hash()
Changed = LogEvent('Changed', {{'value': {{'type': int}}}})
@export
def probe():
    state.set({values!r})
    items['b'] = 2
    items['a'] = 1
    items['removed'] = None
    Changed({{'value': {values[0]!r}}})
    return state.get()
@export
def fail():
    state.set([999])
    items['a'] = 999
    Changed({{'value': 999}})
    assert False, 'forced determinism failure'
@export
def read():
    return [state.get(), items.all()]
"""
    expected = [values, [1, 2]]
    return {
        "source": source,
        "steps": [
            {"function": "probe", "expected_result": values},
            {
                "function": "fail",
                "expected_failure": True,
                "expected_error": "forced determinism failure",
            },
            {"function": "read", "expected_result": expected},
            {
                "function": "probe",
                "expected_failure": True,
                "expected_error": "Out of chi",
                "chi_budget_raw": 1,
            },
            {"function": "read", "expected_result": expected},
        ],
    }


GENERATORS = {
    "integers": _integers,
    "aliases": _aliases,
    "dictionary_order": _dictionary_order,
    "set_order": _set_order,
    "unicode": _unicode,
    "numeric": _numeric,
    "time": _time,
    "random_stream": _random_stream,
    "sequence": _sequence,
}
FAMILIES = tuple(GENERATORS)


def generated_cases(*, seed=DEFAULT_SEED, count=256):
    """Return a deterministic family-interleaved corpus; never consume host RNG."""
    if type(count) is not int or not 0 <= count <= MAX_CASES:
        raise ValueError(f"count must be an integer between 0 and {MAX_CASES}")
    rng = random.Random(seed)
    cases = []
    for index in range(count):
        family = FAMILIES[index % len(FAMILIES)]
        case = GENERATORS[family](rng, index)
        # The numeric and random-stream probes intentionally exercise binary floats.
        profile = "xian_vm_v1" if family in ("numeric", "random_stream") else "xian_vm_v2"
        cases.append(
            {"id": f"generated_{family}_{index:04d}", "family": family, "vm_profile": profile, **case}
        )
    return cases
