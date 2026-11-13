"""Check that every operation family costs about as much CPU time per chi.

Each probe repeats one operation in a contract loop. The script runs the
probe with zero and with `reps` repetitions, takes the best of several runs,
and divides the extra wall time by the extra chi. Baseline probes do plain
interpreter work (loops, arithmetic, calls, small containers, storage). A
probe fails when its time per chi exceeds `--max-ratio` times the median of
the baselines measured in the same run, so the check does not depend on the
speed of the machine.

Usage: uv run python scripts/metering_calibration.py [--max-ratio 8] [--json]
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

HELPER = "con_cal_helper"
SIGNER = "calibrator"
# The VM caps one transaction at its own ceiling; probes stay far below it.
PROBE_CHI = 1_000_000
# A probe repeats its operation until the extra time reaches this, so the
# per-transaction overhead and scheduling noise do not dominate.
TARGET_SECONDS = 0.02
GROWTH = 4
MAX_SCALE = 256

HELPER_SOURCE = """
data = Hash(default_value=0)

@export
def ping(x: Any):
    return 1
"""


@dataclass(frozen=True)
class Probe:
    name: str
    family: str
    setup: tuple[str, ...]
    op: tuple[str, ...]
    reps: int
    scalable: bool = True

    @property
    def baseline(self) -> bool:
        return self.family == "baseline"


def statements(text: str) -> tuple[str, ...]:
    """Split `a; b` into lines; a line ending in `:` indents the lines after it."""
    lines, indent = [], ""
    for line in filter(None, text.split("; ")):
        lines.append(indent + line)
        if line.endswith(":"):
            indent += "    "
    return tuple(lines)


def probe(name: str, family: str, setup: str, op: str, reps: int, scalable=True) -> Probe:
    return Probe(name, family, statements(setup), statements(op), reps, scalable)


LONG = "s = 'a' * 100000; t = 'a' * 99999 + 'b'"
BYTES = LONG + "; b = s.encode()"
LONG_LIST = "base = 'a' * 20000; l = [base + str(j % 10) for j in range(50)]"
HELPER_IMPORT = f"h = importlib.import_module('{HELPER}')"

PROBES: tuple[Probe, ...] = (
    # Plain interpreter work: the reference the other families are held to.
    probe("loop_pass", "baseline", "", "pass", 20000),
    probe("arith", "baseline", "x = 0", "x = (x * 3 + 7) % 1000003", 20000),
    probe("calls", "baseline", "x = 0", "x = ident(x)", 10000),
    probe("decimal", "baseline", "y = decimal('1.5'); d = decimal('0.999')", "y = y * d", 10000),
    probe("small_list", "baseline", "", "l = [1, 2, 3]; l.append(4); x = l[-1]", 10000),
    probe("small_dict", "baseline", "", "d = {'a': 1, 'b': 2}; x = d['b']", 10000),
    probe("small_str", "baseline", "", "x = len(('con_' + str(rep)).upper())", 10000),
    probe(
        "storage", "baseline", "", "store[rep % 50] = rep; x = store[(rep + 1) % 50]", 3000, False
    ),
    # (a) values crossing a contract boundary.
    probe("xcall_list", "boundary", f"{HELPER_IMPORT}; l = list(range(20000))", "h.ping(l)", 10),
    probe(
        "xcall_nested",
        "boundary",
        f"{HELPER_IMPORT}; l = [list(range(100)) for j in range(200)]",
        "h.ping(l)",
        10,
    ),
    probe(
        "xcall_dict",
        "boundary",
        f"{HELPER_IMPORT}; d = {{str(j): j for j in range(500)}}",
        "h.ping(d)",
        10,
    ),
    # (b) string operations that scan the whole string.
    *(
        probe(f"str_{method}", "string", LONG, f"x = s.{method}()", 10)
        for method in (
            "upper",
            "lower",
            "casefold",
            "capitalize",
            "swapcase",
            "title",
            "isalpha",
            "isdigit",
            "islower",
            "isupper",
            "isalnum",
            "isascii",
            "isspace",
            "isdecimal",
            "isnumeric",
            "isidentifier",
            "isprintable",
            "istitle",
            "strip",
            "split",
            "rsplit",
            "splitlines",
        )
    ),
    probe("str_find", "string", LONG, "x = s.find('b')", 10),
    probe("str_rfind", "string", LONG, "x = s.rfind('b')", 10),
    probe("str_count", "string", LONG, "x = s.count('a')", 10),
    probe("str_in", "string", LONG, "x = 'b' in s", 10),
    probe("str_in_long", "string", LONG + "; k = 'a' * 50000 + 'b'", "x = k in s", 10),
    probe("str_startswith", "string", LONG, "x = s.startswith(t)", 10),
    probe("str_endswith", "string", LONG, "x = t.endswith(s)", 10),
    probe("str_replace", "string", LONG, "x = s.replace('a', 'b')", 10),
    probe("str_split_sep", "string", "s = 'ab ' * 30000", "x = s.split(' ')", 10),
    probe("str_split_ws", "string", "s = 'ab ' * 30000", "x = s.split()", 10),
    probe("str_join", "string", "l = ['ab'] * 30000", "x = ' '.join(l)", 10),
    probe("str_partition", "string", LONG, "x = s.partition('b')", 10),
    probe("str_lstrip", "string", LONG, "x = s.lstrip('b')", 10),
    probe("str_zfill", "string", LONG, "x = s.zfill(100001)", 10),
    probe("str_encode", "string", LONG, "x = s.encode()", 10),
    probe("str_slice", "string", LONG, "x = s[1:]", 10),
    probe("str_slice_step", "string", LONG, "x = s[::2]", 10),
    probe("str_reverse", "string", LONG, "x = s[::-1]", 10),
    probe("str_index_char", "string", LONG, "x = s[99999]", 10),
    probe("str_iter", "string", "s = 'a' * 2000", "for c in s:; pass", 10),
    probe("str_len", "string", LONG, "x = len(s)", 10),
    probe("str_concat", "string", LONG, "x = s + 'b'", 10),
    probe("str_mul", "string", "w = 'a' * 60000", "x = w * 2", 10),
    probe("str_fstring", "string", "w = 'a' * 60000", "x = f'{w}{w}'", 10),
    probe("str_decimal", "string", "u = '0' * 100000 + '1'", "x = decimal(u)", 10),
    probe("str_int", "string", "u = '0' * 8000 + '1'", "x = int(u)", 10),
    probe("str_sha3", "string", LONG, "x = hashlib.sha3(s)", 10),
    probe("bytes_in_long", "string", BYTES + "; k = b'a' * 50000 + b'b'", "x = k in b", 10),
    probe("bytes_find", "string", BYTES, "x = b.find(b'b')", 10),
    probe("bytes_eq", "compare", BYTES + "; c = bytes(s, 'utf-8')", "x = b == c", 10),
    # (c) equality and ordering of long strings, alone and inside containers.
    probe("str_eq", "compare", LONG + "; u = 'a' * 100000", "x = s == u", 10),
    probe("str_lt", "compare", LONG, "x = s < t", 10),
    probe("list_eq_longstr", "compare", LONG_LIST + "; m = list(l)", "x = l == [*m]", 10),
    probe("list_in_longstr", "compare", LONG_LIST + "; k = base + 'x'", "x = k in l", 10),
    probe("list_count_longstr", "compare", LONG_LIST + "; k = base + '9'", "x = l.count(k)", 10),
    probe("sorted_longstr", "compare", LONG_LIST, "x = sorted(l)", 10),
    probe("dict_longkey", "compare", LONG_LIST + "; d = {k: 1 for k in l}", "x = d[l[-1]]", 10),
    # (d) whole-hash storage scans.
    probe("hash_all", "storage_scan", "", "x = len(seeded.all())", 5),
    probe("hash_all_prefix", "storage_scan", "", "x = len(seeded.all('k1'))", 5),
    probe("hash_clear", "storage_scan", "", "scratch.clear()", 5),
    probe("hash_clone_from", "storage_scan", "", "scratch.clone_from(seeded)", 1, False),
    # Container work priced by revision 10, kept from regressing. Setups stay
    # small: an in-memory dictionary build is quadratic, and a slow setup
    # makes the zero-repetition run noisy.
    probe("list_eq", "container", "l = list(range(20000)); m = list(l)", "x = l == m", 10),
    probe("list_in", "container", "l = list(range(20000))", "x = -1 in l", 10),
    probe("list_index", "container", "l = list(range(20000))", "x = l.index(19999)", 10),
    probe("list_sorted", "container", "l = list(range(20000))", "x = sorted(l)", 10),
    probe("list_copy", "container", "l = list(range(20000))", "x = list(l)", 10),
    probe("list_slice", "container", "l = list(range(20000))", "x = l[::-1]", 10),
    probe("list_concat", "container", "l = list(range(20000))", "x = l + l", 10),
    probe("list_str", "container", "l = list(range(5000))", "x = str(l)", 10),
    probe("list_sum", "container", "l = list(range(20000))", "x = sum(l) + max(l)", 10),
    probe("list_insert0", "container", "l = list(range(20000))", "l.insert(0, 1)", 50),
    probe("dict_build", "container", "", "d = {str(j): j for j in range(300)}", 10),
    probe(
        "dict_lookup",
        "container",
        "d = {str(j): j for j in range(500)}; k = str(499)",
        "x = d[k]",
        500,
    ),
    probe("set_ops", "container", "a = set(range(500)); b = set(range(250, 750))", "x = a & b", 10),
)

SEEDED_ENTRIES = 1500
PREAMBLE = (
    "store = Hash(default_value=0)",
    "seeded = Hash(default_value=0)",
    "scratch = Hash(default_value=0)",
    "",
    "def ident(a):",
    "    return a",
    "",
    "@export",
    "def seed(count: int):",
    "    for j in range(count):",
    "        seeded['k' + str(j)] = j",
    "",
)


def contract_name(item: Probe) -> str:
    return f"con_{item.name}"


def probe_source(item: Probe) -> str:
    """One small contract per probe keeps the fixed per-call overhead low."""
    lines = [*PREAMBLE, "@export", "def run(n: int):"]
    lines += [f"    {line}" for line in item.setup]
    lines += ["    for rep in range(n):"]
    lines += [f"        {line}" for line in item.op]
    lines += ["    return 1", ""]
    return "\n".join(lines)


@dataclass(frozen=True)
class Measurement:
    probe: Probe
    chi_per_op: float
    us_per_op: float

    @property
    def us_per_chi(self) -> float:
        return self.us_per_op / max(self.chi_per_op, 1e-9)


class ProbeFailure(RuntimeError):
    pass


class ProbeRunner:
    def __init__(self, client, repeat: int) -> None:
        self.client = client
        self.repeat = repeat

    def call(self, contract: str, n: int) -> tuple[int, float]:
        started = time.perf_counter()
        output = self.client.executor.execute(
            sender=SIGNER,
            contract_name=contract,
            function_name="run",
            kwargs={"n": n},
            metering=True,
            chi=PROBE_CHI,
        )
        elapsed = time.perf_counter() - started
        if output["status_code"]:
            raise ProbeFailure(f"{contract}(n={n}) failed: {output['result']!r:.300}")
        return int(output["chi_used"]), elapsed

    def measure(self, item: Probe) -> Measurement:
        """Repeat the operation until its own time dominates timing noise.

        Growth stops at the first run that hits a per-transaction resource
        limit; the last completed run is the measurement.
        """
        contract = contract_name(item)
        empty_chi, empty_time = self.best(contract, 0)
        reps, measurement = item.reps, None
        while True:
            try:
                full_chi, full_time = self.best(contract, reps)
            except ProbeFailure:
                if measurement is None:
                    raise
                return measurement
            measurement = Measurement(
                probe=item,
                chi_per_op=(full_chi - empty_chi) / reps,
                us_per_op=(full_time - empty_time) * 1e6 / reps,
            )
            if not self.should_grow(item, reps, full_chi, full_time - empty_time):
                return measurement
            reps *= GROWTH

    @staticmethod
    def should_grow(item: Probe, reps: int, chi: int, elapsed: float) -> bool:
        return (
            item.scalable
            and elapsed < TARGET_SECONDS
            and reps * GROWTH <= item.reps * MAX_SCALE
            and chi * GROWTH < PROBE_CHI
        )

    def best(self, contract: str, n: int) -> tuple[int, float]:
        runs = [self.call(contract, n) for _ in range(self.repeat)]
        return runs[0][0], min(elapsed for _, elapsed in runs)


def evaluate(results: list[Measurement], max_ratio: float) -> tuple[float, list[str]]:
    """Return the baseline median and a failure line for every slow probe."""
    reference = statistics.median(m.us_per_chi for m in results if m.probe.baseline)
    failures = [
        f"{m.probe.name} ({m.probe.family}): {m.us_per_chi:.2f} us/chi = "
        f"{m.us_per_chi / reference:.1f}x the baseline median {reference:.2f}"
        for m in results
        if not m.probe.baseline and m.us_per_chi > max_ratio * reference
    ]
    return reference, failures


def open_client(home: Path, probes):
    os.environ["HOME"] = str(home)
    from contracting import constants
    from contracting.local import ContractingClient

    constants.STORAGE_HOME = home / ".cometbft" / "xian"
    client = ContractingClient(signer=SIGNER)
    client.flush()
    client.submit(HELPER_SOURCE, name=HELPER)
    for item in probes:
        client.submit(probe_source(item), name=contract_name(item))
        if item.family == "storage_scan":
            client.executor.execute(
                sender=SIGNER,
                contract_name=contract_name(item),
                function_name="seed",
                kwargs={"count": SEEDED_ENTRIES},
                metering=False,
                auto_commit=True,
            )
    return client


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--max-ratio", type=float, default=8.0)
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--only", default="", help="comma-separated probe names")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    selected = {name for name in args.only.split(",") if name}
    probes = [p for p in PROBES if not selected or p.name in selected or p.baseline]
    with tempfile.TemporaryDirectory(prefix="xian-metering-calibration-") as home:
        client = open_client(Path(home), probes)
        try:
            runner = ProbeRunner(client, args.repeat)
            results = [runner.measure(item) for item in probes]
        finally:
            client.close()
    reference, failures = evaluate(results, args.max_ratio)
    if args.json:
        print(json.dumps(report(results, reference), indent=1))
    else:
        for m in sorted(results, key=lambda m: -m.us_per_chi):
            print(
                f"{m.probe.name:20} {m.probe.family:12} chi/op={m.chi_per_op:10.1f} "
                f"us/op={m.us_per_op:10.1f} us/chi={m.us_per_chi:8.2f} "
                f"ratio={m.us_per_chi / reference:6.2f}"
            )
        print(f"baseline median: {reference:.3f} us/chi; max ratio {args.max_ratio}")
    for line in failures:
        print(f"UNDER-PRICED {line}", file=sys.stderr)
    return 1 if failures else 0


def report(results: list[Measurement], reference: float) -> dict:
    return {
        "baseline_median_us_per_chi": reference,
        "probes": {
            m.probe.name: {
                "family": m.probe.family,
                "chi_per_op": m.chi_per_op,
                "us_per_op": m.us_per_op,
                "us_per_chi": m.us_per_chi,
                "ratio": m.us_per_chi / reference,
            }
            for m in results
        },
    }


if __name__ == "__main__":
    raise SystemExit(main())
