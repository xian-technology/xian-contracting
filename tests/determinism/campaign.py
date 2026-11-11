"""Reproducible fresh-process determinism matrix for the native contract runtime."""

import argparse
import decimal
import hashlib
import json
import locale
import os
import platform
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def _child_difference(pairs):
    for left, right, path in pairs:
        difference = first_difference(left, right, path)
        if difference:
            return difference
    return None


def first_difference(left, right, path="$"):
    if type(left) is not type(right):
        return path
    if isinstance(left, dict):
        if left.keys() != right.keys():
            return path + ".keys"
        return _child_difference((left[key], right[key], path + "." + str(key)) for key in left)
    if isinstance(left, list):
        if len(left) != len(right):
            return path + ".length"
        return _child_difference(
            (a, b, f"{path}[{index}]") for index, (a, b) in enumerate(zip(left, right))
        )
    return path if left != right else None


def compare_reports(left, right):
    for key in ("schema", "corpus_sha256", "execution_policy", "observations"):
        if key not in left or key not in right:
            raise AssertionError("Missing report field: " + key)
        difference = first_difference(left[key], right[key], key)
        if difference:
            raise AssertionError("Determinism mismatch at " + difference)
    if not left["observations"]:
        raise AssertionError("Empty observations are not determinism evidence")


def scenarios(seed, *, extended=False):
    base = dict(
        id="baseline",
        hash_seed="0",
        timezone="UTC",
        decimal="default",
        warm=False,
        reverse=False,
        reopen=False,
        optimize="0",
        allocator="pymalloc",
        locale="C",
        poison=False,
    )
    changes = [
        dict(id="hash", hash_seed=str(seed % 4294967295 + 1)),
        dict(id="timezone", timezone="Pacific/Auckland"),
        dict(id="decimal-low", decimal="low"),
        dict(id="warm", warm=True, poison=True),
        dict(id="reverse-reopen", reverse=True, reopen=True),
        dict(id="allocator", allocator="malloc"),
        dict(id="locale", locale="utf8"),
    ]
    if extended:
        changes.extend(
            [
                dict(id="decimal-high", decimal="high"),
                dict(id="hash-second", hash_seed=str((seed + 104729) % 4294967295 + 1)),
                dict(
                    id="combined",
                    hash_seed="42",
                    timezone="America/New_York",
                    decimal="high",
                    warm=True,
                    reverse=True,
                    reopen=True,
                    allocator="malloc",
                    locale="utf8",
                    poison=True,
                ),
            ]
        )
    return [base] + [{**base, **change} for change in changes]


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=True, indent=2, allow_nan=False) + "\n")


def corpus_digest(cases):
    data = json.dumps(cases, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(data.encode()).hexdigest()


def configure_host(scenario):
    selected = "C"
    if scenario["locale"] == "utf8":
        for candidate in ("C.UTF-8", "en_US.UTF-8", "UTF-8"):
            try:
                selected = locale.setlocale(locale.LC_ALL, candidate)
                break
            except locale.Error:
                continue
        else:
            raise RuntimeError("No UTF-8 locale available for requested perturbation")
    else:
        locale.setlocale(locale.LC_ALL, "C")
    time.tzset()
    context = decimal.getcontext()
    if scenario["decimal"] != "default":
        context.prec = 6 if scenario["decimal"] == "low" else 80
        context.rounding = decimal.ROUND_UP if scenario["decimal"] == "low" else decimal.ROUND_DOWN
        context.capitals = 0
    if scenario["warm"]:
        format(decimal.Decimal("-0.001"), "z.2f")
        format(decimal.Decimal("0"), "#.0f")
    if scenario["poison"]:
        from contracting.execution.runtime import rt

        rt.env.update(
            __input_hash="unrelated-previous-input",
            block_hash="unrelated-block",
            chain_id="unrelated-chain",
        )
    return dict(
        locale=selected,
        timezone=list(time.tzname),
        decimal_precision=context.prec,
        decimal_rounding=context.rounding,
        decimal_capitals=context.capitals,
    )


def run_worker(workload, destination, scenario):
    from xian_vm_core import runtime_info

    from tests.determinism.observer import observe_case

    cases = json.loads(workload.read_text())
    host = configure_host(scenario)
    observations = {}
    ordered = list(reversed(cases)) if scenario["reverse"] else cases
    with tempfile.TemporaryDirectory(prefix="xian-determinism-") as directory:
        for index, case in enumerate(ordered):
            try:
                observations[case["id"]] = observe_case(
                    case, Path(directory) / str(index), reopen=scenario["reopen"]
                )
            except Exception as error:
                write_json(
                    destination.with_suffix(".failure.json"),
                    {
                        "scenario": scenario,
                        "case": case,
                        "error": str(error),
                        "completed": len(observations),
                    },
                )
                raise
    write_json(
        destination,
        {
            "schema": 1,
            "corpus_sha256": corpus_digest(cases),
            "execution_policy": {
                profile: runtime_info(vm_profile=profile)
                for profile in sorted({case["vm_profile"] for case in cases})
            },
            "observations": dict(sorted(observations.items())),
            "host": {
                **host,
                "platform": platform.system(),
                "machine": platform.machine(),
                "python": sys.version,
                "scenario": scenario,
            },
        },
    )


def run_process(workload, output, scenario):
    destination = output / (scenario["id"] + ".json")
    environment = {
        **os.environ,
        "PYTHONHASHSEED": scenario["hash_seed"],
        "TZ": scenario["timezone"],
        "PYTHONOPTIMIZE": scenario["optimize"],
        "PYTHONMALLOC": scenario["allocator"],
        "LC_ALL": "C",
        "PYTHONIOENCODING": "utf-8",
    }
    with tempfile.TemporaryDirectory(prefix="xian-determinism-home-") as home:
        environment["HOME"] = home
        command = [
            sys.executable,
            "-m",
            "tests.determinism.campaign",
            "--worker",
            str(workload),
            str(destination),
            json.dumps(scenario),
        ]
        with (output / (scenario["id"] + ".log")).open("w") as log:
            subprocess.run(
                command,
                env=environment,
                stdout=log,
                stderr=subprocess.STDOUT,
                check=True,
                timeout=600,
            )
    return json.loads(destination.read_text())


def collect_cases(seed, generated):
    from tests.determinism.cases import generated_cases
    from tests.determinism.float_cases import float_cases
    from tests.determinism.numeric_cases import numeric_cases
    from tests.surface.catalog import load_cases

    cases = sorted(
        [dict(case, vm_profile="xian_vm_v1") for case in load_cases()]
        + generated_cases(seed=seed, count=generated)
        + float_cases()
        + numeric_cases(),
        key=lambda case: case["id"],
    )
    if len({case["id"] for case in cases}) != len(cases):
        raise ValueError("Duplicate determinism case IDs")
    return cases


def check_optimized_rejection(output):
    result = subprocess.run(
        [sys.executable, "-O", "-c", "import contracting"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode == 0 or "refuses to run with PYTHONOPTIMIZE" not in result.stderr:
        raise AssertionError("Unsupported optimized interpreter did not fail closed")
    write_json(
        output / "optimized-rejection.json",
        {
            "rejected": True,
            "returncode": result.returncode,
            "reason": "contracting refuses optimization that strips consensus assertions",
        },
    )


def validate_workload_report(report, cases):
    compare_reports(report, report)
    if report["corpus_sha256"] != corpus_digest(cases):
        raise AssertionError("Worker corpus does not match requested workload")
    if set(report["observations"]) != {case["id"] for case in cases}:
        raise AssertionError("Worker observations do not cover requested workload")


def run_campaign(output, seed, generated, extended):
    output.mkdir(parents=True, exist_ok=False)
    check_optimized_rejection(output)
    cases = collect_cases(seed, generated)
    workload = output / "workload.json"
    write_json(workload, cases)
    matrix = scenarios(seed, extended=extended)
    summary = dict(
        schema=1,
        seed=seed,
        case_count=len(cases),
        corpus_sha256=corpus_digest(cases),
        scenarios=matrix,
        completed=[],
        success=False,
    )
    write_json(output / "summary.json", summary)
    reference = None
    for scenario in matrix:
        try:
            observed = run_process(workload, output, scenario)
            validate_workload_report(observed, cases)
            if reference is not None:
                compare_reports(reference, observed)
            else:
                reference = observed
        except Exception as error:
            write_json(
                output / "failure.json",
                {
                    "scenario": scenario,
                    "error": str(error),
                    "workload": workload.name,
                    "reference": matrix[0]["id"] + ".json",
                    "observation": scenario["id"] + ".json",
                    "log": scenario["id"] + ".log",
                },
            )
            raise
        summary["completed"].append(scenario["id"])
        write_json(output / "summary.json", summary)
        print(f"{scenario['id']}: {len(cases)} exact observations match", flush=True)
    summary["success"] = True
    write_json(output / "summary.json", summary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--seed", type=int, default=20261103)
    parser.add_argument("--generated", type=int, default=32)
    parser.add_argument("--extended", action="store_true")
    parser.add_argument("--compare", type=Path, nargs="+")
    parser.add_argument("--worker", nargs=3, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker:
        workload, destination, scenario = args.worker
        run_worker(Path(workload), Path(destination), json.loads(scenario))
    elif args.compare:
        if len(args.compare) < 2:
            parser.error("--compare requires at least two reports")
        reference = json.loads(args.compare[0].read_text())
        for path in args.compare[1:]:
            compare_reports(reference, json.loads(path.read_text()))
        print(f"{len(args.compare)} reports match exactly")
    else:
        if args.output is None or not 0 <= args.generated <= 4096:
            parser.error("--output and --generated between 0 and 4096 are required")
        run_campaign(args.output, args.seed, args.generated, args.extended)


if __name__ == "__main__":
    main()
