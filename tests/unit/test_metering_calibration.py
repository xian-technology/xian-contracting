"""The calibration check compares each family with the baselines of its run."""

import importlib.util
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "metering_calibration.py"
spec = importlib.util.spec_from_file_location("metering_calibration", SCRIPT)
calibration = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = calibration
spec.loader.exec_module(calibration)


def measurement(name, family, us_per_chi, reps=10, scalable=True):
    probe = calibration.Probe(name, family, (), ("pass",), reps, scalable)
    return calibration.Measurement(probe=probe, chi_per_op=2.0, us_per_op=2.0 * us_per_chi)


def test_statements_indent_the_body_of_a_compound_line():
    assert calibration.statements("a = 1; for c in s:; pass; b = 2") == (
        "a = 1",
        "for c in s:",
        "    pass",
        "    b = 2",
    )
    assert calibration.statements("") == ()


def test_each_probe_is_a_small_contract_that_repeats_its_operation():
    probe = calibration.probe("demo", "string", "s = 'a'", "x = s.upper()", 10)
    source = calibration.probe_source(probe)
    assert calibration.contract_name(probe) == "con_demo"
    assert source.endswith(
        "def run(n: int):\n    s = 'a'\n    for rep in range(n):\n"
        "        x = s.upper()\n    return 1\n"
    )
    assert "seeded = Hash(default_value=0)" in source


def test_probe_names_are_unique_and_every_family_has_baselines():
    names = [probe.name for probe in calibration.PROBES]
    assert len(names) == len(set(names))
    families = {probe.family for probe in calibration.PROBES}
    assert {"baseline", "boundary", "string", "compare", "storage_scan", "dict"} <= families


def test_only_non_baseline_probes_above_the_ratio_fail():
    results = [
        measurement("loop", "baseline", 1.0),
        measurement("arith", "baseline", 2.0),
        measurement("calls", "baseline", 30.0),
        measurement("fair", "string", 15.9),
        measurement("slow", "string", 16.1),
    ]
    reference, failures = calibration.evaluate(results, max_ratio=8)
    assert reference == 2.0
    assert len(failures) == 1
    assert failures[0].startswith("slow (string): 16.10 us/chi = 8.1x")


@pytest.mark.parametrize(
    ("reps", "chi", "elapsed", "scalable", "grows"),
    [
        (10, 100, 0.001, True, True),
        (10, 100, 0.001, False, False),
        (10, 100, calibration.TARGET_SECONDS, True, False),
        (10 * calibration.MAX_SCALE, 100, 0.001, True, False),
        (10, calibration.PROBE_CHI // calibration.GROWTH, 0.001, True, False),
    ],
)
def test_repetitions_grow_until_time_or_a_limit_is_reached(reps, chi, elapsed, scalable, grows):
    probe = measurement("p", "string", 1.0, reps=10, scalable=scalable).probe
    assert calibration.ProbeRunner.should_grow(probe, reps, chi, elapsed) is grows


class FakeRunner(calibration.ProbeRunner):
    """Charges 5 chi and 1 ms per repetition; fails above `limit`."""

    def __init__(self, limit=None):
        super().__init__(client=None, repeat=1)
        self.limit = limit

    def best(self, contract, n):
        if self.limit is not None and n > self.limit:
            raise calibration.ProbeFailure(f"{contract}(n={n}) failed")
        return 100 + 5 * n, 0.002 + 0.001 * n


def test_measure_grows_repetitions_and_keeps_the_last_completed_run():
    probe = calibration.probe("grow", "string", "", "pass", 1)
    grown = FakeRunner().measure(probe)
    assert grown.chi_per_op == 5
    assert grown.us_per_op == pytest.approx(1000)
    limited = FakeRunner(limit=4).measure(probe)
    assert limited.us_per_chi == pytest.approx(200)
    with pytest.raises(calibration.ProbeFailure):
        FakeRunner(limit=0).measure(probe)


def test_command_line_run_reports_the_selected_family(capsys):
    assert calibration.main(["--only", "str_upper", "--repeat", "1", "--max-ratio", "1000"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert any(line.startswith("str_upper ") for line in lines)
    assert lines[-1].startswith("baseline median:")


def test_json_report_lists_every_measured_probe(capsys):
    calibration.main(["--only", "str_lower", "--repeat", "1", "--max-ratio", "0.001", "--json"])
    output = capsys.readouterr()
    report = __import__("json").loads(output.out)
    baselines = {p.name for p in calibration.PROBES if p.baseline}
    assert set(report["probes"]) == baselines | {"str_lower"}
    assert report["probes"]["str_lower"]["family"] == "string"
    assert "UNDER-PRICED str_lower" in output.err


def test_dict_probes_cover_each_size_with_a_dictionary_of_that_size():
    probes = [probe for probe in calibration.PROBES if probe.family == "dict"]
    sizes = {probe.name.rsplit("_", 1)[1] for probe in probes}
    assert sizes == {str(size) for size in calibration.DICT_SIZES} == {"10", "1000", "10000"}
    assert calibration.statements(calibration.dict_setup(1000)) == (
        "d = {str(j): j for j in range(1000)}",
        "k = str(999)",
        "m = 1000",
    )
