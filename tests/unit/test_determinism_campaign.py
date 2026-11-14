"""The campaign must detect drift rather than bless its first observation."""

import copy

import pytest

from tests.determinism.campaign import compare_reports, first_difference, scenarios


def report():
    return {
        "schema": 1,
        "execution_policy": {"execution_revision": "xvm-execution-4"},
        "corpus_sha256": "same-input",
        "observations": {
            "probe": {
                "chi_used": 40,
                "result": ["tuple", [["int", 1], ["float", "8000000000000000"]]],
                "events": [],
                "state": [["key", ["int", 2]]],
            }
        },
    }


def test_comparison_ignores_host_metadata_but_checks_exact_observations():
    left, right = report(), report()
    left["host"] = {"machine": "aarch64"}
    right["host"] = {"machine": "x86_64"}
    compare_reports(left, right)


@pytest.mark.parametrize(
    "field,value",
    [
        ("chi_used", 41),
        ("result", ["list", [["int", 1], ["float", "8000000000000000"]]]),
        ("result", ["tuple", [["int", 1], ["float", "0000000000000000"]]]),
        ("events", [["unexpected"]]),
        ("state", [["key", ["int", 3]]]),
    ],
)
def test_comparison_rejects_consensus_visible_drift(field, value):
    left, right = report(), report()
    right["observations"]["probe"][field] = value
    with pytest.raises(AssertionError, match=field):
        compare_reports(left, right)


def test_comparison_rejects_missing_cases_and_changed_inputs():
    for key, value in [("observations", {}), ("corpus_sha256", "different")]:
        right = copy.deepcopy(report())
        right[key] = value
        with pytest.raises(AssertionError):
            compare_reports(report(), right)


def test_difference_preserves_value_types_and_list_order():
    assert first_difference([1, 2], [2, 1]) == "$[0]"
    assert first_difference(True, 1) == "$"
    assert first_difference({"x": []}, {"x": [1]}) == "$.x.length"
    assert first_difference({"x": 1}, {"x": 1}) is None


def test_scenarios_cover_independent_host_changes_and_reproducible_seed():
    cases = scenarios(71, extended=True)
    assert cases == scenarios(71, extended=True)
    assert len({case["id"] for case in cases}) == len(cases)
    for field in ("hash_seed", "timezone", "decimal", "warm", "reverse", "reopen", "allocator"):
        assert len({str(case[field]) for case in cases}) > 1, field


def test_unsupported_optimization_fails_closed(tmp_path):
    from tests.determinism.campaign import check_optimized_rejection

    check_optimized_rejection(tmp_path)
    assert (tmp_path / "optimized-rejection.json").is_file()


@pytest.mark.parametrize("change", ["missing", "different"])
def test_comparison_requires_execution_policy(change):
    left, right = report(), report()
    left["execution_policy"] = {"execution_revision": "xvm-execution-4"}
    if change == "missing":
        right.pop("execution_policy")
    if change == "different":
        right["execution_policy"] = {"execution_revision": "xvm-execution-3"}
    with pytest.raises(AssertionError, match="execution_policy"):
        compare_reports(left, right)


@pytest.mark.parametrize("mode", ["drift", "missing-baseline", "missing-output"])
def test_campaign_failure_retains_reproduction_and_never_claims_success(
    tmp_path, monkeypatch, mode
):
    import json

    from tests.determinism import campaign

    cases = [
        {"id": "probe", "source": "@export\ndef probe():\n    return 1\n", "expected_result": 1}
    ]
    monkeypatch.setattr(campaign, "collect_cases", lambda *_: cases)
    monkeypatch.setattr(campaign, "check_optimized_rejection", lambda *_: None)
    matrix = campaign.scenarios(1)[:2]
    monkeypatch.setattr(campaign, "scenarios", lambda *_, **__: matrix)

    def process(workload, output, scenario):
        value = report()
        value["corpus_sha256"] = campaign.corpus_digest(cases)
        if mode == "missing-baseline":
            value["observations"] = {}
        elif scenario["id"] == "hash":
            if mode == "missing-output":
                raise FileNotFoundError("hash.json was not produced")
            value["observations"]["probe"]["chi_used"] += 1
        campaign.write_json(output / (scenario["id"] + ".json"), value)
        return value

    monkeypatch.setattr(campaign, "run_process", process)
    output = tmp_path / "campaign"
    with pytest.raises((AssertionError, FileNotFoundError)):
        campaign.run_campaign(output, 1, 0, False)
    summary = json.loads((output / "summary.json").read_text())
    failure = json.loads((output / "failure.json").read_text())
    assert summary["success"] is False
    assert failure["error"]
    assert failure["workload"] == "workload.json"
    assert failure["scenario"]["id"] == ("baseline" if mode == "missing-baseline" else "hash")
    assert json.loads((output / failure["workload"]).read_text()) == cases


@pytest.fixture
def restored_host(monkeypatch):
    import decimal
    import locale
    import time

    saved_context = decimal.getcontext().copy()
    saved_locale = locale.setlocale(locale.LC_ALL)
    monkeypatch.setenv("TZ", "Pacific/Auckland")
    try:
        yield
    finally:
        decimal.setcontext(saved_context)
        locale.setlocale(locale.LC_ALL, saved_locale)
        monkeypatch.undo()
        time.tzset()


@pytest.mark.parametrize(
    "kind,precision,rounding", [("low", 6, "ROUND_UP"), ("high", 80, "ROUND_DOWN")]
)
def test_host_decimal_locale_and_timezone_are_actual_perturbations(
    restored_host, kind, precision, rounding
):
    import decimal
    import locale
    import time

    from tests.determinism.campaign import configure_host

    scenario = {**scenarios(1)[0], "decimal": kind, "warm": True}
    host = configure_host(scenario)
    assert decimal.getcontext().prec == host["decimal_precision"] == precision
    assert decimal.getcontext().rounding == rounding
    assert decimal.getcontext().capitals == 0
    assert locale.setlocale(locale.LC_ALL) == "C"
    assert list(time.tzname) == host["timezone"]
    assert time.localtime(0).tm_hour == 12


def test_utf8_locale_is_real_or_fails_explicitly(restored_host):
    import locale

    from tests.determinism.campaign import configure_host

    try:
        host = configure_host({**scenarios(1)[0], "locale": "utf8"})
    except RuntimeError as error:
        assert "No UTF-8 locale" in str(error)
    else:
        assert host["locale"] == locale.setlocale(locale.LC_ALL)
        assert "utf" in locale.nl_langinfo(locale.CODESET).lower()


def test_worker_records_actual_runtime_policy_and_reversed_case_order(tmp_path, monkeypatch):
    import json
    import sys
    import types

    from tests.determinism import campaign, observer

    cases = [{"id": "a", "vm_profile": "xian_vm_v2"}, {"id": "b", "vm_profile": "xian_vm_v2"}]
    workload, destination = tmp_path / "workload.json", tmp_path / "report.json"
    campaign.write_json(workload, cases)
    calls = []
    policy = {"execution_revision": "test-revision", "supported_gas_schedules": ["test-gas"]}
    monkeypatch.setitem(
        sys.modules,
        "xian_vm_core",
        types.SimpleNamespace(runtime_info=lambda vm_profile: {**policy, "vm_profile": vm_profile}),
    )
    monkeypatch.setattr(campaign, "configure_host", lambda _: {})

    def observe(case, home, *, reopen):
        calls.append((case["id"], reopen))
        return {"result": case["id"]}

    monkeypatch.setattr(observer, "observe_case", observe)
    campaign.run_worker(workload, destination, {**scenarios(1)[0], "reverse": True, "reopen": True})
    value = json.loads(destination.read_text())
    assert value["execution_policy"] == {"xian_vm_v2": {**policy, "vm_profile": "xian_vm_v2"}}
    assert calls == [("b", True), ("a", True)]
    assert list(value["observations"]) == ["a", "b"]
    assert value["corpus_sha256"] == campaign.corpus_digest(cases)


def test_worker_failure_preserves_exact_case_and_completed_count(tmp_path, monkeypatch):
    import json
    import sys
    import types

    from tests.determinism import campaign, observer

    cases = [{"id": "good"}, {"id": "bad", "source": "broken program"}]
    workload, destination = tmp_path / "workload.json", tmp_path / "report.json"
    campaign.write_json(workload, cases)
    monkeypatch.setitem(
        sys.modules, "xian_vm_core", types.SimpleNamespace(runtime_info=lambda vm_profile: {})
    )
    monkeypatch.setattr(campaign, "configure_host", lambda _: {})

    def observe(case, *_args, **_kwargs):
        if case["id"] == "bad":
            raise AssertionError("exact observation failed")
        return {"result": 1}

    monkeypatch.setattr(observer, "observe_case", observe)
    with pytest.raises(AssertionError, match="exact observation failed"):
        campaign.run_worker(workload, destination, scenarios(1)[0])
    failure = json.loads(destination.with_suffix(".failure.json").read_text())
    assert failure["case"] == cases[1]
    assert failure["completed"] == 1
    assert not destination.exists()


@pytest.mark.parametrize("mode", ["fallback", "unavailable"])
def test_utf8_selection_does_not_silently_skip_requested_profile(monkeypatch, mode):
    import locale

    from tests.determinism import campaign

    attempts = []

    def select(category, value):
        attempts.append(value)
        if mode == "fallback" and value == "en_US.UTF-8":
            return value
        raise locale.Error("not installed")

    monkeypatch.setattr(locale, "setlocale", select)
    monkeypatch.setattr(campaign.time, "tzset", lambda: None)
    profile = {**scenarios(1)[0], "locale": "utf8"}
    if mode == "unavailable":
        with pytest.raises(RuntimeError, match="No UTF-8 locale"):
            campaign.configure_host(profile)
        assert attempts == ["C.UTF-8", "en_US.UTF-8", "UTF-8"]
    else:
        assert campaign.configure_host(profile)["locale"] == "en_US.UTF-8"
        assert attempts == ["C.UTF-8", "en_US.UTF-8"]


@pytest.mark.parametrize("returncode,stderr", [(0, ""), (1, "unrelated import failure")])
def test_optimized_preflight_does_not_accept_unrelated_failure(
    tmp_path, monkeypatch, returncode, stderr
):
    from types import SimpleNamespace

    from tests.determinism import campaign

    monkeypatch.setattr(
        campaign.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=returncode, stderr=stderr),
    )
    with pytest.raises(AssertionError, match="did not fail closed"):
        campaign.check_optimized_rejection(tmp_path)
    assert not (tmp_path / "optimized-rejection.json").exists()


@pytest.mark.parametrize("mode", ["digest", "ids"])
def test_first_worker_must_match_requested_workload(mode):
    from tests.determinism import campaign

    cases = [{"id": "probe"}]
    observed = report()
    observed["corpus_sha256"] = campaign.corpus_digest(cases)
    if mode == "digest":
        observed["corpus_sha256"] = "other-workload"
    else:
        observed["observations"] = {"wrong-case": observed["observations"]["probe"]}
    with pytest.raises(AssertionError, match="workload"):
        campaign.validate_workload_report(observed, cases)


def test_collection_is_v2_only_and_sorted():
    from tests.determinism.campaign import collect_cases

    cases = collect_cases(seed=71, generated=18)
    assert {case["vm_profile"] for case in cases} == {"xian_vm_v2"}
    assert not any(case["id"].startswith("float_edge_") for case in cases)
    assert [case["id"] for case in cases] == sorted(case["id"] for case in cases)
