"""New public surface requires an explicit inventory/test decision."""

import ast
import json

from tests.surface import catalog
from tests.surface.catalog import DIRECTORY, coverage_report, discover, load_cases

CATALOG = json.loads((DIRECTORY / "catalog.json").read_text())


def test_public_surface_has_not_changed_without_review():
    assert discover() == CATALOG["discovery"]


def test_cases_reference_reviewed_items_and_explicit_expectations():
    items = {item["id"] for item in CATALOG["items"]}
    assert len(items) == len(CATALOG["items"])
    cases = load_cases()
    assert len({case["id"] for case in cases}) == len(cases)
    for case in cases:
        assert case["covers"] and set(case["covers"]) <= items, case["id"]
        assert case["dimension"] in {"nominal", "boundary", "invalid"}, case["id"]
        assert ("expected_result" in case) != case.get("expected_failure", False), case["id"]
        assert case["id"].isidentifier() and case["id"] == case["id"].lower()
        if case.get("native_only"):
            assert case["expected_failure"] and case["policy_reason"], case["id"]
            assert case["dimension"] == "invalid", case["id"]
        tree = ast.parse(case["source"])
        calls = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        attributes = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
        for name in case["covers"]:
            if name.startswith("builtin."):
                assert name.removeprefix("builtin.") in calls, (case["id"], name)
            elif name.startswith(("method.", "attribute.")):
                assert name.rsplit(".", 1)[1] in attributes, (case["id"], name)


def test_each_callable_builtin_has_three_behavioral_dimensions():
    syntax = {"True", "False", "None", "import"}
    rows = {row["id"]: row for row in coverage_report()["items"]}
    for name in set(CATALOG["discovery"]["builtins"]) - syntax:
        row = rows["builtin." + name]
        assert set(row["direct_cases"]) == {"nominal", "boundary", "invalid"}, name


def test_explicit_gaps_are_not_reported_as_behaviorally_covered():
    for row in coverage_report()["items"]:
        if row["implementation"] == "missing":
            assert row["reason"], row["id"]
        for path in row.get("existing_test_files", []):
            assert (DIRECTORY.parents[1] / path).is_file(), (row["id"], path)


def test_present_value_members_have_successful_shared_cases():
    successful_members = {
        name
        for case in load_cases()
        if not case.get("expected_failure") and not case.get("native_only")
        for name in case["covers"]
    }
    for row in coverage_report()["items"]:
        if row["implementation"] == "present" and row["kind"] in {"method", "attribute"}:
            assert row["id"] in successful_members, row["id"]


def test_inventory_detects_new_builtin_without_a_catalog_update(monkeypatch):
    surface = catalog.CONTRACT_LANGUAGE_MANIFEST["python_contracting"]
    monkeypatch.setitem(surface, "allowed_builtins", [*surface["allowed_builtins"], "new_builtin"])
    assert not coverage_report()["discovery_matches"]


def test_inventory_detects_new_public_value_member(monkeypatch):
    class ExtendedString(str):
        def added_method(self):
            return None

    examples = catalog.value_examples()
    examples["str"] = ExtendedString("a")
    monkeypatch.setattr(catalog, "value_examples", lambda: examples)
    assert not coverage_report()["discovery_matches"]


def test_report_counts_direct_cases_without_counting_source_references(monkeypatch):
    monkeypatch.setattr(
        catalog,
        "load_cases",
        lambda: [{"id": "example", "covers": ["builtin.abs"], "dimension": "nominal"}],
    )
    report = coverage_report()
    assert report["counts"]["authored_cases"] == 1
    assert report["counts"]["items_with_direct_cases"] == 1
    rows = {row["id"]: row for row in report["items"]}
    assert rows["builtin.abs"]["direct_cases"] == {"nominal": ["example"]}
    assert rows["builtin.len"]["existing_test_files"]
    assert rows["builtin.len"]["direct_cases"] == {}


def test_policy_cases_are_distinct_from_shared_compatibility_cases():
    report = coverage_report()
    cases = load_cases()
    policy_cases = [case for case in cases if case.get("native_only")]
    assert report["counts"]["native_only_policy_cases"] == len(policy_cases)
    assert report["counts"]["shared_compatibility_cases"] == len(cases) - len(policy_cases)
    assert report["counts"]["policy_disposition"] == {"deferred": 4, "excluded": 1, "restricted": 1}
    rows = {row["id"]: row for row in report["items"]}
    for case in policy_cases:
        for name in case["covers"]:
            disposition = rows[name]["disposition"]
            assert disposition in {"deferred", "excluded", "restricted"}, name
            implementation = "present" if disposition == "restricted" else "missing"
            assert rows[name]["implementation"] == implementation, name
    unresolved = [
        row
        for row in report["items"]
        if row["implementation"] == "missing" and not row.get("disposition")
    ]
    assert report["counts"]["unresolved_missing_items"] == len(unresolved)


def test_historical_and_newer_policy_members_have_explicit_scope():
    rows = {row["id"]: row for row in CATALOG["items"]}
    for name in ("float.from_number", "Decimal.from_number", "bytearray.resize"):
        assert rows["method." + name]["historical_python_312"] is False
    assert rows["method.Exception.with_traceback"]["historical_python_312"] is True


def test_builtin_set_inventory_keeps_kind_boundary_and_member_domain_distinct():
    rows = {row["id"]: row for row in CATALOG["items"]}
    discovery = CATALOG["discovery"]["value_members"]
    extra_methods = {
        "update",
        "intersection_update",
        "difference_update",
        "symmetric_difference_update",
    }
    assert set(discovery["builtin_set"]) - set(discovery["set"]) == extra_methods
    for name in discovery["builtin_set"]:
        assert rows["method.builtin_set." + name]["implementation"] == "present"
    assert rows["protocol.builtin_set.external_boundary"]["disposition"] == "restricted"
    members = rows["protocol.builtin_set.callable_members"]
    assert members["implementation"] == "present"
    assert "disposition" not in members
    assert members["existing_test_files"] == ["tests/integration/test_vm_builtin_set_keys.py"]
    assert "packages/xian-vm-core/src/builtin_set_keys.rs" in members["notes"]


def test_interface_subject_inventory_lists_only_reviewed_metadata_fields():
    members = {name: "attribute" for name in ("kind", "name", "args", "storage_type")}
    assert discover()["value_members"]["InterfaceSubject"] == members
    rows = {row["id"]: row for row in CATALOG["items"]}
    for name in members:
        row = rows["attribute.InterfaceSubject." + name]
        assert row["implementation"] == "present"
        assert "read-only" in row["reason"]
        assert (
            "tests/integration/test_vm_interface_subject_boundaries.py"
            in row["existing_test_files"]
        )
    assert "InterfaceSubject" not in CATALOG["discovery"]["builtins"]
    assert "InterfaceSubject" not in CATALOG["discovery"]["environment"]
