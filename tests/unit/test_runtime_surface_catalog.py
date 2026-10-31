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
