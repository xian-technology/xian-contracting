"""The generated corpus is reproducible, bounded and independently anchored."""

import ast
import random

import pytest

from tests.determinism.cases import DEFAULT_SEED, FAMILIES, generated_cases


def test_generated_corpus_is_seeded_unique_and_balanced():
    cases = generated_cases()
    assert cases == generated_cases(seed=DEFAULT_SEED, count=256)
    assert len(cases) == len({case["id"] for case in cases}) == 256
    assert {case["family"] for case in cases[: len(FAMILIES)]} == set(FAMILIES)
    assert cases != generated_cases(seed=DEFAULT_SEED + 1)


def test_generation_does_not_read_or_mutate_global_random_state():
    saved = random.getstate()
    try:
        random.seed(1)
        first = generated_cases(count=20)
        before = random.getstate()
        second = generated_cases(count=20)
        assert random.getstate() == before
        random.seed(999)
        assert first == second == generated_cases(count=20)
    finally:
        random.setstate(saved)


def test_every_generated_source_is_bounded_and_has_explicit_semantic_anchors():
    for case in generated_cases():
        assert len(case["source"].encode()) < 8192
        tree = ast.parse(case["source"])
        assert len(list(ast.walk(tree))) < 1000
        steps = case.get("steps", [case])
        for step in steps:
            assert ("expected_result" in step) != bool(step.get("expected_failure"))
            if step.get("expected_failure"):
                assert step["expected_error"]


def test_sequence_cases_exercise_rollback_low_budget_and_followup():
    sequences = [case for case in generated_cases() if case["family"] == "sequence"]
    assert sequences
    for case in sequences:
        steps = case["steps"]
        assert [step["function"] for step in steps] == ["probe", "fail", "read", "probe", "read"]
        assert steps[1]["expected_error"] == "forced determinism failure"
        assert steps[3]["chi_budget_raw"] == 1
        assert steps[3]["expected_error"] == "Out of chi"
        assert steps[2]["expected_result"] == steps[4]["expected_result"]


@pytest.mark.parametrize("count", [-1, 4097, True, 1.5])
def test_invalid_corpus_size_rejected(count):
    with pytest.raises((TypeError, ValueError)):
        generated_cases(count=count)


def test_generation_is_independent_of_ambient_decimal_context():
    import decimal

    expected = generated_cases(count=40)
    with decimal.localcontext() as context:
        context.prec = 2
        context.rounding = decimal.ROUND_UP
        context.traps[decimal.Inexact] = True
        assert generated_cases(count=40) == expected


def test_generated_literals_do_not_turn_quoted_unicode_into_source():
    unicode_cases = [case for case in generated_cases() if case["family"] == "unicode"]
    literals = [
        node.value
        for case in unicode_cases
        for node in ast.walk(ast.parse(case["source"]))
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    ]
    assert any("\x00" in value for value in literals)
    assert any("\n" in value for value in literals)
    assert any("'" in value and '"' in value for value in literals)
    assert all("def probe" in case["source"] for case in unicode_cases)
