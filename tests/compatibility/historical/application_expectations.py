"""Exact reviewed policy replacements; never numeric tolerances or field ignores."""

from copy import deepcopy


def expected_current(observations, deviations):
    expected = deepcopy(observations)
    applied = set()
    for replacement in deviations["replacements"]:
        scenario = replacement["scenario"]
        if scenario not in expected:
            continue
        key = (scenario, replacement["step"], tuple(replacement["path"]))
        if key in applied:
            raise ValueError(f"Duplicate policy replacement: {key}")
        applied.add(key)
        if replacement["policy"] not in deviations["policies"]:
            raise ValueError("Undocumented application policy")
        step = next(item for item in expected[scenario] if item["id"] == replacement["step"])
        replace_exact(step, replacement)
    return expected, len(applied)


def replace_exact(step, replacement):
    target = step
    for component in replacement["path"][:-1]:
        target = target[component]
    leaf = replacement["path"][-1]
    if target[leaf] != replacement["historical"]:
        raise ValueError(f"Policy replacement does not match historical evidence: {replacement}")
    target[leaf] = deepcopy(replacement["current"])
