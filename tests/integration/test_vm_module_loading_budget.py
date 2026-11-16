"""Native transaction budgets bound preparation as well as executed instructions."""

import pytest
from xian_runtime_types.time import Datetime

from contracting.artifacts import compile_contract_source
from contracting.local.client import BUILTIN_SUBMISSION_SOURCE_PATH
from contracting.storage.driver import Driver
from tests.vm_calls import execute_contract


def install(driver, name, source):
    compiled = compile_contract_source(module_name=name, source=source)
    driver.set_contract(
        name=name, source=compiled["source"], vm_ir_json=compiled["vm_ir_json"], overwrite=True
    )


@pytest.fixture
def driver(tmp_path):
    with Driver(storage_home=tmp_path, vm_profile="xian_vm_v2") as store:
        yield store


def call(driver, *, budget=200_000, metered=True, **kwargs):
    return execute_contract(
        driver=driver,
        contract_name="con_probe",
        function_name="read",
        kwargs=kwargs,
        context={"caller": "alice", "signer": "alice", "now": Datetime(2026, 1, 1)},
        meter=metered,
        chi_budget_raw=budget * 1_000,
    )


def test_exhausted_preparation_budget_stops_before_following_imports(driver):
    install(
        driver,
        "con_probe",
        f'"{"x" * 10_000}"\nimport con_missing\n@export\ndef read():\n    return 1\n',
    )
    driver.commit()

    result = call(driver, budget=10)

    assert result.status_code == 1
    assert "Out of chi" in str(result.result)
    assert result.chi_used == 10
    assert result.writes == {}
    assert result.events == []


def test_dynamic_module_loading_uses_the_same_budget(driver):
    install(driver, "con_large", f'"{"x" * 100_000}"\n@export\ndef read():\n    return 7\n')
    install(
        driver,
        "con_probe",
        "@export\ndef read(target: str):\n    module = importlib.import_module(target)\n"
        "    return module.read()\n",
    )
    driver.commit()

    result = call(driver, budget=100, target="con_large")

    assert result.status_code == 1
    assert "Out of chi" in str(result.result)
    assert result.chi_used == 100
    assert result.writes == {}
    enough = call(driver, budget=1_000, target="con_large")
    assert enough.status_code == 0, enough.result
    assert enough.result == 7


def test_module_cache_warmth_does_not_change_execution_costs(driver):
    install(driver, "con_leaf", '"' + "x" * 20_000 + '"\n@export\ndef read():\n    return 7\n')
    install(
        driver, "con_probe", "import con_leaf\n@export\ndef read():\n    return con_leaf.read()\n"
    )
    driver.commit()

    cold = call(driver)
    warm = call(driver)

    assert cold.status_code == warm.status_code == 0
    assert cold.result == warm.result == 7
    assert cold.chi_used == warm.chi_used
    assert cold.contract_costs == warm.contract_costs
    # Even an unused docstring is parsed during preparation, so its bytes
    # have a cost. This is far above the old fixed import/call charge.
    assert cold.chi_used >= 50


@pytest.mark.parametrize(
    ("count", "padding", "error"),
    [
        (511, 0, None),
        (512, 0, "module graph exceeds 512 modules"),
        (135, 125_000, "module graph exceeds 16777216 IR bytes"),
    ],
)
def test_unmetered_preparation_has_an_aggregate_bound(driver, count, padding, error):
    source = f'"{"x" * padding}"\n@export\ndef read():\n    return 7\n'
    for index in range(count):
        install(driver, f"con_leaf_{index}", source)
    install(
        driver,
        "con_probe",
        "\n".join(f"import con_leaf_{index}" for index in range(count))
        + "\n@export\ndef read():\n    return 1\n",
    )
    driver.commit()

    result = call(driver, metered=False)

    assert result.status_code == (1 if error else 0)
    if error:
        assert error in str(result.result)
    else:
        assert result.result == 1
    assert result.writes == {}
    assert result.events == []


def install_full_graph(driver, *, probe=None, submission=False):
    count, padding, limit = 134, 122_000, 16 * 1024 * 1024
    sources = {
        f"con_leaf_{index}": f'"{"x" * padding}"\n@export\ndef read():\n    return 7\n'
        for index in range(count)
    }
    sources["con_probe"] = (
        "\n".join(f"import con_leaf_{index}" for index in range(count))
        + ("\nimport submission\n" if submission else "\n")
        + (probe or "@export\ndef read():\n    return 1\n")
    )
    if submission:
        sources["submission"] = BUILTIN_SUBMISSION_SOURCE_PATH.read_text()
    compiled = {
        name: compile_contract_source(module_name=name, source=source)
        for name, source in sources.items()
    }
    remaining = limit - sum(len(item["vm_ir_json"].encode()) for item in compiled.values())
    assert remaining > 0
    for name in sources:
        if not name.startswith("con_leaf_") or remaining == 0:
            continue
        extra = min(remaining, 8_000)
        sources[name] = sources[name].replace('"\n@export', "x" * extra + '"\n@export', 1)
        compiled[name] = compile_contract_source(module_name=name, source=sources[name])
        remaining -= extra
        last = name
    assert remaining == 0
    assert sum(len(item["vm_ir_json"].encode()) for item in compiled.values()) == limit
    for name, item in compiled.items():
        driver.set_contract(name=name, source=item["source"], vm_ir_json=item["vm_ir_json"])
    driver.commit()
    return last, sources[last]


def test_unmetered_module_ir_byte_limit_accepts_exact_boundary(driver):
    last, source = install_full_graph(driver)

    accepted = call(driver, metered=False)
    assert accepted.status_code == 0, accepted.result
    assert accepted.result == 1

    install(driver, last, source.replace('"\n@export', 'x"\n@export', 1))
    driver.commit()
    refused = call(driver, metered=False)
    assert refused.status_code == 1
    assert "module graph exceeds 16777216 IR bytes" in str(refused.result)


def test_an_absent_lookup_cannot_hide_ir_loaded_by_a_new_constructor(driver):
    created = (
        "@construct\ndef seed():\n    assert importlib.has_export(ctx.this, 'read')\n"
        "@export\ndef read():\n    return 7\n"
    )
    probe = (
        "@export\ndef read():\n    assert not importlib.exists('con_new')\n"
        f"    submission.submit_contract(name='con_new', code={created!r})\n    return 1\n"
    )
    install_full_graph(driver, probe=probe, submission=True)

    result = call(driver, metered=False)

    assert result.status_code == 1
    assert "module graph exceeds 16777216 IR bytes" in str(result.result)
    assert result.writes == {}
    assert result.events == []
