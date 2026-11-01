"""Host callable aliases share authored semantics with their direct call forms."""

import pytest

from contracting.execution.executor import Executor
from contracting.storage.driver import Driver

pytestmark = pytest.mark.optional_native

# Explicit catalog snapshot: adding an admitted function requires deliberate coverage.
CALLABLE_BINDINGS = (
    "indexed",
    "Contract.deploy",
    "Contract.get_info",
    "Contract.set_owner",
    "Contract.set_developer",
    "decimal",
    "datetime.datetime",
    "datetime.timedelta",
    "datetime.datetime.strptime",
    "hashlib.sha3",
    "hashlib.sha256",
    "hashlib.sha3_text",
    "hashlib.sha3_hex",
    "hashlib.sha256_text",
    "hashlib.sha256_hex",
    "crypto.verify",
    "crypto.key_is_valid",
    "importlib.import_module",
    "importlib.exists",
    "importlib.has_export",
    "importlib.call",
    "importlib.enforce_interface",
    "importlib.owner_of",
    "importlib.contract_info",
    "importlib.code_hash",
    "importlib.Func",
    "importlib.Var",
    "random.seed",
    "random.random",
    "random.shuffle",
    "random.getrandbits",
    "random.randrange",
    "random.randint",
    "random.choice",
    "random.choices",
    "zk.is_available",
    "zk.has_verifying_key",
    "zk.get_vk_info",
    "zk.verify_groth16_bn254",
    "zk.verify_groth16",
    "zk.clear_prepared_vk_cache",
    "zk.clear_verified_proof_cache",
    "zk.warm_verified_proofs",
    "zk.shielded_note_append_commitments",
    "zk.shielded_command_nullifier_digest",
    "zk.shielded_command_binding",
    "zk.shielded_command_execution_tag",
    "zk.shielded_command_public_inputs",
    "zk.shielded_deposit_public_inputs",
    "zk.shielded_output_payload_hashes",
    "zk.shielded_output_payload_hash",
    "zk.shielded_transfer_public_inputs",
    "zk.shielded_withdraw_public_inputs",
)

NOMINAL_CASES = [
    (
        "instance_classmethod_identity",
        "value = datetime.datetime(2000, 1, 1)\nf = value.strptime\nreturn [f == datetime.datetime.strptime, f is datetime.datetime.strptime, f is f]",
        [True, False, True],
    ),
    (
        "class_method_identity",
        "f = Contract.get_info\nreturn [f is f, Contract.get_info is Contract.get_info, f == Contract.get_info, hashlib.sha3 is hashlib.sha3]",
        [True, False, True, True],
    ),
    (
        "import_handle_identity",
        'first = importlib.import_module("con_host_callable_target")\nsecond = importlib.import_module("con_host_callable_target")\nreturn [first is first, first is second, first == second, first.value is first.value, first.value == second.value]',
        [True, False, False, True, False],
    ),
    (
        "import_handle_keys",
        'first = importlib.import_module("con_host_callable_target")\nsecond = importlib.import_module("con_host_callable_target")\nvalues = {first: 1, second: 2}\nreturn [len(values), values[first], values[second]]',
        [2, 1, 2],
    ),
    (
        "constructor_sort_key",
        'f = decimal\nreturn sorted(["2", "10", "1"], key=f)',
        ["1", "2", "10"],
    ),
    (
        "host_filter_callback",
        'f = crypto.key_is_valid\nreturn list(filter(f, ["", "invalid"]))',
        [],
    ),
    (
        "random_choice_identity",
        'random.seed("alias")\nitems = []\nf = random.choice\nselected = f(items=[items])\nselected.append(3)\nreturn items',
        [3],
    ),
    (
        "random_choices_identity",
        'random.seed("alias")\nitems = []\nf = random.choices\nselected = f(items=[items], k=2)\nselected[0].append(3)\nreturn [items, selected[1] is items]',
        [[3], True],
    ),
    (
        "random_shuffle_identity",
        'random.seed("alias")\nitems = [1, 2, 3]\nother = items\nf = random.shuffle\nf(items=items)\nreturn [items is other, sorted(other)]',
        [True, [1, 2, 3]],
    ),
    (
        "interface_constructor_alias",
        'f = importlib.Func\nv = importlib.Var\ncheck = importlib.enforce_interface\nreturn check("con_host_callable_target", [f(name="value"), v(name="state", t=Variable)])',
        True,
    ),
    (
        "runtime_export_callback",
        'loader = importlib.import_module\nmodule = loader("con_host_callable_target")\nf = module.value\nreturn f()',
        7,
    ),
    (
        "metadata_distinct_keyword_names",
        'f = Contract.get_info\ng = importlib.contract_info\nreturn [f(name="con_host_callables")["owner"], g(contract="con_host_callables")["owner"]]',
        ["alice", "alice"],
    ),
    (
        "hash_keyword",
        'f = hashlib.sha3_text\nreturn f(value="abc")',
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
    ),
    (
        "hash_keyword_direct",
        'return hashlib.sha3_text(value="abc")',
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
    ),
    ("crypto_keyword", 'f = crypto.key_is_valid\nreturn f(key="")', False),
    ("crypto_keyword_direct", 'return crypto.key_is_valid(key="")', False),
    ("exists_keyword", 'f = importlib.exists\nreturn f(contract="con_host_callables")', True),
    ("exists_keyword_direct", 'return importlib.exists(contract="con_host_callables")', True),
    (
        "timedelta_callback",
        "f = datetime.timedelta\nreturn [str(x) for x in map(f, [1, 2])]",
        ["7 days, 0:00:00", "14 days, 0:00:00"],
    ),
    (
        "hash_alias",
        'f = hashlib.sha3\nreturn f("abc")',
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
    ),
    (
        "hash_callback",
        'f = hashlib.sha256_text\nreturn list(map(f, ["abc"]))',
        ["ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"],
    ),
    (
        "module_value_alias",
        'module = hashlib\nf = module.sha3_text\nreturn f("abc")',
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
    ),
    ("decimal_alias", 'f = decimal\nreturn str(f("1.25"))', "1.25"),
    (
        "decimal_callback",
        'f = decimal\nreturn [str(x) for x in map(f, ["1.25", "2.5"])]',
        ["1.25", "2.5"],
    ),
    ("decimal_classinfo", 'f = decimal\nreturn isinstance(f("2"), f)', True),
    ("datetime_alias", "f = datetime.datetime\nreturn str(f(2026, 1, 2))", "2026-01-02 00:00:00"),
    (
        "datetime_classinfo",
        "f = datetime.datetime\nreturn [isinstance(f(2026, 1, 2), f), issubclass(f, datetime.datetime)]",
        [True, True],
    ),
    (
        "timedelta_alias_keywords",
        "f = datetime.timedelta\nreturn str(f(days=2))",
        "2 days, 0:00:00",
    ),
    ("indexed_alias", 'f = indexed\nreturn f(str)["idx"]', True),
    ("exists_alias", 'f = importlib.exists\nreturn f("con_host_callables")', True),
    ("has_export_alias", 'f = importlib.has_export\nreturn f("con_host_callables", "probe")', True),
    (
        "module_import_alias",
        'f = importlib.import_module\nmodule = f("con_host_callable_target")\nreturn module.value()',
        7,
    ),
    (
        "importlib_call_alias",
        'f = importlib.call\nreturn f("con_host_callable_target", "value")',
        7,
    ),
    (
        "host_callback_in_dict",
        'functions = {"hash": hashlib.sha256_text}\nreturn functions["hash"]("abc")',
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    ),
]


def execute_case(home, body, *, native, meter=False, prefix=""):
    source = (
        prefix
        + "state = Variable()\n@export\ndef probe():\n"
        + "".join("    " + line + "\n" for line in body.splitlines())
    )
    target = "state = Variable()\nledger = Hash()\n@export\ndef value():\n    return 7\n"
    with Driver(storage_home=home) as driver:
        driver.set_contract_from_source("con_host_callable_target", target, owner=None)
        driver.set("con_host_callable_target.state", 7)
        driver.set("con_host_callable_target.ledger:ready", 9)
        driver.set_contract_from_source("con_host_callables", source, owner="alice")
        driver.commit()
        if native:
            from xian_vm_core import execute_contract

            result = execute_contract(
                driver=driver,
                contract_name="con_host_callables",
                function_name="probe",
                kwargs={},
                context={"caller": "alice", "signer": "alice", "this": "con_host_callables"},
                meter=meter,
            )
            return result.status_code, result.result, result.writes
        result = Executor(driver=driver, metering=False).execute(
            sender="alice",
            contract_name="con_host_callables",
            function_name="probe",
            kwargs={},
            metering=False,
        )
        return result["status_code"], result["result"], result["writes"]


@pytest.mark.parametrize("native", [False, True], ids=["python", "native"])
@pytest.mark.parametrize("binding", CALLABLE_BINDINGS)
def test_admitted_host_callable_can_be_retrieved(tmp_path, native, binding):
    status, result, _ = execute_case(tmp_path, f"f = {binding}\nreturn f is f", native=native)
    assert status == 0, result
    assert result is True


@pytest.mark.parametrize("native", [False, True], ids=["python", "native"])
@pytest.mark.parametrize(
    ("case_id", "body", "expected"), NOMINAL_CASES, ids=[case[0] for case in NOMINAL_CASES]
)
def test_host_callable_alias_semantics(tmp_path, native, case_id, body, expected):
    status, result, _ = execute_case(tmp_path, body, native=native)
    assert status == 0, result
    assert result == expected


@pytest.mark.parametrize(
    "expression",
    [
        "int",
        "abs",
        "hashlib.sha3",
        "[hashlib.sha3]",
        "decimal",
        "[datetime.datetime]",
        '{"factory": datetime.timedelta}',
    ],
)
@pytest.mark.parametrize("meter", [False, True])
@pytest.mark.parametrize("operation", ["store", "return"])
def test_host_callables_cannot_escape_execution(tmp_path, expression, operation, meter):
    body = f"state.set({expression})\nreturn 1" if operation == "store" else f"return {expression}"
    status, result, writes = execute_case(tmp_path, body, native=True, meter=meter)
    assert status == 1, result
    assert "cannot cross" in str(result), result
    assert writes == {}


HOST_ALIAS_EXCLUSIONS = {
    "Variable": "ORM declaration aliases are forbidden",
    "Hash": "ORM declaration aliases are forbidden",
    "ForeignVariable": "ORM declaration aliases are forbidden",
    "ForeignHash": "ORM declaration aliases are forbidden",
    "LogEvent": "ORM declaration aliases are forbidden",
    "Variable.get": "Bound storage receiver required",
    "Variable.set": "Bound storage receiver required",
    "Hash.all": "Bound storage receiver required",
    "ForeignVariable.get": "Bound storage receiver required",
    "ForeignHash.all": "Bound storage receiver required",
    "Hash.__getitem__": "Private synthetic operation",
    "Hash.__setitem__": "Private synthetic operation",
    "ForeignHash.__getitem__": "Private synthetic operation",
    "LogEvent.__call__": "Private synthetic operation",
    "__Contract": "Private synthetic operation",
    "__contract_export__": "Private synthetic operation",
}


def test_host_callable_snapshot_covers_catalog_with_reviewed_exclusions():
    from contracting.compilation.ir import HOST_BINDINGS

    syscalls = {item["binding"] for item in HOST_BINDINGS if item["kind"] == "syscall"}
    assert set(HOST_ALIAS_EXCLUSIONS) <= syscalls
    assert set(CALLABLE_BINDINGS) == syscalls - set(HOST_ALIAS_EXCLUSIONS)


@pytest.mark.parametrize("value", ["int", "decimal", "hashlib.sha3", "[datetime.timedelta]"])
@pytest.mark.parametrize("meter", [False, True])
def test_ordinary_host_arguments_reject_callable_capabilities(tmp_path, value, meter):
    status, result, writes = execute_case(
        tmp_path, f"state.set(9)\nrandom.seed({value})\nreturn 1", native=True, meter=meter
    )
    assert status == 1, result
    assert "cannot cross" in str(result), result
    assert writes == {}


def run_metered_callbacks(home, count, *, budget=1_000_000):
    source = """
state = Variable()
@export
def probe(count: int):
    state.set(9)
    f = hashlib.sha256_text
    values = list(map(f, ["abc"] * count))
    return len(values)
"""
    return run_metered_source(home, source, {"count": count}, budget=budget)


def run_metered_source(home, source, kwargs, *, budget=1_000_000):
    from xian_vm_core import execute_contract

    with Driver(storage_home=home) as driver:
        driver.set_contract_from_source("con_host_meter", source, owner=None)
        driver.commit()
        return execute_contract(
            driver=driver,
            contract_name="con_host_meter",
            function_name="probe",
            kwargs=kwargs,
            context={"caller": "alice", "signer": "alice", "this": "con_host_meter"},
            meter=True,
            chi_budget_raw=budget,
        )


def test_host_callback_work_is_charged_per_invocation(tmp_path):
    small = run_metered_callbacks(tmp_path / "small", 10)
    large = run_metered_callbacks(tmp_path / "large", 20)
    assert small.status_code == large.status_code == 0
    assert (small.result, large.result) == (10, 20)
    assert large.raw_cost - small.raw_cost >= 10 * 5_000


def test_host_callback_budget_failure_rolls_back_prior_writes(tmp_path):
    small = run_metered_callbacks(tmp_path / "small", 1, budget=100_000)
    assert small.status_code == 0, small.result
    large = run_metered_callbacks(tmp_path / "large", 30, budget=100_000)
    assert large.status_code == 1, large.result
    assert "Out of chi" in str(large.result), large.result
    assert large.writes == {} and large.events == []


@pytest.mark.parametrize("binding", CALLABLE_BINDINGS)
def test_host_callable_unknown_keyword_is_controlled_and_rolls_back(tmp_path, binding):
    status, result, writes = execute_case(
        tmp_path, f"state.set(9)\nf = {binding}\nf(unexpected_parameter=1)\nreturn 1", native=True
    )
    assert status == 1, result
    assert isinstance(result, str), result
    assert "keyword" in result or (
        binding == "indexed" and "positional arguments only" in result
    ), result
    assert writes == {}


@pytest.mark.parametrize("keyword", ["driver", "deployment_artifacts"])
def test_deploy_host_only_keywords_are_not_admitted(tmp_path, keyword):
    status, result, writes = execute_case(
        tmp_path,
        f"f = Contract.deploy\nf(name='con_child', code='ignored', {keyword}=None)\nreturn 1",
        native=True,
    )
    assert status == 1, result
    assert "unexpected keyword" in str(result), result
    assert writes == {}


@pytest.mark.parametrize("native", [False, True], ids=["python", "native"])
def test_static_and_dynamic_import_function_identity(tmp_path, native):
    body = """static = con_host_callable_target
module = importlib.import_module("con_host_callable_target")
other = importlib.import_module("con_host_callable_target")
return [static is static, module is module, module is other, static is module, static.value is static.value, module.value is module.value, static.value == module.value]"""
    status, result, _ = execute_case(
        tmp_path, body, native=native, prefix="import con_host_callable_target\n"
    )
    assert status == 0, result
    assert result == [True, True, False, False, True, True, False]


def test_class_and_instance_strptime_callbacks_pay_the_same_dispatch_work(tmp_path):
    deltas = []
    for label, origin in [
        ("class", "datetime.datetime.strptime"),
        ("instance", "datetime.datetime(2000, 1, 1).strptime"),
    ]:
        costs = []
        source = (
            "@export\ndef probe(count: int):\n"
            f"    f = {origin}\n"
            '    return len(list(map(f, ["2026"] * count, ["%Y"] * count)))\n'
        )
        for count in [10, 20]:
            result = run_metered_source(tmp_path / f"{label}-{count}", source, {"count": count})
            assert result.status_code == 0, result.result
            assert result.result == count
            costs.append(result.raw_cost)
        deltas.append(costs[1] - costs[0])
    assert deltas[0] == deltas[1]
    assert deltas[0] >= 10 * 5_000
