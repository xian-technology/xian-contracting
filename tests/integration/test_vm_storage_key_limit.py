"""A storage key is at most 511 bytes: the largest key LMDB 0.9 stores.

V2 fails the transaction at the write that forms a longer key. Archival V1
execution is unchanged; the driver refuses to stage such a key in every
profile, so it can never reach a commit.
"""

import pytest
from xian_vm_core import MAX_STORAGE_KEY_BYTES, execute_contract

from contracting.artifacts import compile_contract_source
from contracting.local import ContractingClient
from contracting.storage.driver import Driver

LIMIT_ERROR = "Storage key is too long (512 bytes). Max is 511."
CONTRACT = "con_keys"
# "con_keys.data:" is 14 bytes; every write below forms a 512-byte key except
# largest_key, which forms exactly 511.
TARGET = "t" * 102
LONG_VARIABLE = "v" * 503
SOURCE = (
    f"data = Hash(default_value=0)\n{TARGET} = Hash()\n{LONG_VARIABLE} = Variable()\n\n"
    "@export\ndef hash_key():\n    data['x' * 498] = 1\n"
    "@export\ndef mutate_key():\n    data['x' * 498] += 1\n"
    "@export\ndef utf8_key():\n    data['\\u00e9' * 249] = 1\n"
    "@export\ndef multi_key():\n    data['x' * 248, 'y' * 249] = 1\n"
    f"@export\ndef variable_key():\n    {LONG_VARIABLE}.set(1)\n"
    f"@export\ndef clone_key():\n    data['k' * 400] = 1\n    {TARGET}.clone_from(data)\n"
    "@export\ndef largest_key():\n    data['x' * 497] = 1\n"
    "@export\ndef read(size: int):\n    return data['r' * size]\n"
)
OVER_LONG = ["hash_key", "mutate_key", "utf8_key", "multi_key", "variable_key", "clone_key"]
LARGEST_KEY = f"{CONTRACT}.data:{'x' * 497}"


def test_the_limit_is_lmdbs_largest_key():
    assert MAX_STORAGE_KEY_BYTES == 511
    assert len(LARGEST_KEY.encode()) == MAX_STORAGE_KEY_BYTES


@pytest.fixture
def driver(tmp_path, profile):
    with Driver(storage_home=tmp_path / "state", vm_profile=profile) as driver:
        compiled = compile_contract_source(module_name=CONTRACT, source=SOURCE, vm_profile=profile)
        driver.set_contract(
            name=CONTRACT, source=compiled["source"], vm_ir_json=compiled["vm_ir_json"]
        )
        driver.commit()
        yield driver


def execute(driver, function, **kwargs):
    return execute_contract(
        driver=driver,
        contract_name=CONTRACT,
        function_name=function,
        kwargs=kwargs,
        context={"caller": "alice", "signer": "alice"},
        vm_profile=driver.vm_profile,
    )


@pytest.mark.parametrize("profile", ["xian_vm_v2"])
@pytest.mark.parametrize("function", OVER_LONG)
def test_v2_fails_the_write_that_forms_an_over_long_key(driver, function):
    result = execute(driver, function)

    assert result.status_code == 1
    assert LIMIT_ERROR in str(result.result)
    assert result.writes == {}


@pytest.mark.parametrize("profile", ["xian_vm_v2"])
def test_v2_stores_and_commits_the_largest_key(driver):
    result = execute(driver, "largest_key")

    assert result.status_code == 0
    assert result.writes == {LARGEST_KEY: 1}
    driver.apply_writes(result.writes)
    driver.commit()
    driver.flush_cache()
    assert driver.get(LARGEST_KEY) == 1


@pytest.mark.parametrize(
    ("profile", "size", "error"),
    [
        # A V2 hash key is bounded by the store's limit; a lookup whose whole
        # key is too long but whose hash key fits finds nothing.
        ("xian_vm_v2", 511, None),
        ("xian_vm_v2", 512, "Key is too long (512). Max is 511."),
        # Archival V1 keeps its 1024-character hash key bound.
        ("xian_vm_v1", 1024, None),
        ("xian_vm_v1", 1025, "Key is too long (1025). Max is 1024."),
    ],
)
def test_hash_key_bound_on_reads(driver, size, error):
    result = execute(driver, "read", size=size)

    if error is None:
        assert (result.status_code, result.result) == (0, 0)
    else:
        assert result.status_code == 1
        assert error in str(result.result)


@pytest.mark.parametrize("profile", ["xian_vm_v1"])
@pytest.mark.parametrize("function", OVER_LONG)
def test_archival_v1_execution_is_unchanged_but_the_key_is_never_staged(driver, function):
    result = execute(driver, function)

    assert result.status_code == 0
    over_long = [key for key in result.writes if len(key.encode()) > MAX_STORAGE_KEY_BYTES]
    assert over_long
    with pytest.raises(ValueError, match=LIMIT_ERROR.replace("(", r"\(").replace(")", r"\)")):
        driver.apply_writes(result.writes)
    assert not any(key.startswith(f"{CONTRACT}.") for key in driver.pending_writes)
    driver.commit()


def test_v2_deployment_fails_when_its_constructor_forms_an_over_long_key(tmp_path):
    source = (
        f"{LONG_VARIABLE} = Variable()\n@construct\ndef seed():\n    {LONG_VARIABLE}.set(1)\n"
        "@export\ndef read():\n    return 1\n"
    )
    with ContractingClient(storage_home=tmp_path / "client") as client:
        with pytest.raises(Exception, match="Max is 511"):
            client.submit(source, name=CONTRACT)
        client.raw_driver.commit()
        assert client.raw_driver.get_contract_source(CONTRACT) is None


@pytest.mark.parametrize("profile", ["xian_vm_v1", "xian_vm_v2"])
def test_the_driver_refuses_to_stage_an_over_long_key(tmp_path, profile):
    over_long = "k" * 512
    with Driver(storage_home=tmp_path / "state", vm_profile=profile) as driver:
        with pytest.raises(ValueError, match="Max is 511"):
            driver.set(over_long, 1)
        with pytest.raises(ValueError, match="Max is 511"):
            driver.apply_writes({"a.ok": 1, over_long: 1})
        assert driver.pending_writes == {}
        driver.set("k" * 511, 1)
        driver.commit()
        assert driver.get("k" * 511) == 1
