"""Hash prefix operations select the whole hash only when called without prefix.

An empty-string prefix is an ordinary first dimension: ``h.clear("")`` and
``h.all("")`` affect only keys whose first dimension is ``""``.
"""

from contracting.local import ContractingClient
from contracting.storage.driver import Driver
from contracting.storage.orm import ForeignHash, Hash

SOURCE = """
records = Hash(default_value=0)

@export
def seed():
    records['', 'x'] = 1
    records['a', 'x'] = 2
    records['solo'] = 3

@export
def all_empty():
    return records.all('')

@export
def all_everything():
    return sorted(records.all())

@export
def clear_empty():
    records.clear('')
    return sorted(records.all())
"""

READER = """
foreign = ForeignHash(foreign_contract='con_prefix_owner', foreign_name='records')

@export
def foreign_empty():
    return foreign.all('')
"""


def _seeded_hash(driver):
    records = Hash("con_orm_prefix", "records", driver=driver)
    records["", "x"] = 1
    records["a", "x"] = 2
    records["solo"] = 3
    return records


def test_orm_empty_prefix_is_a_first_dimension(tmp_path):
    with Driver(storage_home=tmp_path / "orm") as driver:
        records = _seeded_hash(driver)
        foreign = ForeignHash(
            "con_orm_reader",
            "foreign",
            foreign_contract="con_orm_prefix",
            foreign_name="records",
            driver=driver,
        )
        assert records.all("") == [1]
        assert foreign.all("") == [1]
        assert sorted(records.all()) == [1, 2, 3]
        records.clear("")
        assert sorted(records.all()) == [2, 3]


def test_native_empty_prefix_is_a_first_dimension():
    client = ContractingClient(signer="stu")
    try:
        client.flush()
        client.submit(SOURCE, name="con_prefix_owner")
        client.submit(READER, name="con_prefix_reader")
        owner = client.get_contract_proxy("con_prefix_owner")
        owner.seed()
        assert owner.all_empty() == [1]
        assert owner.all_everything() == [1, 2, 3]
        assert client.get_contract_proxy("con_prefix_reader").foreign_empty() == [1]
        assert owner.clear_empty() == [2, 3]
    finally:
        client.close()
