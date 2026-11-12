"""``Driver.discarding_changes`` undoes exactly what one execution changed.

Transaction execution used to deep-copy the whole pending block state before
every transaction and copy it back afterwards. The discarding scope records the
first previous value of every entry it touches instead; leaving the scope must
restore the same state ``snapshot_state``/``restore_state`` would have.
"""

import random
from copy import deepcopy

import pytest

from contracting.storage.driver import Driver

CONTAINERS = (
    "pending_writes",
    "pending_reads",
    "transaction_reads",
    "transaction_writes",
)


def pending_state(driver):
    """Everything restore_state restores, with dict order and value identity."""
    state = {name: list(getattr(driver, name).items()) for name in CONTAINERS}
    state["transaction_read_prefixes"] = set(driver.transaction_read_prefixes)
    state["log_events"] = list(driver.log_events)
    state["pending_deltas"] = deepcopy(driver.pending_deltas)
    return state


@pytest.fixture
def driver():
    driver = Driver(bypass_cache=False)
    driver.flush_full()
    driver.set("con_thing.balances:carol", 5)
    driver.commit()
    driver.set("con_thing.balances:alice", 10, is_txn_write=True)
    driver.set("con_thing.items:alice", [1, 2], is_txn_write=True)
    driver.get("con_thing.balances:bob")
    driver.keys_from_disk("con_thing.")
    driver.set_event({"event": "Transfer"})
    driver.pending_deltas["100"] = {"writes": {}, "reads": {}}
    yield driver
    driver.flush_full()
    driver.close()


def touch_everything(driver):
    driver.get("con_thing.balances:carol")
    driver.get("con_thing.balances:dave")
    driver.set("con_thing.balances:alice", 11, is_txn_write=True)
    driver.set("con_thing.balances:erin", 3, is_txn_write=True)
    driver.delete("con_thing.balances:carol")
    driver.apply_writes({"con_thing.balances:frank": 4, "con_thing.items:alice": [9]})
    driver.set_event({"event": "Junk"})
    driver.keys_from_disk("con_other.")
    driver.iter_from_disk("con_thing.")
    driver.scan_keys_from_disk("con_scan.")
    list(driver.iter_items("con_iter."))


def test_leaving_the_scope_restores_the_exact_pending_state(driver):
    before = pending_state(driver)

    with driver.discarding_changes():
        touch_everything(driver)
        assert pending_state(driver) != before

    assert pending_state(driver) == before


def test_restored_entries_keep_their_original_values_and_order(driver):
    items_before = driver.pending_writes["con_thing.items:alice"]
    order_before = list(driver.pending_writes)

    with driver.discarding_changes():
        touch_everything(driver)

    assert driver.pending_writes["con_thing.items:alice"] is items_before
    assert list(driver.pending_writes) == order_before


def test_the_scope_is_undone_when_execution_raises(driver):
    before = pending_state(driver)

    with pytest.raises(ZeroDivisionError):
        with driver.discarding_changes():
            touch_everything(driver)
            raise ZeroDivisionError

    assert pending_state(driver) == before


def test_changes_after_the_scope_are_kept(driver):
    with driver.discarding_changes():
        driver.set("con_thing.balances:alice", 99)

    driver.set("con_thing.balances:alice", 12)
    driver.set_event({"event": "Kept"})

    assert driver.pending_writes["con_thing.balances:alice"] == 12
    assert driver.log_events[-1] == {"event": "Kept"}


def test_reads_inside_the_scope_see_the_scope_writes(driver):
    with driver.discarding_changes():
        driver.set("con_thing.balances:alice", 42)
        assert driver.get("con_thing.balances:alice") == 42
        assert driver.transaction_reads["con_thing.balances:bob"] is None

    assert driver.get("con_thing.balances:alice") == 10


def test_scopes_do_not_nest(driver):
    with driver.discarding_changes():
        with pytest.raises(RuntimeError, match="already open"):
            with driver.discarding_changes():
                pass


@pytest.mark.parametrize(
    "operation",
    [
        lambda d: d.commit(),
        lambda d: d.hard_apply("200"),
        lambda d: d.rollback(),
        lambda d: d.rollback("100"),
        lambda d: d.flush_cache(),
        lambda d: d.flush_full(),
        lambda d: d.clear_transaction_writes(),
        lambda d: d.clear_transaction_reads(),
        lambda d: d.clear_events(),
        lambda d: d.set_transaction_read_tracking(False),
        lambda d: d.restore_state(d.snapshot_state()),
        lambda d: d.detach_pending_state(),
        lambda d: d.attach_pending_state(d.detach_pending_state()),
        lambda d: d.delete_contract("con_thing"),
    ],
)
def test_bulk_operations_cannot_run_inside_a_scope(driver, operation):
    before = pending_state(driver)

    with driver.discarding_changes():
        with pytest.raises(RuntimeError, match="discarding scope"):
            operation(driver)

    assert pending_state(driver) == before


def test_replacing_a_container_inside_a_scope_is_rejected(driver):
    with pytest.raises(RuntimeError, match="replaced"):
        with driver.discarding_changes():
            driver.pending_writes = {}


def _random_operation(rng, driver):
    key = f"con_rand.v:{rng.randrange(12)}"
    choice = rng.randrange(7)
    if choice == 0:
        driver.get(key)
    elif choice == 1:
        driver.set(
            key, rng.choice([None, 1, "x", [rng.randrange(3)]]), is_txn_write=rng.random() < 0.5
        )
    elif choice == 2:
        driver.apply_writes({key: rng.randrange(5)})
    elif choice == 3:
        driver.set_event({"n": rng.randrange(5)})
    elif choice == 4:
        driver.keys_from_disk(f"con_rand.{rng.randrange(3)}")
    elif choice == 5:
        driver.get(key, save=False)
    else:
        list(driver.iter_items(key))


@pytest.mark.parametrize("seed", range(25))
def test_random_executions_match_a_deep_copy_restore(driver, seed):
    rng = random.Random(seed)
    for _ in range(rng.randrange(30)):
        _random_operation(rng, driver)
    driver.set_transaction_read_tracking(rng.random() < 0.8)
    snapshot = driver.snapshot_state()
    steps = [rng.getstate()]

    with driver.discarding_changes():
        for _ in range(rng.randrange(60)):
            _random_operation(rng, driver)
    journaled = pending_state(driver)

    rng.setstate(steps[0])
    for _ in range(rng.randrange(60)):
        _random_operation(rng, driver)
    driver.restore_state(snapshot)

    assert journaled == pending_state(driver)


def test_apply_writes_with_an_unstorable_value_changes_nothing(driver):
    before = pending_state(driver)

    with pytest.raises((TypeError, ValueError)):
        driver.apply_writes({"con_thing.ok": 1, "con_thing.bad": object()})

    assert pending_state(driver) == before
