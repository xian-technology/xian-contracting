import json

import pytest
from nacl.signing import SigningKey
from xian_vm_core import TransactionAdmissionCache, decode_and_validate_transaction


def signed_wire(nonce, *, chain_id="local"):
    key = SigningKey(bytes(32))
    payload = {
        "chain_id": chain_id,
        "contract": "currency",
        "function": "transfer",
        "kwargs": {"amount": {"__fixed__": "1.25"}},
        "nonce": nonce,
        "sender": key.verify_key.encode().hex(),
        "chi_supplied": 10,
    }
    signature = key.sign(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
    document = {"metadata": {"signature": signature.signature.hex()}, "payload": payload}
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode().hex().encode()


def test_cached_admission_returns_fresh_documents():
    cache = TransactionAdmissionCache("local", max_entries=2, max_bytes=64_000)
    raw = signed_wire(0)
    expected = decode_and_validate_transaction(raw, "local")

    decoded = cache.decode(raw)
    assert decoded == expected
    decoded["payload"]["kwargs"]["amount"]["__fixed__"] = "999"
    decoded["b_meta"] = {"nanos": 100}

    assert cache.decode(raw) == expected
    stats = cache.stats()
    assert (stats["hits"], stats["misses"], stats["entries"]) == (1, 1, 1)
    assert len(raw) <= stats["retained_bytes"] <= 64_000


def test_cache_keys_are_exact_and_instances_are_isolated():
    first = TransactionAdmissionCache("local", max_entries=2, max_bytes=64_000)
    second = TransactionAdmissionCache("other", max_entries=2, max_bytes=64_000)
    raw = signed_wire(0)
    first.decode(raw)

    assert first.chain_id == "local"
    with pytest.raises(AttributeError):
        first.chain_id = "other"

    for cache, refused, chain_id in (
        (first, raw.upper(), "local"),
        (second, raw, "other"),
    ):
        with pytest.raises(ValueError) as uncached:
            decode_and_validate_transaction(refused, chain_id)
        for _ in range(2):
            with pytest.raises(ValueError) as cached:
                cache.decode(refused)
            assert str(cached.value) == str(uncached.value)

    assert first.stats()["entries"] == 1
    assert second.stats()["entries"] == 0
    assert second.stats()["misses"] == 2
    assert first.stats()["hits"] == second.stats()["hits"] == 0


def test_cache_evicts_the_least_recently_used_transaction():
    cache = TransactionAdmissionCache("local", max_entries=2, max_bytes=64_000)
    first, second, third = (signed_wire(nonce) for nonce in range(3))
    for raw in [first, second, first, third, first]:
        cache.decode(raw)
    stats = cache.stats()
    assert (stats["hits"], stats["misses"], stats["evictions"], stats["entries"]) == (2, 3, 1, 2)

    cache.decode(second)
    assert cache.stats()["misses"] == 4


def test_byte_budget_evicts_even_when_entry_slots_remain():
    raw = signed_wire(0)
    sizing = TransactionAdmissionCache("local", max_entries=10, max_bytes=64_000)
    sizing.decode(raw)
    budget = sizing.stats()["retained_bytes"]

    cache = TransactionAdmissionCache("local", max_entries=10, max_bytes=budget)
    cache.decode(raw)
    cache.decode(signed_wire(1))
    stats = cache.stats()
    assert stats["retained_bytes"] == budget
    assert stats["evictions"] == stats["entries"] == 1

    larger = signed_wire(12)
    assert cache.decode(larger) == decode_and_validate_transaction(larger, "local")
    cache.decode(signed_wire(1))
    assert cache.stats() == {
        "hits": 1,
        "misses": 3,
        "evictions": 1,
        "entries": 1,
        "retained_bytes": budget,
    }


@pytest.mark.parametrize("max_entries,max_bytes", [(0, 64_000), (2, 0), (2, 1)])
def test_disabled_or_too_small_cache_admits_without_retaining(max_entries, max_bytes):
    cache = TransactionAdmissionCache("local", max_entries=max_entries, max_bytes=max_bytes)
    raw = signed_wire(0)
    expected = decode_and_validate_transaction(raw, "local")

    assert cache.decode(raw) == cache.decode(raw) == expected
    assert cache.stats() == {
        "hits": 0,
        "misses": 2,
        "evictions": 0,
        "entries": 0,
        "retained_bytes": 0,
    }
