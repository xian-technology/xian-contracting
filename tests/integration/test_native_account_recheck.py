"""Exercise the trusted CheckTx cache after the application has authenticated a spend."""

import json
from functools import lru_cache

import pytest
from xian_vm_core import BlockState, LmdbEnvironment, TransactionAdmissionCache

SENDER = "ab" * 32
POLICY_KEY = b"_accounts.policy"
POLICY = b'{"transition_chi":100,"version":2}'
RECORD_KEY = ("_accounts.records:" + SENDER).encode()
BALANCE = ("currency.balances:" + SENDER).encode()
NONCE = ("__n." + SENDER + ":").encode()


@pytest.fixture(scope="module")
def admitted():
    from nacl.signing import SigningKey
    from xian_vm_core import verify_account_components

    hybrid = pytest.importorskip("xian_accounts.hybrid")
    pytest.importorskip("pqcrypto")

    def material():
        ed = SigningKey.generate()
        pq, secret = hybrid.backend().generate_keypair()
        return hybrid.PublicKeys(bytes(ed.verify_key), pq), bytes(ed), secret

    keys, seed, pq_secret = material()
    record = hybrid.AccountRecord(0, keys, material()[0])
    witness = json.dumps(record.to_dict(), sort_keys=True, separators=(",", ":")).encode()

    @lru_cache(maxsize=2)
    def wire(nonce=1):
        payload = {
            "chain_id": "local",
            "sender": SENDER,
            "nonce": nonce,
            "chi_supplied": 100,
            "contract": "currency",
            "function": "transfer",
            "kwargs": {"to": "bob", "amount": 2},
        }
        message = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        proof = hybrid.sign(keys, 0, message, ed_seed=seed, pq_secret=pq_secret)
        assert hybrid.verify(keys, 0, message, proof, verifier=verify_account_components)
        return hybrid.compact_transaction(message, proof)

    return wire, witness


def test_compact_recheck_reuses_only_the_exact_authenticated_authority(tmp_path, admitted):
    admitted_wire, record = admitted
    cache = TransactionAdmissionCache("local", max_entries=8, max_bytes=128_000)
    env = LmdbEnvironment(tmp_path, 1024 * 1024)
    env.write(
        [(POLICY_KEY, POLICY), (RECORD_KEY, record), (BALANCE, b"12"), (b"chi_cost.S:value", b"10")]
    )
    overlay = BlockState()
    wire = admitted_wire()

    def check(raw=wire, limit=100, balance=True):
        return cache.check_account_live(raw, env, overlay, max_chi=limit, require_balance=balance)

    assert check() is False
    cache.remember_account(wire, record, POLICY)
    assert check() is True
    assert check(admitted_wire(2)) is False
    assert check(wire[:100] + bytes([wire[100] ^ 1]) + wire[101:]) is False
    with pytest.raises(ValueError):
        cache.decode(wire)
    with pytest.raises(ValueError):
        cache.check_live(wire, env, overlay, max_chi=100, require_balance=True)
    assert (
        TransactionAdmissionCache("local", max_entries=8, max_bytes=128_000).check_account_live(
            wire, env, overlay, max_chi=100, require_balance=True
        )
        is False
    )

    for key, old, changed in [
        (POLICY_KEY, POLICY, b'{"version":2,"transition_chi":101}'),
        (RECORD_KEY, record, b'{"epoch":1}'),
        (RECORD_KEY, record, None),
        (POLICY_KEY, POLICY, None),
    ]:
        env.write([(key, changed)])
        assert check() is False
        env.write([(key, old)])
        assert check() is True

    env.write([(BALANCE, b"11")])
    with pytest.raises(ValueError, match="amount plus"):
        check()
    assert check(balance=False) is True
    env.write([(BALANCE, b"12"), (b"chi_cost.S:value", b"1")])
    with pytest.raises(ValueError, match="balance cannot cover"):
        check()
    with pytest.raises(ValueError, match="per-transaction limit"):
        check(limit=99)
    env.write([(NONCE, b"1")])
    with pytest.raises(ValueError, match="nonce"):
        check(balance=False)
    env.write([(NONCE, b"{}")])
    assert check() is False
    overlay.write_value("con_x.v", 1)
    assert check(balance=False) is False


def test_cache_budget_replacement_and_policy_do_not_widen_admission(tmp_path, admitted):
    admitted_wire, record = admitted
    env = LmdbEnvironment(tmp_path, 1024 * 1024)
    env.write([(POLICY_KEY, POLICY), (RECORD_KEY, record)])
    overlay = BlockState()
    wire = admitted_wire()

    for max_entries, max_bytes in [(0, 100000), (10, 100)]:
        cache = TransactionAdmissionCache("local", max_entries=max_entries, max_bytes=max_bytes)
        cache.remember_account(wire, record, POLICY)
        assert cache.stats()["entries"] == 0
    wrong = TransactionAdmissionCache("other", max_entries=3, max_bytes=128000)
    with pytest.raises(ValueError):
        wrong.remember_account(wire, record, POLICY)

    cache = TransactionAdmissionCache("local", max_entries=1, max_bytes=128000)
    cache.remember_account(wire, record, POLICY)
    retained = cache.stats()["retained_bytes"]
    assert retained > len(wire) + len(record) + len(POLICY)
    tight = TransactionAdmissionCache("local", max_entries=8, max_bytes=retained - 1)
    tight.remember_account(wire, record, POLICY)
    assert tight.stats()["entries"] == 0
    cache.remember_account(wire, record, POLICY)
    assert cache.stats()["retained_bytes"] == retained
    cache.remember_account(admitted_wire(2), record, POLICY)
    assert cache.stats()["entries"] == 1
    assert not cache.check_account_live(wire, env, overlay, max_chi=None, require_balance=False)
    with pytest.raises(ValueError):
        cache.remember_account(
            wire, record, b'{"version":1,"transition_chi":100,"enrollment_open":false}'
        )
