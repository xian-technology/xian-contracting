"""The ABCI application calls the explicit transition path after checking proofs."""

import json

import pytest
from xian_vm_core import BlockExecutor, BlockState, LmdbEnvironment

SENDER = "ab" * 32
RECORD = {"epoch": 0, "version": 1, "active": {"example": "new"}}


def raw(contract="_accounts", function="rotate", metadata=None):
    document = {
        "payload": {
            "contract": contract,
            "function": function,
            "kwargs": {"record": RECORD},
            "chain_id": "local",
            "chi_supplied": 100,
            "sender": SENDER,
            "nonce": 8,
        },
        "metadata": metadata or {"tx_format": "xian_account_v1", "auth": {"signature": "proof"}},
    }
    return json.dumps(document, separators=(",", ":"), sort_keys=True).encode().hex().encode()


def executor(tmp_path):
    state = BlockState()
    env = LmdbEnvironment(tmp_path, 1024 * 1024)
    state.write_value("chi_cost.S:value", 1)
    return BlockExecutor(
        env,
        state,
        meter_execution=True,
        charge_fees=True,
        distribute_fee_rewards=False,
        protected_keys=[],
        zk_enabled_without_state=False,
        block_meta={"height": 3, "hash": "ab", "chain_id": "local", "nanos": 0},
    ), state


def test_transition_only_enters_via_authenticated_node_path(tmp_path):
    ex, _ = executor(tmp_path)
    with pytest.raises(ValueError):
        ex.add(raw())
    for wire, fee in [
        (raw(contract="currency"), 5),
        (raw(function="erase"), 5),
        (raw(metadata={"signature": "classical"}), 5),
        (raw(), 101),
        (raw(), 0),
    ]:
        with pytest.raises(ValueError):
            ex.add_account_transition(wire, fee)


@pytest.mark.parametrize("balance, success", [(150, True), (0, False)])
def test_transition_record_and_fee_share_one_successful_outcome(tmp_path, balance, success):
    ex, state = executor(tmp_path)
    balance_key = f"currency.balances:{SENDER}"
    state.write_value(balance_key, balance)
    ex.add_account_transition(raw(), 100)
    (outcome,) = ex.run()
    assert (outcome[0] == 0) is success
    record_key = f"_accounts.records:{SENDER}"
    assert state.lookup(record_key)[0] is success
    if success:
        assert json.loads(state.lookup(record_key)[1]) == RECORD
        assert outcome[5] == 100
        assert dict(outcome[3])[balance_key] == 50


def test_cached_classical_signature_rechecks_current_policy_and_enrollment(tmp_path):
    from nacl.signing import SigningKey
    from xian_vm_core import TransactionAdmissionCache

    key = SigningKey(bytes([9]) * 32)
    sender = key.verify_key.encode().hex()
    payload = json.loads(bytes.fromhex(raw(contract="currency").decode()))["payload"]
    payload["sender"] = sender

    def encoded(value):
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()

    document = {
        "payload": payload,
        "metadata": {"signature": key.sign(encoded(payload)).signature.hex()},
    }
    wire = encoded(document).hex().encode()
    cache = TransactionAdmissionCache("local", max_entries=2, max_bytes=65536)
    cache.decode(wire)
    env = LmdbEnvironment(tmp_path, 1024 * 1024)
    state = BlockState()

    def check():
        return cache.check_live(wire, env, state, max_chi=100, require_balance=False)

    assert check() is None
    assert not cache.check_account_live(wire, env, state, max_chi=100, require_balance=False)
    record = ("_accounts.records:" + sender).encode()
    env.write([(record, b"null")])
    with pytest.raises(ValueError, match="hybrid"):
        check()
    env.write([(record, None), (b"_accounts.policy", b'{"transition_chi":10,"version":2}')])
    with pytest.raises(ValueError, match="hybrid"):
        check()


@pytest.mark.parametrize("route", ["direct", "alias", "callback"])
def test_classical_permit_fails_for_enrolled_and_strict_unknown_owners(tmp_path, route):
    from nacl.signing import SigningKey
    from contracting.storage.driver import Driver
    from tests.vm_calls import execute_contract

    signer = SigningKey(bytes([8]) * 32)
    owner = signer.verify_key.encode().hex()
    signature = signer.sign(b"permit").signature.hex()
    args = f'"{owner.upper()}", "permit", "{signature}"'
    body = {
        "direct": f"return crypto.verify({args})",
        "alias": f"verify = crypto.verify\n    return verify({args})",
        "callback": f'return list(map(crypto.verify, ["{owner.upper()}"], ["permit"], ["{signature}"]))[0]',
    }[route]
    with Driver(storage_home=tmp_path) as driver:
        driver.set_contract_from_source(
            "con_permit", f"@export\ndef check():\n    {body}\n", owner=None
        )

        def verify():
            driver.commit()
            result = execute_contract(
                driver=driver,
                contract_name="con_permit",
                function_name="check",
                kwargs={},
                context={"caller": "alice", "signer": "alice", "this": "con_permit"},
                meter=True,
                chi_budget_raw=10_000_000,
            )
            assert result.status_code == 0, result.result
            return result.result

        assert verify() is True
        driver.set("_accounts.records:" + owner, {"malformed": True})
        assert verify() is False
        driver.set("_accounts.records:" + owner, None)
        driver.set("_accounts.policy", {"version": 2, "transition_chi": 10})
        assert verify() is False
