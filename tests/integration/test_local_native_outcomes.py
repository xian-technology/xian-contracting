"""The default local executor reports transaction outcomes like the native node."""

from decimal import Decimal

import pytest

from contracting.local import ContractingClient


def test_local_numeric_admission_reports_failure_without_changing_pending_state(tmp_path):
    source = """balance = Variable()
@export
def record(amount: decimal):
    balance.set(amount)
    return ctx.submission_name
@export
def read():
    return balance.get()
"""
    with ContractingClient(storage_home=tmp_path) as client:
        client.submit(source, name="con_account")
        account = client.get_contract_proxy("con_account")
        initial = Decimal("1.000000000000000000000000000001")
        account.record(amount=initial)
        for amount, error_type in [
            (0.25, TypeError),
            (Decimal("1e-31"), ValueError),
            (2**512, ValueError),
        ]:
            failure = account.record(amount=amount, return_full_output=True)
            assert failure["status_code"] == 1
            assert isinstance(failure["result"], error_type)
            assert failure["writes"] == {}
            assert failure["events"] == []
            assert failure["chi_used"] == 0
            assert account.read() == initial
            with pytest.raises(error_type):
                account.record(amount=amount)

        assert account.record(amount=2, environment={"submission_name": "stale"}) is None
        assert account.read() == 2
