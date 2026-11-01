"""Subject metadata and its byte-based inspection fees stay explicit."""

import pytest

from contracting.execution.interface_subject import (
    InterfaceSubject,
    charge_subject_match,
    make_interface_subject,
    storage_subject_matches,
)
from contracting.execution.runtime import contract_execution_scope, rt
from contracting.stdlib.bridge.orm import H, V


def test_subject_metadata_fees_and_family_checks(monkeypatch):
    charges = []
    monkeypatch.setattr(rt, "deduct_execution_cost", charges.append)

    def transfer(amount, to):
        return None

    function = make_interface_subject(transfer, "alias")
    assert (function.kind, function.name, function.args, function.storage_type) == (
        "function",
        "transfer",
        ("amount", "to"),
        None,
    )
    # 19 bytes/tags of function metadata + alias(5) + four exposed fields.
    assert charges == [28]
    charge_subject_match(function)
    assert charges == [28, 19]
    storage = make_interface_subject(object.__new__(V), "__balance")
    assert (storage.kind, storage.name, storage.args, storage.storage_type) == (
        "storage",
        "__balance",
        None,
        "Variable",
    )
    charge_subject_match(storage)
    assert charges == [28, 19, 22, 18]
    assert storage_subject_matches(storage, V)
    assert not storage_subject_matches(storage, H)
    assert not storage_subject_matches(function, V)


def test_subject_has_no_authored_constructor_or_mutable_attributes():
    subject = InterfaceSubject("function", "probe", ())
    with contract_execution_scope():
        with pytest.raises(TypeError, match="no public constructor"):
            InterfaceSubject("storage", "forged", storage_type="Variable")
    with pytest.raises(TypeError, match="read-only"):
        subject.name = "changed"
    with pytest.raises(TypeError, match="read-only"):
        del subject.args
    assert repr(subject) == "<InterfaceSubject>"
