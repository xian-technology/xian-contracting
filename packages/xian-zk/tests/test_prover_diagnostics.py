"""Unexpected prover failures give operators safe evidence, never witness data."""

import io
import json
import logging
import re
from types import SimpleNamespace

from xian_zk.prover_service import ShieldedZkProverService


class FakeHandler:
    path = "/private-request-path?proof=private-query"
    headers = {"Authorization": "Bearer private-auth-token"}

    def __init__(self):
        self.wfile = io.BytesIO()

    def send_response(self, status):
        self.status = status

    def send_header(self, *_args):
        pass

    def end_headers(self):
        pass


def failing_service():
    service = object.__new__(ShieldedZkProverService)
    service.auth_token = "private-auth-token"

    def unexpected(_path):
        witness = "private-witness-key"
        raise RuntimeError(witness + " private-proof-bytes")

    service._handle_get = unexpected
    return service


def test_unexpected_failure_is_correlated_and_omits_secrets(caplog):
    handler = FakeHandler()
    with caplog.at_level(logging.ERROR):
        failing_service()._handle(handler, "GET")
    payload = json.loads(handler.wfile.getvalue())
    assert handler.status == 500
    assert re.fullmatch("[0-9a-f]{32}", payload["incident_id"])
    assert payload["incident_id"] in payload["error"]
    assert payload["incident_id"] in caplog.text
    assert "RuntimeError" in caplog.text
    assert "unexpected" in caplog.text
    assert "private-" not in caplog.text + json.dumps(payload)
    assert re.search(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z \| ERROR \| xian-zk/prover \|", caplog.text
    )
    assert all(record.exc_info is None for record in caplog.records)


def test_failed_operator_logging_still_returns_generic_500(monkeypatch):
    from xian_zk import prover_service

    def broken(*_args, **_kwargs):
        raise OSError("private-log-failure")

    monkeypatch.setattr(prover_service, "_LOGGER", SimpleNamespace(error=broken), raising=False)
    handler = FakeHandler()
    failing_service()._handle(handler, "GET")
    payload = json.loads(handler.wfile.getvalue())
    assert handler.status == 500
    assert re.fullmatch("[0-9a-f]{32}", payload["incident_id"])
    assert "private-" not in json.dumps(payload)


def test_diagnostics_do_not_render_exception_messages_notes_or_causes(caplog):
    class SensitiveFailure(Exception):
        def __str__(self):
            raise AssertionError("private-render-attempt")

    def unexpected(_path):
        error = SensitiveFailure("private-witness")
        error.add_note("private-note")
        raise error from ValueError("private-cause")

    service = failing_service()
    service._handle_get = unexpected
    handler = FakeHandler()
    with caplog.at_level(logging.ERROR):
        service._handle(handler, "GET")
    assert handler.status == 500
    assert "SensitiveFailure" in caplog.text
    assert "private-" not in caplog.text + handler.wfile.getvalue().decode()


def test_operator_record_is_bounded_and_single_line(caplog):
    error_type = type("Injected\n\x1b" * 1000, (Exception,), {})

    def recurse(depth):
        if depth:
            return recurse(depth - 1)
        raise error_type("private-witness")

    service = failing_service()
    service._handle_get = lambda _: recurse(50)
    with caplog.at_level(logging.ERROR):
        service._handle(FakeHandler(), "GET")
    message = caplog.records[-1].getMessage()
    assert len(message) < 2600
    assert len(message.splitlines()) == 1
    assert "\x1b" not in message
    assert message.count(";") == 15
