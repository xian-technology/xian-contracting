from __future__ import annotations

import argparse
import ipaddress
import json
import threading
import urllib.error
import urllib.request
from dataclasses import asdict, is_dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

from xian_zk.shielded_commands import (
    ShieldedCommandProofResult,
    ShieldedCommandProver,
    ShieldedCommandRequest,
)
from xian_zk.shielded_notes import (
    ShieldedDepositRequest,
    ShieldedInput,
    ShieldedNoteProver,
    ShieldedOutput,
    ShieldedProofResult,
    ShieldedTransferRequest,
    ShieldedTreeState,
    ShieldedWithdrawRequest,
)
from xian_zk.shielded_relay import (
    ShieldedRelayTransferProofResult,
    ShieldedRelayTransferProver,
    ShieldedRelayTransferRequest,
)


class ZkProverClientError(RuntimeError):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        super().__init__(message)


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True).encode("utf-8")


def _serialize_value(value: Any) -> Any:
    if is_dataclass(value):
        return asdict(value)
    return value


def _read_text(path: str | None) -> str | None:
    if path is None:
        return None
    return Path(path).expanduser().resolve().read_text()


def _is_loopback_host(host: str) -> bool:
    normalized = host.strip().lower()
    if normalized == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def _validate_bind_configuration(
    host: str,
    *,
    auth_token: str | None,
    allow_remote_host: bool,
) -> None:
    normalized = host.strip()
    if normalized == "":
        raise ValueError("host must be non-empty")
    if _is_loopback_host(normalized):
        return
    if not allow_remote_host:
        raise ValueError(
            "refusing to bind prover service to a non-loopback host without "
            "--unsafe-allow-remote-host"
        )
    if auth_token is None or auth_token.strip() == "":
        raise ValueError(
            "remote prover service requires a non-empty --auth-token"
        )


def _tree_state_from_value(
    value: ShieldedTreeState | dict[str, Any],
) -> ShieldedTreeState:
    if isinstance(value, ShieldedTreeState):
        return value
    return ShieldedTreeState(**value)


def _input_from_value(value: ShieldedInput | dict[str, Any]) -> ShieldedInput:
    if isinstance(value, ShieldedInput):
        return value
    return ShieldedInput(**value)


def _output_from_value(
    value: ShieldedOutput | dict[str, Any],
) -> ShieldedOutput:
    if isinstance(value, ShieldedOutput):
        return value
    return ShieldedOutput(**value)


def _note_deposit_request_from_value(
    value: ShieldedDepositRequest | dict[str, Any],
) -> ShieldedDepositRequest:
    if isinstance(value, ShieldedDepositRequest):
        return value
    return ShieldedDepositRequest(
        asset_id=value["asset_id"],
        old_root=value["old_root"],
        append_state=_tree_state_from_value(value["append_state"]),
        amount=value["amount"],
        outputs=[_output_from_value(item) for item in value["outputs"]],
        output_payload_hashes=list(value.get("output_payload_hashes", [])),
    )


def _note_transfer_request_from_value(
    value: ShieldedTransferRequest | dict[str, Any],
) -> ShieldedTransferRequest:
    if isinstance(value, ShieldedTransferRequest):
        return value
    return ShieldedTransferRequest(
        asset_id=value["asset_id"],
        old_root=value["old_root"],
        append_state=_tree_state_from_value(value["append_state"]),
        inputs=[_input_from_value(item) for item in value["inputs"]],
        outputs=[_output_from_value(item) for item in value["outputs"]],
        output_payload_hashes=list(value.get("output_payload_hashes", [])),
    )


def _note_withdraw_request_from_value(
    value: ShieldedWithdrawRequest | dict[str, Any],
) -> ShieldedWithdrawRequest:
    if isinstance(value, ShieldedWithdrawRequest):
        return value
    return ShieldedWithdrawRequest(
        asset_id=value["asset_id"],
        old_root=value["old_root"],
        append_state=_tree_state_from_value(value["append_state"]),
        amount=value["amount"],
        recipient=value["recipient"],
        inputs=[_input_from_value(item) for item in value["inputs"]],
        outputs=[_output_from_value(item) for item in value["outputs"]],
        output_payload_hashes=list(value.get("output_payload_hashes", [])),
    )


def _command_request_from_value(
    value: ShieldedCommandRequest | dict[str, Any],
) -> ShieldedCommandRequest:
    if isinstance(value, ShieldedCommandRequest):
        return value
    return ShieldedCommandRequest(
        asset_id=value["asset_id"],
        old_root=value["old_root"],
        append_state=_tree_state_from_value(value["append_state"]),
        fee=value["fee"],
        public_amount=value["public_amount"],
        inputs=[_input_from_value(item) for item in value["inputs"]],
        outputs=[_output_from_value(item) for item in value["outputs"]],
        target_contract=value["target_contract"],
        payload=value.get("payload"),
        relayer=value["relayer"],
        chain_id=value["chain_id"],
        expires_at=value.get("expires_at"),
        output_payload_hashes=list(value.get("output_payload_hashes", [])),
    )


def _relay_request_from_value(
    value: ShieldedRelayTransferRequest | dict[str, Any],
) -> ShieldedRelayTransferRequest:
    if isinstance(value, ShieldedRelayTransferRequest):
        return value
    return ShieldedRelayTransferRequest(
        asset_id=value["asset_id"],
        old_root=value["old_root"],
        append_state=_tree_state_from_value(value["append_state"]),
        fee=value["fee"],
        inputs=[_input_from_value(item) for item in value["inputs"]],
        outputs=[_output_from_value(item) for item in value["outputs"]],
        relayer=value["relayer"],
        chain_id=value["chain_id"],
        expires_at=value.get("expires_at"),
        output_payload_hashes=list(value.get("output_payload_hashes", [])),
    )


class _BaseProverClient:
    def __init__(self, base_url: str, *, auth_token: str | None = None):
        self.base_url = base_url.rstrip("/")
        self.auth_token = auth_token

    def _request(
        self, method: str, path: str, payload: Any | None = None
    ) -> dict[str, Any]:
        headers = {
            "Accept": "application/json",
        }
        data = None
        if payload is not None:
            data = _json_bytes(_serialize_value(payload))
            headers["Content-Type"] = "application/json"
        if self.auth_token is not None:
            headers["Authorization"] = f"Bearer {self.auth_token}"

        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=data,
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(request) as response:
                raw = response.read().decode("utf-8")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8")
            message = body
            try:
                payload = json.loads(body)
            except json.JSONDecodeError:
                payload = None
            if isinstance(payload, dict):
                error = payload.get("error")
                if isinstance(error, str) and error:
                    message = error
            raise ZkProverClientError(exc.code, message) from exc


class ShieldedNoteProverClient(_BaseProverClient):
    def registry_manifest(self) -> dict[str, Any]:
        return self._request("GET", "/v1/manifests/shielded-note")

    def prove_deposit(
        self, request: ShieldedDepositRequest | dict[str, Any]
    ) -> ShieldedProofResult:
        return ShieldedProofResult(
            **self._request("POST", "/v1/shielded-note/prove/deposit", request)
        )

    def prove_transfer(
        self, request: ShieldedTransferRequest | dict[str, Any]
    ) -> ShieldedProofResult:
        return ShieldedProofResult(
            **self._request("POST", "/v1/shielded-note/prove/transfer", request)
        )

    def prove_withdraw(
        self, request: ShieldedWithdrawRequest | dict[str, Any]
    ) -> ShieldedProofResult:
        return ShieldedProofResult(
            **self._request("POST", "/v1/shielded-note/prove/withdraw", request)
        )


class ShieldedCommandProverClient(_BaseProverClient):
    def registry_manifest(self) -> dict[str, Any]:
        return self._request("GET", "/v1/manifests/shielded-command")

    def prove_deposit(
        self, request: ShieldedDepositRequest | dict[str, Any]
    ) -> ShieldedProofResult:
        return ShieldedProofResult(
            **self._request(
                "POST", "/v1/shielded-command/prove/deposit", request
            )
        )

    def prove_execute(
        self, request: ShieldedCommandRequest | dict[str, Any]
    ) -> ShieldedCommandProofResult:
        return ShieldedCommandProofResult(
            **self._request(
                "POST", "/v1/shielded-command/prove/execute", request
            )
        )

    def prove_withdraw(
        self, request: ShieldedWithdrawRequest | dict[str, Any]
    ) -> ShieldedProofResult:
        return ShieldedProofResult(
            **self._request(
                "POST", "/v1/shielded-command/prove/withdraw", request
            )
        )


class ShieldedRelayTransferProverClient(_BaseProverClient):
    def registry_manifest(self) -> dict[str, Any]:
        return self._request("GET", "/v1/manifests/shielded-relay")

    def prove_relay_transfer(
        self, request: ShieldedRelayTransferRequest | dict[str, Any]
    ) -> ShieldedRelayTransferProofResult:
        return ShieldedRelayTransferProofResult(
            **self._request(
                "POST", "/v1/shielded-relay/prove/transfer", request
            )
        )


class ShieldedZkProverService:
    def __init__(
        self,
        *,
        note_prover: ShieldedNoteProver | None = None,
        command_prover: ShieldedCommandProver | None = None,
        relay_prover: ShieldedRelayTransferProver | None = None,
        host: str = "127.0.0.1",
        port: int = 0,
        auth_token: str | None = None,
        allow_remote_host: bool = False,
    ):
        if (
            note_prover is None
            and command_prover is None
            and relay_prover is None
        ):
            raise ValueError("at least one prover must be configured")
        _validate_bind_configuration(
            host,
            auth_token=auth_token,
            allow_remote_host=allow_remote_host,
        )
        self._note_bundle_json = (
            None if note_prover is None else note_prover.bundle_json
        )
        self._command_bundle_json = (
            None if command_prover is None else command_prover.bundle_json
        )
        self._relay_bundle_json = (
            None if relay_prover is None else relay_prover.bundle_json
        )
        if self._relay_bundle_json is None:
            self._relay_bundle_json = self._command_bundle_json
        self.auth_token = auth_token
        self._thread_state = threading.local()
        self._thread: threading.Thread | None = None
        self._server = HTTPServer((host, port), self._build_handler())

    @property
    def server_address(self) -> tuple[str, int]:
        host, port = self._server.server_address[:2]
        return str(host), int(port)

    @property
    def base_url(self) -> str:
        host, port = self.server_address
        return f"http://{host}:{port}"

    def _build_handler(self):
        service = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:
                return

            def do_GET(self) -> None:
                service._handle(self, "GET")

            def do_POST(self) -> None:
                service._handle(self, "POST")

        return Handler

    def _note_prover(self) -> ShieldedNoteProver | None:
        if self._note_bundle_json is None:
            return None
        prover = getattr(self._thread_state, "note_prover", None)
        if prover is None:
            prover = ShieldedNoteProver(self._note_bundle_json)
            self._thread_state.note_prover = prover
        return prover

    def _command_prover(self) -> ShieldedCommandProver | None:
        if self._command_bundle_json is None:
            return None
        prover = getattr(self._thread_state, "command_prover", None)
        if prover is None:
            prover = ShieldedCommandProver(self._command_bundle_json)
            self._thread_state.command_prover = prover
        return prover

    def _relay_prover(self) -> ShieldedRelayTransferProver | None:
        if self._relay_bundle_json is None:
            return None
        prover = getattr(self._thread_state, "relay_prover", None)
        if prover is None:
            prover = ShieldedRelayTransferProver(self._relay_bundle_json)
            self._thread_state.relay_prover = prover
        return prover

    def _check_auth(self, handler: BaseHTTPRequestHandler) -> bool:
        if self.auth_token is None:
            return True
        header = handler.headers.get("Authorization")
        return header == f"Bearer {self.auth_token}"

    def _send_json(
        self,
        handler: BaseHTTPRequestHandler,
        status: int,
        payload: dict[str, Any],
    ) -> None:
        encoded = _json_bytes(payload)
        handler.send_response(status)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(encoded)))
        handler.end_headers()
        handler.wfile.write(encoded)

    def _read_json(self, handler: BaseHTTPRequestHandler) -> dict[str, Any]:
        raw_length = handler.headers.get("Content-Length", "0")
        length = int(raw_length)
        body = handler.rfile.read(length).decode("utf-8")
        if body == "":
            return {}
        payload = json.loads(body)
        if not isinstance(payload, dict):
            raise ValueError("request body must be a JSON object")
        return payload

    def _handle(self, handler: BaseHTTPRequestHandler, method: str) -> None:
        if not self._check_auth(handler):
            self._send_json(handler, 401, {"error": "unauthorized"})
            return
        try:
            if method == "GET":
                payload = self._handle_get(handler.path)
            else:
                payload = self._handle_post(
                    handler.path, self._read_json(handler)
                )
            self._send_json(handler, 200, payload)
        except KeyError as exc:
            self._send_json(
                handler, 400, {"error": f"missing field: {exc.args[0]}"}
            )
        except ValueError as exc:
            self._send_json(handler, 400, {"error": str(exc)})
        except LookupError as exc:
            self._send_json(handler, 404, {"error": str(exc)})
        except Exception as exc:
            self._send_json(handler, 500, {"error": str(exc)})

    def _handle_get(self, path: str) -> dict[str, Any]:
        if path == "/healthz":
            return {
                "ok": True,
                "note": self._note_bundle_json is not None,
                "command": self._command_bundle_json is not None,
                "relay": self._relay_bundle_json is not None,
            }
        if path == "/v1/manifests/shielded-note":
            prover = self._note_prover()
            if prover is None:
                raise LookupError("shielded note prover not configured")
            return prover.registry_manifest()
        if path == "/v1/manifests/shielded-command":
            prover = self._command_prover()
            if prover is None:
                raise LookupError("shielded command prover not configured")
            return prover.registry_manifest()
        if path == "/v1/manifests/shielded-relay":
            prover = self._relay_prover()
            if prover is None:
                raise LookupError("shielded relay prover not configured")
            return prover.registry_manifest()
        raise LookupError("unknown endpoint")

    def _handle_post(
        self, path: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        if path == "/v1/shielded-note/prove/deposit":
            prover = self._note_prover()
            if prover is None:
                raise LookupError("shielded note prover not configured")
            return asdict(
                prover.prove_deposit(_note_deposit_request_from_value(payload))
            )
        if path == "/v1/shielded-note/prove/transfer":
            prover = self._note_prover()
            if prover is None:
                raise LookupError("shielded note prover not configured")
            return asdict(
                prover.prove_transfer(
                    _note_transfer_request_from_value(payload)
                )
            )
        if path == "/v1/shielded-note/prove/withdraw":
            prover = self._note_prover()
            if prover is None:
                raise LookupError("shielded note prover not configured")
            return asdict(
                prover.prove_withdraw(
                    _note_withdraw_request_from_value(payload)
                )
            )
        if path == "/v1/shielded-command/prove/deposit":
            prover = self._command_prover()
            if prover is None:
                raise LookupError("shielded command prover not configured")
            return asdict(
                prover.prove_deposit(_note_deposit_request_from_value(payload))
            )
        if path == "/v1/shielded-command/prove/execute":
            prover = self._command_prover()
            if prover is None:
                raise LookupError("shielded command prover not configured")
            return asdict(
                prover.prove_execute(_command_request_from_value(payload))
            )
        if path == "/v1/shielded-command/prove/withdraw":
            prover = self._command_prover()
            if prover is None:
                raise LookupError("shielded command prover not configured")
            return asdict(
                prover.prove_withdraw(
                    _note_withdraw_request_from_value(payload)
                )
            )
        if path == "/v1/shielded-relay/prove/transfer":
            prover = self._relay_prover()
            if prover is None:
                raise LookupError("shielded relay prover not configured")
            return asdict(
                prover.prove_relay_transfer(_relay_request_from_value(payload))
            )
        raise LookupError("unknown endpoint")

    def serve_forever(self) -> None:
        self._server.serve_forever()

    def start_in_thread(self) -> threading.Thread:
        if self._thread is not None and self._thread.is_alive():
            return self._thread
        self._thread = threading.Thread(
            target=self.serve_forever,
            name="xian-zk-prover-service",
            daemon=True,
        )
        self._thread.start()
        return self._thread

    def shutdown(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def __enter__(self) -> "ShieldedZkProverService":
        self.start_in_thread()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.shutdown()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="xian-zk-prover-service",
        description=(
            "Run a local authenticated proving service for Xian shielded note "
            "and command circuits. This service is intended for trusted local "
            "use only."
        ),
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument(
        "--auth-token",
        default=None,
        help=(
            "Bearer token required by clients. Mandatory for non-loopback "
            "binds."
        ),
    )
    parser.add_argument("--note-bundle", default=None)
    parser.add_argument("--command-bundle", default=None)
    parser.add_argument(
        "--unsafe-allow-remote-host",
        action="store_true",
        help=(
            "Allow binding the prover service to a non-loopback host. "
            "Requires --auth-token and should only be used behind trusted "
            "network controls."
        ),
    )
    parser.add_argument(
        "--insecure-dev-note",
        action="store_true",
        help="Serve shielded-note proving with the insecure development bundle.",
    )
    parser.add_argument(
        "--insecure-dev-command",
        action="store_true",
        help="Serve shielded-command and relay proving with the insecure development bundle.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    note_prover = None
    command_prover = None

    if args.note_bundle is not None:
        note_prover = ShieldedNoteProver(_read_text(args.note_bundle))
    elif args.insecure_dev_note:
        note_prover = ShieldedNoteProver.build_insecure_dev_bundle()

    if args.command_bundle is not None:
        command_prover = ShieldedCommandProver(_read_text(args.command_bundle))
    elif args.insecure_dev_command:
        command_prover = ShieldedCommandProver.build_insecure_dev_bundle()

    if note_prover is None and command_prover is None:
        raise SystemExit(
            "configure at least one prover with --note-bundle, --command-bundle, "
            "--insecure-dev-note, or --insecure-dev-command"
        )

    service = ShieldedZkProverService(
        note_prover=note_prover,
        command_prover=command_prover,
        host=args.host,
        port=args.port,
        auth_token=args.auth_token,
        allow_remote_host=args.unsafe_allow_remote_host,
    )
    print("xian-zk prover service listening")
    print(f"base_url={service.base_url}")
    print("warning=trusted local service only; witness material is exposed")
    if _is_loopback_host(args.host):
        print("bind_scope=loopback-only")
    else:
        print("bind_scope=remote-host")
    if args.auth_token is not None:
        print("auth=enabled")
    else:
        print("auth=disabled")
    try:
        service.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        service.shutdown()
    return 0


__all__ = [
    "ShieldedCommandProverClient",
    "ShieldedNoteProverClient",
    "ShieldedRelayTransferProverClient",
    "ShieldedZkProverService",
    "ZkProverClientError",
    "main",
]
