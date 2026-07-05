import json
import socket
import urllib.request

import pytest
from xian_zk import (
    ShieldedCommandProver,
    ShieldedKeyBundle,
    ShieldedNote,
    ShieldedNoteProver,
    ShieldedNoteProverClient,
    ShieldedRelayTransferProverClient,
    ShieldedRelayTransferWallet,
    ShieldedWallet,
    ShieldedZkProverService,
    ZkProverClientError,
    asset_id_for_contract,
)


class _DummyProver:
    bundle_json = "{}"


def field(value: int) -> str:
    return f"0x{value:064x}"


def _require_ipv6_bind(host: str) -> None:
    if not socket.has_ipv6:
        pytest.skip("IPv6 sockets are not available")
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    try:
        sock.bind((host, 0))
    except OSError as exc:
        pytest.skip(f"IPv6 bind to {host} is not available: {exc}")
    finally:
        sock.close()


def test_prover_service_default_bind_stays_ipv4_loopback():
    with ShieldedZkProverService(note_prover=_DummyProver()) as service:
        host, port = service.server_address
        assert host == "127.0.0.1"
        assert service.base_url == f"http://127.0.0.1:{port}"


@pytest.mark.parametrize("host", ["::1", "[::1]"])
def test_prover_service_accepts_ipv6_loopback_bind(host: str):
    _require_ipv6_bind("::1")

    with ShieldedZkProverService(
        note_prover=_DummyProver(),
        host=host,
    ) as service:
        host, port = service.server_address
        assert host == "::1"
        assert service.base_url == f"http://[::1]:{port}"

        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(f"{service.base_url}/healthz", timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))

    assert payload == {
        "ok": True,
        "note": True,
        "command": False,
        "relay": False,
    }


def test_prover_service_rejects_ipv6_remote_host_without_explicit_override():
    with pytest.raises(ValueError, match="non-loopback host"):
        ShieldedZkProverService(
            note_prover=_DummyProver(),
            host="::",
        )


def test_prover_service_requires_auth_token_for_ipv6_remote_host():
    with pytest.raises(ValueError, match="auth-token"):
        ShieldedZkProverService(
            note_prover=_DummyProver(),
            host="[::]",
            allow_remote_host=True,
        )


def test_prover_service_allows_ipv6_remote_host_with_override_and_token():
    _require_ipv6_bind("::")

    with ShieldedZkProverService(
        note_prover=_DummyProver(),
        host="::",
        auth_token="secret",
        allow_remote_host=True,
    ) as service:
        host, port = service.server_address
        assert host == "::"
        assert service.base_url == f"http://[::]:{port}"


def test_note_prover_service_round_trips_deposit_request():
    asset_id = asset_id_for_contract("con_shielded_note_token")
    wallet = ShieldedWallet.from_parts(
        asset_id=asset_id,
        owner_secret=field(101),
        viewing_private_key="11" * 32,
    )
    plan = wallet.build_deposit(amount=7)

    with ShieldedZkProverService(
        note_prover=ShieldedNoteProver.build_insecure_dev_bundle(),
        auth_token="secret",
    ) as service:
        client = ShieldedNoteProverClient(service.base_url, auth_token="secret")

        manifest = client.registry_manifest()
        proof = client.prove_deposit(plan.request)

    assert manifest["circuit_family"].startswith("shielded_note_v")
    assert proof.old_root == plan.request.old_root
    assert proof.output_payload_hashes == plan.output_payload_hashes
    assert len(proof.output_commitments) == 1


def test_prover_service_rejects_missing_token():
    with ShieldedZkProverService(
        note_prover=ShieldedNoteProver.build_insecure_dev_bundle(),
        auth_token="secret",
    ) as service:
        client = ShieldedNoteProverClient(service.base_url)
        with pytest.raises(ZkProverClientError) as exc_info:
            client.registry_manifest()

    assert exc_info.value.status_code == 401


def test_prover_service_rejects_remote_host_without_explicit_override():
    with pytest.raises(ValueError, match="non-loopback host"):
        ShieldedZkProverService(
            note_prover=ShieldedNoteProver.build_insecure_dev_bundle(),
            host="0.0.0.0",
        )


def test_prover_service_requires_auth_token_for_remote_host():
    with pytest.raises(ValueError, match="auth-token"):
        ShieldedZkProverService(
            note_prover=ShieldedNoteProver.build_insecure_dev_bundle(),
            host="0.0.0.0",
            allow_remote_host=True,
        )


def test_prover_service_allows_remote_host_with_explicit_override_and_token():
    service = ShieldedZkProverService(
        note_prover=ShieldedNoteProver.build_insecure_dev_bundle(),
        host="0.0.0.0",
        auth_token="secret",
        allow_remote_host=True,
    )
    try:
        service.start_in_thread()
        host, _port = service.server_address
        assert host == "0.0.0.0"
    finally:
        service.shutdown()


def test_relay_prover_service_round_trips_hidden_sender_request():
    wallet = ShieldedRelayTransferWallet.from_parts(
        asset_id=field(777),
        owner_secret=field(888),
        viewing_private_key="33" * 32,
    )
    recipient = ShieldedKeyBundle.from_parts(
        owner_secret=field(999),
        viewing_private_key="44" * 32,
    )
    funding_note = ShieldedNote(
        owner_secret=wallet.owner_secret,
        amount=15,
        rho=field(1001),
        blind=field(1002),
    )
    wallet.sync_records(
        [
            {
                "index": 0,
                "commitment": funding_note.commitment(wallet.asset_id),
                "payload": funding_note.to_output().encrypt_for(
                    asset_id=wallet.asset_id,
                    viewing_public_key=wallet.viewing_public_key,
                ),
            }
        ]
    )
    plan = wallet.build_relay_transfer(
        recipient=recipient.recipient,
        amount=10,
        relayer="relayer",
        chain_id="xian-local-1",
        fee=3,
        expires_at="2026-01-01 12:45:00",
    )

    with ShieldedZkProverService(
        command_prover=ShieldedCommandProver.build_insecure_dev_bundle(),
        auth_token="secret",
    ) as service:
        client = ShieldedRelayTransferProverClient(service.base_url, auth_token="secret")

        manifest = client.registry_manifest()
        proof = client.prove_relay_transfer(plan.request)

    assert manifest["configure_actions"] == [
        {
            "action": "relay_transfer",
            "vk_id": manifest["registry_entries"][0]["vk_id"],
        }
    ]
    assert proof.relay_binding == plan.relay_binding
    assert proof.execution_tag == plan.execution_tag
    assert proof.output_payload_hashes == plan.output_payload_hashes
