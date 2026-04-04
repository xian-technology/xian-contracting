import hashlib
import json
from pathlib import Path

import pytest

from xian_zk import (
    ZkEncodingError,
    prepare_groth16_bn254_vk,
    recipient_digest,
    verify_groth16_bn254,
    verify_groth16_bn254_prepared,
)


FIXTURE_PATH = (
    Path(__file__).parent / "fixtures" / "groth16_bn254_demo.json"
)
SHIELDED_FIXTURE_PATH = (
    Path(__file__).parent / "fixtures" / "shielded_note_flow.json"
)
FIELD_MODULUS = (
    21888242871839275222246405745257275088548364400416034343698204186575808495617
)


def load_fixture():
    return json.loads(FIXTURE_PATH.read_text())


def load_shielded_fixture():
    return json.loads(SHIELDED_FIXTURE_PATH.read_text())


def test_demo_vector_verifies():
    fixture = load_fixture()
    assert verify_groth16_bn254(
        fixture["vk_hex"],
        fixture["proof_hex"],
        fixture["public_inputs"],
    )


def test_tampered_public_input_fails_without_error():
    fixture = load_fixture()
    tampered_inputs = list(fixture["public_inputs"])
    tampered_inputs[0] = (
        "0x0000000000000000000000000000000000000000000000000000000000000001"
    )
    assert not verify_groth16_bn254(
        fixture["vk_hex"],
        fixture["proof_hex"],
        tampered_inputs,
    )


def test_prepared_vk_verifies_demo_vector():
    fixture = load_fixture()
    prepared = prepare_groth16_bn254_vk(fixture["vk_hex"])
    assert verify_groth16_bn254_prepared(
        prepared,
        fixture["proof_hex"],
        fixture["public_inputs"],
    )


def test_non_prefixed_inputs_are_rejected():
    fixture = load_fixture()
    with pytest.raises(ZkEncodingError):
        verify_groth16_bn254(
            fixture["vk_hex"][2:],
            fixture["proof_hex"],
            fixture["public_inputs"],
        )


def test_non_canonical_public_inputs_are_rejected():
    fixture = load_fixture()
    over_modulus = f"0x{'ff' * 32}"
    with pytest.raises(ZkEncodingError):
        verify_groth16_bn254(
            fixture["vk_hex"],
            fixture["proof_hex"],
            [over_modulus],
        )


def test_short_public_inputs_are_rejected():
    fixture = load_fixture()
    with pytest.raises(ZkEncodingError):
        verify_groth16_bn254(
            fixture["vk_hex"],
            fixture["proof_hex"],
            ["0x02"],
        )


def test_shielded_note_flow_vectors_verify():
    fixture = load_shielded_fixture()
    by_id = {vk["vk_id"]: vk["vk_hex"] for vk in fixture["verifying_keys"]}

    assert verify_groth16_bn254(
        by_id["shielded-deposit-v3"],
        fixture["deposit"]["proof_hex"],
        fixture["deposit"]["public_inputs"],
    )
    assert verify_groth16_bn254(
        by_id["shielded-transfer-v3"],
        fixture["transfer"]["proof_hex"],
        fixture["transfer"]["public_inputs"],
    )
    assert verify_groth16_bn254(
        by_id["shielded-withdraw-v3"],
        fixture["withdraw"]["proof_hex"],
        fixture["withdraw"]["public_inputs"],
    )


def test_recipient_digest_matches_contract_hashing_for_hex_like_values():
    recipient = "ab" * 32
    digest = hashlib.sha3_256(bytes.fromhex(recipient)).hexdigest()
    expected = f"0x{(int(digest, 16) % FIELD_MODULUS):064x}"
    assert recipient_digest(recipient) == expected
