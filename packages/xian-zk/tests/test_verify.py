import json
from pathlib import Path

import pytest

from xian_zk import (
    ZkEncodingError,
    prepare_groth16_bn254_vk,
    verify_groth16_bn254,
    verify_groth16_bn254_prepared,
)


FIXTURE_PATH = (
    Path(__file__).parent / "fixtures" / "groth16_bn254_demo.json"
)


def load_fixture():
    return json.loads(FIXTURE_PATH.read_text())


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
