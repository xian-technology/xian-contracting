"""Cross-implementation FIPS 204 proof of possession through the contract VM."""

from pathlib import Path

import pytest

from tests.integration.test_vm_hash_crypto_resources import execute

pytestmark = pytest.mark.optional_native


def test_verify_ml_dsa_65_through_contract(tmp_path):
    # PQClean (pqcrypto 0.4.0), pure ML-DSA-65 with empty context.
    vector = (Path(__file__).parents[1] / "fixtures" / "ml_dsa_65_pop.bin").read_bytes()
    public_key, signature = vector[:1952], vector[1952:]
    message = "xian-validator-key-v1\nlocal\n验证者"
    expression = f'crypto.verify_ml_dsa_65("{public_key.hex()}", payload, "{signature.hex()}")'
    for index, (payload, expected) in enumerate(((message, True), (message + "x", False))):
        result = execute(tmp_path / str(index), "return " + expression, payload)
        assert result.status_code == 0, result.result
        assert result.result is expected


def test_verify_ml_dsa_65_charges_before_decoding_and_rolls_back(tmp_path):
    result = execute(
        tmp_path, 'return crypto.verify_ml_dsa_65("zz", payload, "00")', "", budget=50_000
    )
    assert result.status_code == 1 and "Out of chi" in str(result.result)
    assert result.writes == {} and result.events == []


@pytest.mark.parametrize("operand", ["wrong_key", "upper_key", "upper_sig", "short_sig", "long_sig"])
def test_verify_ml_dsa_65_rejects_noncanonical_inputs(tmp_path, operand):
    vector = (Path(__file__).parents[1] / "fixtures" / "ml_dsa_65_pop.bin").read_bytes()
    key, signature = vector[:1952].hex(), vector[1952:].hex()
    if operand == "wrong_key":
        key = "00" * 1952
    elif operand == "upper_key":
        key = key.upper()
    elif operand == "upper_sig":
        signature = signature.upper()
    elif operand == "short_sig":
        signature = signature[:-2]
    else:
        signature += "00"
    body = f'return crypto.verify_ml_dsa_65("{key}", payload, "{signature}")'
    result = execute(tmp_path, body, "xian-validator-key-v1\nlocal\n验证者")
    if operand == "long_sig":
        assert result.status_code == 1 and "resource limit" in str(result.result)
        assert result.writes == {}
    else:
        assert result.status_code == 0 and result.result is False
