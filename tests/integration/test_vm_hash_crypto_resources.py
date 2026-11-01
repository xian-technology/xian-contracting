"""Hash/crypto work charges and admission hold across authored invocation routes."""

import pytest

from contracting.storage.driver import Driver

pytestmark = pytest.mark.optional_native
TEXT_LIMIT = 1024 * 1024


def execute(home, body, payload, *, budget=50_000_000, meter=True):
    from xian_vm_core import execute_contract

    source = "state = Variable()\n@export\ndef probe(payload: str):\n"
    source += "    state.set(7)\n" + "\n".join("    " + line for line in body.splitlines()) + "\n"
    with Driver(storage_home=home) as driver:
        driver.set_contract_from_source("con_crypto_resources", source, owner=None)
        driver.commit()
        return execute_contract(
            driver=driver,
            contract_name="con_crypto_resources",
            function_name="probe",
            kwargs={"payload": payload},
            context={"caller": "alice", "signer": "alice", "this": "con_crypto_resources"},
            meter=meter,
            chi_budget_raw=budget,
        )


@pytest.mark.parametrize(
    ("name", "price"),
    [
        ("sha256_text", 2),
        ("sha3_text", 4),
        ("sha256_hex", 4),
        ("sha3_hex", 6),
        ("sha256", 4),
        ("sha3", 6),
    ],
)
@pytest.mark.parametrize("route", ["direct", "alias", "callback"])
def test_hash_byte_prices_apply_once_per_invocation(tmp_path, name, price, route):
    bodies = {
        "direct": f"return hashlib.{name}(payload)",
        "alias": f"f = hashlib.{name}\nreturn f(payload)",
        "callback": f"return list(map(hashlib.{name}, [payload, payload]))",
    }
    short = execute(tmp_path / "short", bodies[route], "ab" * 8)
    wide = execute(tmp_path / "wide", bodies[route], "ab" * 128)
    assert short.status_code == wide.status_code == 0, (short.result, wide.result)
    invocations = 2 if route == "callback" else 1
    assert wide.raw_cost - short.raw_cost == (256 - 16) * price * invocations


@pytest.mark.parametrize("meter", [True, False])
@pytest.mark.parametrize(
    ("name", "payload"),
    [
        ("sha256_text", "é" * (TEXT_LIMIT // 2) + "a"),
        ("sha3_hex", "ab" * TEXT_LIMIT + "00"),
        ("sha256", "ab" * (TEXT_LIMIT // 2) + "z"),
    ],
    ids=["text_utf8", "strict_hex", "legacy_fallback"],
)
def test_caps_rollback_and_apply_without_meter(tmp_path, name, payload, meter):
    result = execute(tmp_path, f"return hashlib.{name}(payload)", payload, meter=meter)
    assert result.status_code == 1 and "resource limit" in str(result.result)
    assert result.writes == {} and result.events == []


def test_low_budget_precedes_legacy_classification_and_rolls_back(tmp_path):
    result = execute(
        tmp_path, "return hashlib.sha3(payload)", "ab" * (TEXT_LIMIT // 2) + "z", budget=100_000
    )
    assert result.status_code == 1 and "Out of chi" in str(result.result)
    assert result.writes == {} and result.events == []


def test_low_budget_precedes_strict_hex_validation(tmp_path):
    result = execute(tmp_path, "return hashlib.sha256_hex(payload)", "z" * 100_000, budget=100_000)
    assert result.status_code == 1 and "Out of chi" in str(result.result)
    assert result.writes == {} and result.events == []


@pytest.mark.parametrize("route", ["direct", "alias", "callback"])
def test_ed25519_message_price_and_valid_signatures(tmp_path, route):
    import nacl.signing

    signer = nacl.signing.SigningKey(b"\x07" * 32)
    key = signer.verify_key.encode().hex()
    results = []
    for size in [16, 256]:
        payload = "é" * (size // 2)
        signature = signer.sign(payload.encode()).signature.hex()
        bodies = {
            "direct": f'return crypto.verify("{key}", payload, "{signature}")',
            "alias": f'f = crypto.verify\nreturn f("{key}", payload, "{signature}")',
            "callback": f'return list(map(crypto.verify, ["{key}", "{key}"], [payload, payload], ["{signature}", "{signature}"]))',
        }
        result = execute(tmp_path / str(size), bodies[route], payload)
        assert result.status_code == 0, result.result
        assert result.result == ([True, True] if route == "callback" else True)
        results.append(result)
    calls = 2 if route == "callback" else 1
    assert results[1].raw_cost - results[0].raw_cost == 4 * (256 - 16) * calls


@pytest.mark.parametrize("meter", [True, False])
@pytest.mark.parametrize("operand", ["key", "signature", "message"])
def test_ed25519_caps_are_admission_errors(tmp_path, operand, meter):
    key = "ab" * 32 + ("00" if operand == "key" else "")
    signature = "00" * 64 + ("00" if operand == "signature" else "")
    message = "a" * (TEXT_LIMIT + 1) if operand == "message" else "ok"
    body = f'return crypto.verify("{key}", payload, "{signature}")'
    result = execute(tmp_path, body, message, meter=meter)
    assert result.status_code == 1 and "resource limit" in str(result.result)
    assert result.writes == {} and result.events == []


@pytest.mark.parametrize("route", ["parameter", "concat", "storage", "cross_contract"])
@pytest.mark.parametrize("size", [256 * 1024, TEXT_LIMIT, TEXT_LIMIT + 1])
def test_payload_origin_does_not_change_syscall_admission(tmp_path, route, size):
    import hashlib

    from xian_vm_core import execute_contract

    payload = "x" * size
    body = {
        "parameter": "return hashlib.sha256_text(payload)",
        "concat": "value = payload + suffix\nreturn hashlib.sha256_text(value)",
        "storage": "return hashlib.sha256_text(stored.get())",
        "cross_contract": "return target.digest(payload)",
    }[route]
    source = "import con_crypto_target as target\nstate = Variable()\nstored = Variable()\n"
    source += "@export\ndef probe(payload: str, suffix: str):\n    state.set(7)\n"
    source += "\n".join("    " + line for line in body.splitlines()) + "\n"
    with Driver(storage_home=tmp_path) as driver:
        driver.set_contract_from_source(
            "con_crypto_target",
            "@export\ndef digest(payload: str):\n    return hashlib.sha256_text(payload)\n",
            owner=None,
        )
        driver.set_contract_from_source("con_crypto_origin", source, owner=None)
        # Host-loaded legacy/external state need not have passed current metered writes.
        if route == "storage":
            driver.set("con_crypto_origin.stored", payload)
        driver.commit()
        argument = payload[:-1] if route == "concat" else payload
        result = execute_contract(
            driver=driver,
            contract_name="con_crypto_origin",
            function_name="probe",
            kwargs={"payload": argument, "suffix": "x"},
            context={"caller": "alice", "signer": "alice", "this": "con_crypto_origin"},
            meter=True,
            chi_budget_raw=50_000_000,
        )
    if size > TEXT_LIMIT:
        assert result.status_code == 1 and "resource limit" in str(result.result)
        assert result.writes == {} and result.events == []
    else:
        assert result.status_code == 0, result.result
        assert result.result == hashlib.sha256(payload.encode()).hexdigest()


def test_verify_low_budget_precedes_malformed_key(tmp_path):
    result = execute(tmp_path, 'return crypto.verify("zz", payload, "00")', "", budget=50_000)
    assert result.status_code == 1 and "Out of chi" in str(result.result)
    assert result.writes == {} and result.events == []
