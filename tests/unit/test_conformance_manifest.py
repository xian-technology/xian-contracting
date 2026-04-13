import json

from contracting.compilation.conformance import (
    CONFORMANCE_BUILTIN_EXCLUSIONS,
    CONFORMANCE_ENV_EXCLUSIONS,
    CONTRACT_LANGUAGE_CONFORMANCE_CASES,
    CONTRACT_LANGUAGE_MANIFEST,
    CONTRACT_LANGUAGE_MANIFEST_VERSION,
    covered_conformance_surface,
    current_vm_parity_gaps,
)


def test_contract_language_manifest_is_json_serializable():
    payload = json.dumps(CONTRACT_LANGUAGE_MANIFEST, sort_keys=True)
    decoded = json.loads(payload)

    assert decoded["manifest_version"] == CONTRACT_LANGUAGE_MANIFEST_VERSION


def test_manifest_tracks_public_contract_surface_only():
    python_surface = CONTRACT_LANGUAGE_MANIFEST["python_contracting"][
        "public_env_surface"
    ]
    vm_surface = CONTRACT_LANGUAGE_MANIFEST["xian_vm_v1"]

    assert "Variable" in python_surface
    assert "Hash" in python_surface
    assert "Contract" in python_surface
    assert "rt" not in python_surface
    assert "__export" not in python_surface
    assert "Exception" in CONTRACT_LANGUAGE_MANIFEST["python_contracting"][
        "allowed_builtins"
    ]
    assert "set" not in CONTRACT_LANGUAGE_MANIFEST["python_contracting"][
        "allowed_builtins"
    ]
    assert "frozenset" not in CONTRACT_LANGUAGE_MANIFEST["python_contracting"][
        "allowed_builtins"
    ]
    assert "raise" in vm_surface["supported_ir"]["statement_nodes"]
    assert "dict_comp" in vm_surface["supported_ir"]["expression_nodes"]
    assert "bitand" in vm_surface["supported_ir"]["binary_operators"]
    assert "invert" in vm_surface["supported_ir"]["unary_operators"]


def test_conformance_case_ids_are_unique():
    case_ids = [case["id"] for case in CONTRACT_LANGUAGE_CONFORMANCE_CASES]

    assert len(case_ids) == len(set(case_ids))


def test_current_vm_parity_gaps_surface_remaining_backlog():
    gaps = current_vm_parity_gaps()

    assert gaps["builtins"] == []
    assert gaps["syntax"] == []


def test_callable_builtin_surface_is_covered_or_explicitly_excluded():
    covered = covered_conformance_surface()["builtins"]
    required = set(CONTRACT_LANGUAGE_MANIFEST["python_contracting"]["allowed_builtins"])
    missing = sorted(required - covered - set(CONFORMANCE_BUILTIN_EXCLUSIONS))

    assert missing == []


def test_public_env_surface_is_covered_or_explicitly_excluded():
    covered = covered_conformance_surface()["env"]
    required = set(CONTRACT_LANGUAGE_MANIFEST["python_contracting"]["public_env_surface"])
    missing = sorted(required - covered - set(CONFORMANCE_ENV_EXCLUSIONS))

    assert missing == []
