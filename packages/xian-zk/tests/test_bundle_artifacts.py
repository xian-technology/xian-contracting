import json

import pytest
from xian_zk import ShieldedCommandProver, ShieldedNoteProver
from xian_zk.bundles import (
    validate_shielded_command_bundle,
    validate_shielded_note_bundle,
)
from xian_zk.cli import main


def test_validate_note_bundle_requires_setup_ceremony_for_external_imports():
    bundle = ShieldedNoteProver.build_random_bundle(
        contract_name="con_private_usd",
        vk_id_prefix="private-usd-v3",
    ).bundle
    bundle["setup_mode"] = "ceremony-import"
    bundle["setup_ceremony"] = ""

    with pytest.raises(ValueError, match="setup_ceremony"):
        validate_shielded_note_bundle(bundle)


def test_validate_command_bundle_accepts_external_import_metadata():
    bundle = ShieldedCommandProver.build_random_bundle(
        contract_name="con_shielded_commands",
        vk_id_prefix="shielded-command-v4",
    ).bundle
    bundle["setup_mode"] = "ceremony-import"
    bundle["setup_ceremony"] = "powers-of-tau-phase2-2026"

    normalized = validate_shielded_command_bundle(bundle)

    assert normalized["setup_mode"] == "ceremony-import"
    assert normalized["setup_ceremony"] == "powers-of-tau-phase2-2026"


def test_cli_import_note_bundle_writes_artifacts(tmp_path):
    bundle_path = tmp_path / "imported-note-bundle.json"
    output_dir = tmp_path / "artifacts"
    bundle = ShieldedNoteProver.build_random_bundle(
        contract_name="con_private_usd",
        vk_id_prefix="private-usd-v3",
    ).bundle
    bundle["setup_mode"] = "ceremony-import"
    bundle["setup_ceremony"] = "powers-of-tau-phase2-2026"
    bundle_path.write_text(json.dumps(bundle, sort_keys=True, indent=2) + "\n")

    result = main(
        [
            "import-note",
            "--bundle",
            str(bundle_path),
            "--output-dir",
            str(output_dir),
        ]
    )

    assert result == 0
    manifest = json.loads(
        (output_dir / "shielded-note-registry-manifest.json").read_text()
    )
    guide = (output_dir / "shielded-note-deployment.md").read_text()
    assert manifest["setup_mode"] == "ceremony-import"
    assert manifest["setup_ceremony"] == "powers-of-tau-phase2-2026"
    assert "powers-of-tau-phase2-2026" in guide
    script = (output_dir / "register_and_bind.py").read_text()
    compile(script, "register_and_bind.py", "exec")
    assert "register_and_bind" in script
    assert "zk_registry.register_vk(**args" in script
    assert '"shielded-note-registry-manifest.json"' in script


def test_cli_promote_writes_combined_operator_artifacts(tmp_path):
    note_bundle_path = tmp_path / "ceremony-note-bundle.json"
    command_bundle_path = tmp_path / "ceremony-command-bundle.json"
    output_dir = tmp_path / "promoted"

    note_bundle = ShieldedNoteProver.build_random_bundle(
        contract_name="con_private_usd",
        vk_id_prefix="private-usd-note-v4",
    ).bundle
    note_bundle["setup_mode"] = "ceremony-import"
    note_bundle["setup_ceremony"] = "xian-shielded-note-v4-2026"
    note_bundle_path.write_text(
        json.dumps(note_bundle, sort_keys=True, indent=2) + "\n"
    )

    command_bundle = ShieldedCommandProver.build_random_bundle(
        contract_name="con_private_usd",
        vk_id_prefix="private-usd-relay-v5",
    ).bundle
    command_bundle["setup_mode"] = "ceremony-import"
    command_bundle["setup_ceremony"] = "xian-shielded-command-v5-2026"
    command_bundle_path.write_text(
        json.dumps(command_bundle, sort_keys=True, indent=2) + "\n"
    )

    result = main(
        [
            "promote",
            "--network",
            "testnet",
            "--contract-name",
            "con_private_usd",
            "--note-bundle",
            str(note_bundle_path),
            "--relay-command-bundle",
            str(command_bundle_path),
            "--output-dir",
            str(output_dir),
        ]
    )

    assert result == 0
    note_manifest = json.loads(
        (output_dir / "shielded-note-registry-manifest.json").read_text()
    )
    relay_manifest = json.loads(
        (output_dir / "shielded-relay-registry-manifest.json").read_text()
    )
    script = (output_dir / "register_and_bind.py").read_text()
    compile(script, "register_and_bind.py", "exec")
    summary = json.loads((output_dir / "promotion-summary.json").read_text())
    catalog_entries = json.loads(
        (output_dir / "catalog-artifacts-snippet.json").read_text()
    )

    assert note_manifest["setup_mode"] == "ceremony-import"
    assert relay_manifest["registry_entries"][0]["action"] == "relay_transfer"
    assert relay_manifest["contract_name"] == "con_private_usd"
    assert '"shielded-note-registry-manifest.json"' in script
    assert '"shielded-relay-registry-manifest.json"' in script
    assert summary["network"] == "testnet"
    assert summary["operator_script"] == "register_and_bind.py"
    assert [entry["kind"] for entry in catalog_entries] == [
        "shielded_note",
        "shielded_relay",
    ]
    assert all(len(entry["sha256"]) == 64 for entry in catalog_entries)
