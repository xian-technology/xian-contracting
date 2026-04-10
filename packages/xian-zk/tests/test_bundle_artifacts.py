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
