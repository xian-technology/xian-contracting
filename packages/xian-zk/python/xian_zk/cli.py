from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from xian_zk import (
    ShieldedCommandProver,
    ShieldedNoteProver,
    ShieldedRelayTransferProver,
    bundle_summary,
    shielded_command_registry_manifest,
    shielded_registry_manifest,
    shielded_relay_registry_manifest,
)
from xian_zk.bundles import load_and_validate_bundle_text

_ARTIFACT_KINDS = {
    "note": "shielded_note",
    "command": "shielded_command",
    "relay": "shielded_relay",
}


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", value).strip("-").lower()
    return slug or "shielded-note"


def _default_vk_id_prefix(contract_name: str, *, bundle_type: str) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{_slugify(contract_name)}-{bundle_type}-v2-{timestamp}"


def _write_text(path: Path, content: str, *, overwrite: bool) -> None:
    if path.exists() and not overwrite:
        raise FileExistsError(f"{path} already exists; pass --overwrite to replace it")
    path.write_text(content)


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _operator_script(
    *,
    manifest_filenames: list[str],
    configure_target: str = "contract",
) -> str:
    manifest_lines = ",\n".join(f'    "{filename}"' for filename in manifest_filenames)
    return f"""from __future__ import annotations

import json
from pathlib import Path


REGISTRY_SIGNER = "sys"
CONTRACT_SIGNER = "sys"
MANIFEST_FILENAMES = [
{manifest_lines}
]


def _load_manifest(filename: str) -> dict:
    return json.loads((Path(__file__).resolve().parent / filename).read_text())


def register_manifests(zk_registry) -> list[str]:
    registered = []
    seen_vk_ids = set()
    for filename in MANIFEST_FILENAMES:
        manifest = _load_manifest(filename)
        for entry in manifest["registry_entries"]:
            if entry["vk_id"] in seen_vk_ids:
                continue
            args = dict(entry)
            args.pop("action", None)
            zk_registry.register_vk(**args, signer=REGISTRY_SIGNER)
            registered.append(entry["vk_id"])
            seen_vk_ids.add(entry["vk_id"])
    return registered


def bind_manifests({configure_target}) -> list[tuple[str, str]]:
    configured = []
    for filename in MANIFEST_FILENAMES:
        manifest = _load_manifest(filename)
        for binding in manifest["configure_actions"]:
            {configure_target}.configure_vk(
                action=binding["action"],
                vk_id=binding["vk_id"],
                signer=CONTRACT_SIGNER,
            )
            configured.append((binding["action"], binding["vk_id"]))
    return configured


def register_and_bind(zk_registry, {configure_target}) -> dict[str, list]:
    return {{
        "registered": register_manifests(zk_registry),
        "configured": bind_manifests({configure_target}),
    }}
"""


def _deployment_instructions(
    manifest: dict[str, object],
    *,
    title: str,
    bundle_filename: str,
    manifest_filename: str,
    configure_target: str = "contract",
) -> str:
    registry_entries = manifest["registry_entries"]
    configure_actions = manifest["configure_actions"]

    lines = [
        f"# {title}",
        "",
        "This directory contains:",
        "",
        f"- `{bundle_filename}`: private proving bundle. Keep this offline and access-controlled.",
        f"- `{manifest_filename}`: public verifying-key manifest for `zk_registry`.",
        f"- `{_slugify(title)}-deployment.md`: this operator guide.",
        "- `register_and_bind.py`: importable helper for registration and binding.",
        "",
        "## Register Verifying Keys",
        "",
        "```python",
        f'manifest = json.loads(Path("{manifest_filename}").read_text())',
        'for entry in manifest["registry_entries"]:',
        "    args = dict(entry)",
        '    args.pop("action", None)',
        '    zk_registry.register_vk(**args, signer="sys")',
        "```",
        "",
        "## Bind The Contract",
        "",
        "```python",
        f'manifest = json.loads(Path("{manifest_filename}").read_text())',
        'for binding in manifest["configure_actions"]:',
        f"    {configure_target}.configure_vk(",
        '        action=binding["action"],',
        '        vk_id=binding["vk_id"],',
        '        signer="sys",',
        "    )",
        "```",
        "",
        "Or import the generated helper and call:",
        "",
        "```python",
        "from register_and_bind import register_and_bind",
        f"register_and_bind(zk_registry, {configure_target})",
        "```",
        "",
        "## Warning",
        "",
        str(manifest["warning"]),
    ]

    setup_mode = str(manifest.get("setup_mode", "")).strip().lower()
    setup_ceremony = str(manifest.get("setup_ceremony", "")).strip()
    if setup_mode == "single-party":
        lines.extend(
            [
                "",
                "This bundle was generated from local randomness and is suitable for",
                "testing or controlled deployments, but it is still not a multi-party",
                "ceremony. Do not represent it as ceremony-grade proving material.",
            ]
        )
    elif setup_mode == "insecure-dev":
        lines.extend(
            [
                "",
                "This is the deterministic development bundle. It must never be used",
                "on a real network.",
            ]
        )
    elif setup_ceremony:
        lines.extend(
            [
                "",
                f"Setup ceremony: `{setup_ceremony}`",
                "Verify the imported artifact provenance before registering these keys.",
            ]
        )

    if isinstance(registry_entries, list) and isinstance(configure_actions, list):
        lines.extend(["", "## Generated IDs", ""])
        for entry in registry_entries:
            if not isinstance(entry, dict):
                continue
            lines.append(f"- `{entry['vk_id']}` for `{entry['circuit_name']}`")

    return "\n".join(lines) + "\n"


def _write_artifacts(
    *,
    output_dir: Path,
    overwrite: bool,
    bundle_json: str,
    manifest: dict[str, object],
    title: str,
    bundle_filename: str,
    manifest_filename: str,
    instructions_filename: str,
    script_filename: str = "register_and_bind.py",
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    bundle_path = output_dir / bundle_filename
    manifest_path = output_dir / manifest_filename
    instructions_path = output_dir / instructions_filename
    script_path = output_dir / script_filename

    _write_text(bundle_path, bundle_json, overwrite=overwrite)
    _write_text(
        manifest_path,
        json.dumps(manifest, sort_keys=True, indent=2) + "\n",
        overwrite=overwrite,
    )
    _write_text(
        instructions_path,
        _deployment_instructions(
            manifest,
            title=title,
            bundle_filename=bundle_filename,
            manifest_filename=manifest_filename,
            configure_target="contract",
        ),
        overwrite=overwrite,
    )
    _write_text(
        script_path,
        _operator_script(manifest_filenames=[manifest_filename]),
        overwrite=overwrite,
    )

    print(f"Generated bundle: {bundle_path}")
    print(f"Generated registry manifest: {manifest_path}")
    print(f"Generated operator guide: {instructions_path}")
    print(f"Generated operator script: {script_path}")
    print()
    print("Bundle warning:")
    print(manifest["warning"])


def _note_manifest_from_prover(prover: ShieldedNoteProver) -> dict[str, object]:
    return shielded_registry_manifest(prover)


def _command_manifest_from_prover(
    prover: ShieldedCommandProver,
) -> dict[str, object]:
    return shielded_command_registry_manifest(prover)


def _relay_manifest_from_prover(
    prover: ShieldedRelayTransferProver,
    *,
    artifact_contract_name: str | None = None,
) -> dict[str, object]:
    return shielded_relay_registry_manifest(
        prover,
        artifact_contract_name=artifact_contract_name,
    )


def _add_output_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--output-dir",
        required=True,
        help="Directory where bundle and manifest files will be written.",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite existing files in the output directory.",
    )


def _add_generate_arguments(parser: argparse.ArgumentParser, *, bundle_type: str) -> None:
    _add_output_arguments(parser)
    default_contract_name = (
        "con_shielded_note_token" if bundle_type == "shielded-note" else "con_shielded_commands"
    )
    parser.add_argument(
        "--contract-name",
        default=default_contract_name,
        help="Contract name to record in the generated bundle metadata.",
    )
    parser.add_argument(
        "--vk-id-prefix",
        default=None,
        help=("Prefix used to derive vk ids. Defaults to a timestamped contract-specific prefix."),
    )


def _add_import_arguments(parser: argparse.ArgumentParser) -> None:
    _add_output_arguments(parser)
    parser.add_argument(
        "--bundle",
        required=True,
        help="Path to an externally generated prover bundle JSON file.",
    )


def _add_validate_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--bundle",
        required=True,
        help="Path to a prover bundle JSON file to validate.",
    )


def _add_promote_arguments(parser: argparse.ArgumentParser) -> None:
    _add_output_arguments(parser)
    parser.add_argument(
        "--network",
        required=True,
        help="Network name recorded in the generated catalog snippet.",
    )
    parser.add_argument(
        "--contract-name",
        required=True,
        help="Contract name used when building relay artifact metadata.",
    )
    parser.add_argument(
        "--note-bundle",
        default=None,
        help="Ceremony-generated shielded-note bundle to import.",
    )
    parser.add_argument(
        "--command-bundle",
        default=None,
        help="Ceremony-generated shielded-command bundle to import.",
    )
    parser.add_argument(
        "--relay-command-bundle",
        default=None,
        help=(
            "Ceremony-generated shielded-command bundle to expose as a "
            "shielded-note relay_transfer manifest."
        ),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="xian-zk-shielded-bundle",
        description=(
            "Generate, import, or validate shielded proving bundles and registry manifests."
        ),
    )
    subparsers = parser.add_subparsers(dest="command")

    generate_note = subparsers.add_parser(
        "generate-note", help="Generate a random shielded-note bundle."
    )
    _add_generate_arguments(generate_note, bundle_type="shielded-note")

    import_note = subparsers.add_parser(
        "import-note",
        help="Import an externally generated shielded-note bundle.",
    )
    _add_import_arguments(import_note)

    validate_note = subparsers.add_parser(
        "validate-note",
        help="Validate a shielded-note bundle and print a summary.",
    )
    _add_validate_arguments(validate_note)

    generate_command = subparsers.add_parser(
        "generate-command",
        help="Generate a random shielded-command bundle.",
    )
    _add_generate_arguments(generate_command, bundle_type="shielded-command")

    import_command = subparsers.add_parser(
        "import-command",
        help="Import an externally generated shielded-command bundle.",
    )
    _add_import_arguments(import_command)

    validate_command = subparsers.add_parser(
        "validate-command",
        help="Validate a shielded-command bundle and print a summary.",
    )
    _add_validate_arguments(validate_command)

    promote = subparsers.add_parser(
        "promote",
        help="Import ceremony bundles and write combined operator handoff artifacts.",
    )
    _add_promote_arguments(promote)
    return parser


def _handle_generate_note(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir).expanduser().resolve()
    vk_id_prefix = args.vk_id_prefix or _default_vk_id_prefix(
        args.contract_name, bundle_type="shielded-note"
    )
    prover = ShieldedNoteProver.build_random_bundle(
        contract_name=args.contract_name,
        vk_id_prefix=vk_id_prefix,
    )
    _write_artifacts(
        output_dir=output_dir,
        overwrite=args.overwrite,
        bundle_json=prover.bundle_json + "\n",
        manifest=_note_manifest_from_prover(prover),
        title="Shielded Note Deployment",
        bundle_filename="shielded-note-bundle.json",
        manifest_filename="shielded-note-registry-manifest.json",
        instructions_filename="shielded-note-deployment.md",
    )
    return 0


def _handle_import_note(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir).expanduser().resolve()
    bundle_json, _ = load_and_validate_bundle_text(args.bundle, bundle_type="note")
    prover = ShieldedNoteProver(bundle_json)
    _write_artifacts(
        output_dir=output_dir,
        overwrite=args.overwrite,
        bundle_json=bundle_json,
        manifest=_note_manifest_from_prover(prover),
        title="Shielded Note Deployment",
        bundle_filename="shielded-note-bundle.json",
        manifest_filename="shielded-note-registry-manifest.json",
        instructions_filename="shielded-note-deployment.md",
    )
    return 0


def _handle_validate_note(args: argparse.Namespace) -> int:
    _, normalized = load_and_validate_bundle_text(args.bundle, bundle_type="note")
    print(f"valid note bundle: {bundle_summary(normalized, bundle_type='note')}")
    print(f"contract_name={normalized['contract_name']}")
    print(f"setup_ceremony={normalized['setup_ceremony'] or '-'}")
    return 0


def _handle_generate_command(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir).expanduser().resolve()
    vk_id_prefix = args.vk_id_prefix or _default_vk_id_prefix(
        args.contract_name, bundle_type="shielded-command"
    )
    prover = ShieldedCommandProver.build_random_bundle(
        contract_name=args.contract_name,
        vk_id_prefix=vk_id_prefix,
    )
    _write_artifacts(
        output_dir=output_dir,
        overwrite=args.overwrite,
        bundle_json=prover.bundle_json + "\n",
        manifest=_command_manifest_from_prover(prover),
        title="Shielded Command Deployment",
        bundle_filename="shielded-command-bundle.json",
        manifest_filename="shielded-command-registry-manifest.json",
        instructions_filename="shielded-command-deployment.md",
    )
    return 0


def _handle_import_command(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir).expanduser().resolve()
    bundle_json, _ = load_and_validate_bundle_text(args.bundle, bundle_type="command")
    prover = ShieldedCommandProver(bundle_json)
    _write_artifacts(
        output_dir=output_dir,
        overwrite=args.overwrite,
        bundle_json=bundle_json,
        manifest=_command_manifest_from_prover(prover),
        title="Shielded Command Deployment",
        bundle_filename="shielded-command-bundle.json",
        manifest_filename="shielded-command-registry-manifest.json",
        instructions_filename="shielded-command-deployment.md",
    )
    return 0


def _handle_validate_command(args: argparse.Namespace) -> int:
    _, normalized = load_and_validate_bundle_text(args.bundle, bundle_type="command")
    print(f"valid command bundle: {bundle_summary(normalized, bundle_type='command')}")
    print(f"contract_name={normalized['contract_name']}")
    print(f"setup_ceremony={normalized['setup_ceremony'] or '-'}")
    return 0


def _artifact_record(
    *,
    kind: str,
    manifest_path: Path,
    manifest_filename: str,
    manifest: dict[str, object],
) -> dict[str, object]:
    return {
        "kind": kind,
        "contract_name": manifest["contract_name"],
        "registry_manifest_path": f"./{manifest_filename}",
        "sha256": _sha256_file(manifest_path),
        "setup_mode": manifest.get("setup_mode", ""),
        "setup_ceremony": manifest.get("setup_ceremony", ""),
        "bundle_hash": manifest.get("bundle_hash", ""),
    }


def _write_promoted_artifact(
    *,
    output_dir: Path,
    overwrite: bool,
    bundle_json: str,
    manifest: dict[str, object],
    bundle_filename: str,
    manifest_filename: str,
) -> tuple[Path, Path]:
    bundle_path = output_dir / bundle_filename
    manifest_path = output_dir / manifest_filename
    _write_text(bundle_path, bundle_json, overwrite=overwrite)
    _write_text(
        manifest_path,
        json.dumps(manifest, sort_keys=True, indent=2) + "\n",
        overwrite=overwrite,
    )
    return bundle_path, manifest_path


def _handle_promote(args: argparse.Namespace) -> int:
    if not (args.note_bundle or args.command_bundle or args.relay_command_bundle):
        raise SystemExit(
            "promote requires at least one of --note-bundle, --command-bundle, "
            "or --relay-command-bundle"
        )

    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest_filenames: list[str] = []
    artifact_records: list[dict[str, object]] = []
    written_bundles: list[Path] = []
    written_manifests: list[Path] = []

    if args.note_bundle:
        bundle_json, _ = load_and_validate_bundle_text(
            args.note_bundle,
            bundle_type="note",
        )
        prover = ShieldedNoteProver(bundle_json)
        manifest_filename = "shielded-note-registry-manifest.json"
        bundle_path, manifest_path = _write_promoted_artifact(
            output_dir=output_dir,
            overwrite=args.overwrite,
            bundle_json=bundle_json,
            manifest=_note_manifest_from_prover(prover),
            bundle_filename="shielded-note-bundle.json",
            manifest_filename=manifest_filename,
        )
        manifest = json.loads(manifest_path.read_text())
        manifest_filenames.append(manifest_filename)
        written_bundles.append(bundle_path)
        written_manifests.append(manifest_path)
        artifact_records.append(
            _artifact_record(
                kind=_ARTIFACT_KINDS["note"],
                manifest_path=manifest_path,
                manifest_filename=manifest_filename,
                manifest=manifest,
            )
        )

    if args.command_bundle:
        bundle_json, _ = load_and_validate_bundle_text(
            args.command_bundle,
            bundle_type="command",
        )
        prover = ShieldedCommandProver(bundle_json)
        manifest_filename = "shielded-command-registry-manifest.json"
        bundle_path, manifest_path = _write_promoted_artifact(
            output_dir=output_dir,
            overwrite=args.overwrite,
            bundle_json=bundle_json,
            manifest=_command_manifest_from_prover(prover),
            bundle_filename="shielded-command-bundle.json",
            manifest_filename=manifest_filename,
        )
        manifest = json.loads(manifest_path.read_text())
        manifest_filenames.append(manifest_filename)
        written_bundles.append(bundle_path)
        written_manifests.append(manifest_path)
        artifact_records.append(
            _artifact_record(
                kind=_ARTIFACT_KINDS["command"],
                manifest_path=manifest_path,
                manifest_filename=manifest_filename,
                manifest=manifest,
            )
        )

    if args.relay_command_bundle:
        bundle_json, _ = load_and_validate_bundle_text(
            args.relay_command_bundle,
            bundle_type="command",
        )
        prover = ShieldedRelayTransferProver(bundle_json)
        manifest_filename = "shielded-relay-registry-manifest.json"
        bundle_path, manifest_path = _write_promoted_artifact(
            output_dir=output_dir,
            overwrite=args.overwrite,
            bundle_json=bundle_json,
            manifest=_relay_manifest_from_prover(
                prover,
                artifact_contract_name=args.contract_name,
            ),
            bundle_filename="shielded-relay-command-bundle.json",
            manifest_filename=manifest_filename,
        )
        manifest = json.loads(manifest_path.read_text())
        manifest_filenames.append(manifest_filename)
        written_bundles.append(bundle_path)
        written_manifests.append(manifest_path)
        artifact_records.append(
            _artifact_record(
                kind=_ARTIFACT_KINDS["relay"],
                manifest_path=manifest_path,
                manifest_filename=manifest_filename,
                manifest=manifest,
            )
        )

    script_path = output_dir / "register_and_bind.py"
    _write_text(
        script_path,
        _operator_script(manifest_filenames=manifest_filenames),
        overwrite=args.overwrite,
    )
    summary_path = output_dir / "promotion-summary.json"
    _write_text(
        summary_path,
        json.dumps(
            {
                "schema_version": 1,
                "network": args.network,
                "contract_name": args.contract_name,
                "registry_manifests": [path.name for path in written_manifests],
                "private_bundles": [path.name for path in written_bundles],
                "operator_script": script_path.name,
                "artifact_catalog_entries": artifact_records,
            },
            sort_keys=True,
            indent=2,
        )
        + "\n",
        overwrite=args.overwrite,
    )
    catalog_snippet_path = output_dir / "catalog-artifacts-snippet.json"
    _write_text(
        catalog_snippet_path,
        json.dumps(artifact_records, sort_keys=True, indent=2) + "\n",
        overwrite=args.overwrite,
    )

    print(f"Promoted artifacts for network: {args.network}")
    for path in written_bundles:
        print(f"Generated bundle: {path}")
    for path in written_manifests:
        print(f"Generated registry manifest: {path}")
    print(f"Generated operator script: {script_path}")
    print(f"Generated promotion summary: {summary_path}")
    print(f"Generated catalog snippet: {catalog_snippet_path}")
    print()
    print("Private bundle files contain proving keys; keep them offline and access-controlled.")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    handlers = {
        "generate-note": _handle_generate_note,
        "import-note": _handle_import_note,
        "validate-note": _handle_validate_note,
        "generate-command": _handle_generate_command,
        "import-command": _handle_import_command,
        "validate-command": _handle_validate_command,
        "promote": _handle_promote,
    }
    if args.command is None:
        raise SystemExit("a bundle subcommand is required")
    return handlers[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
