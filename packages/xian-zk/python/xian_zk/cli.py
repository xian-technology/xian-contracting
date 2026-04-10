from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from xian_zk import (
    ShieldedCommandProver,
    ShieldedNoteProver,
    bundle_summary,
    shielded_command_registry_manifest,
    shielded_registry_manifest,
)
from xian_zk.bundles import load_and_validate_bundle_text


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", value).strip("-").lower()
    return slug or "shielded-note"


def _default_vk_id_prefix(contract_name: str, *, bundle_type: str) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{_slugify(contract_name)}-{bundle_type}-v2-{timestamp}"


def _write_text(path: Path, content: str, *, overwrite: bool) -> None:
    if path.exists() and not overwrite:
        raise FileExistsError(
            f"{path} already exists; pass --overwrite to replace it"
        )
    path.write_text(content)


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
        "",
        "## Register Verifying Keys",
        "",
        "```python",
        f'manifest = json.loads(Path("{manifest_filename}").read_text())',
        'for entry in manifest["registry_entries"]:',
        "    zk_registry.register_vk(",
        '        vk_id=entry["vk_id"],',
        '        vk_hex=entry["vk_hex"],',
        '        circuit_name=entry["circuit_name"],',
        '        version=entry["version"],',
        '        signer="sys",',
        "    )",
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

    if isinstance(registry_entries, list) and isinstance(
        configure_actions, list
    ):
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
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    bundle_path = output_dir / bundle_filename
    manifest_path = output_dir / manifest_filename
    instructions_path = output_dir / instructions_filename

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

    print(f"Generated bundle: {bundle_path}")
    print(f"Generated registry manifest: {manifest_path}")
    print(f"Generated operator guide: {instructions_path}")
    print()
    print("Bundle warning:")
    print(manifest["warning"])


def _note_manifest_from_prover(prover: ShieldedNoteProver) -> dict[str, object]:
    return shielded_registry_manifest(prover)


def _command_manifest_from_prover(
    prover: ShieldedCommandProver,
) -> dict[str, object]:
    return shielded_command_registry_manifest(prover)


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


def _add_generate_arguments(
    parser: argparse.ArgumentParser, *, bundle_type: str
) -> None:
    _add_output_arguments(parser)
    default_contract_name = (
        "con_shielded_note_token"
        if bundle_type == "shielded-note"
        else "con_shielded_commands"
    )
    parser.add_argument(
        "--contract-name",
        default=default_contract_name,
        help="Contract name to record in the generated bundle metadata.",
    )
    parser.add_argument(
        "--vk-id-prefix",
        default=None,
        help=(
            "Prefix used to derive vk ids. Defaults to a timestamped "
            "contract-specific prefix."
        ),
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="xian-zk-shielded-bundle",
        description=(
            "Generate, import, or validate shielded proving bundles and "
            "registry manifests."
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
    return parser


def _legacy_argv(argv: list[str] | None) -> list[str] | None:
    resolved = list(sys.argv[1:] if argv is None else argv)
    if len(resolved) == 0:
        return resolved
    if resolved[0].startswith("-"):
        return ["generate-note", *resolved]
    return resolved


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
    bundle_json, _ = load_and_validate_bundle_text(
        args.bundle, bundle_type="note"
    )
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
    _, normalized = load_and_validate_bundle_text(
        args.bundle, bundle_type="note"
    )
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
    bundle_json, _ = load_and_validate_bundle_text(
        args.bundle, bundle_type="command"
    )
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
    _, normalized = load_and_validate_bundle_text(
        args.bundle, bundle_type="command"
    )
    print(
        f"valid command bundle: {bundle_summary(normalized, bundle_type='command')}"
    )
    print(f"contract_name={normalized['contract_name']}")
    print(f"setup_ceremony={normalized['setup_ceremony'] or '-'}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(_legacy_argv(argv))

    handlers = {
        "generate-note": _handle_generate_note,
        "import-note": _handle_import_note,
        "validate-note": _handle_validate_note,
        "generate-command": _handle_generate_command,
        "import-command": _handle_import_command,
        "validate-command": _handle_validate_command,
    }
    if args.command is None:
        raise SystemExit("a bundle subcommand is required")
    return handlers[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
