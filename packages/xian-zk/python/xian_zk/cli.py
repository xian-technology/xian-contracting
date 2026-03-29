from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from xian_zk import ShieldedNoteProver, shielded_registry_manifest


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", value).strip("-").lower()
    return slug or "shielded-note"


def _default_vk_id_prefix(contract_name: str) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{_slugify(contract_name)}-shielded-note-v2-{timestamp}"


def _write_text(path: Path, content: str, *, overwrite: bool) -> None:
    if path.exists() and not overwrite:
        raise FileExistsError(
            f"{path} already exists; pass --overwrite to replace it"
        )
    path.write_text(content)


def _deployment_instructions(manifest: dict[str, object]) -> str:
    registry_entries = manifest["registry_entries"]
    configure_actions = manifest["configure_actions"]

    lines = [
        "# Shielded Note Deployment",
        "",
        "This directory contains:",
        "",
        "- `shielded-note-bundle.json`: private proving bundle. Keep this offline and access-controlled.",
        "- `shielded-note-registry-manifest.json`: public verifying-key manifest for `zk_registry`.",
        "- `shielded-note-deployment.md`: this operator guide.",
        "",
        "## Register Verifying Keys",
        "",
        "```python",
        'manifest = json.loads(Path("shielded-note-registry-manifest.json").read_text())',
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
        "## Bind The Token",
        "",
        "```python",
        'manifest = json.loads(Path("shielded-note-registry-manifest.json").read_text())',
        'for binding in manifest["configure_actions"]:',
        "    token.configure_vk(",
        '        action=binding["action"],',
        '        vk_id=binding["vk_id"],',
        '        signer="sys",',
        "    )",
        "```",
        "",
        "## Warning",
        "",
        str(manifest["warning"]),
        "",
        "A single-party random setup is materially better than the deterministic dev bundle,",
        "but it is still not a multi-party ceremony. If you need ceremony-grade trust reduction,",
        "generate proving material from an external MPC setup and import those keys instead of",
        "treating this output as a substitute for an MPC transcript.",
    ]

    if isinstance(registry_entries, list) and isinstance(
        configure_actions, list
    ):
        lines.extend(
            [
                "",
                "## Generated IDs",
                "",
            ]
        )
        for entry in registry_entries:
            if not isinstance(entry, dict):
                continue
            lines.append(f"- `{entry['vk_id']}` for `{entry['circuit_name']}`")

    return "\n".join(lines) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="xian-zk-shielded-bundle",
        description=(
            "Generate a random shielded-note proving bundle and a registry-ready "
            "verifying-key manifest."
        ),
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        help="Directory where bundle and manifest files will be written.",
    )
    parser.add_argument(
        "--contract-name",
        default="con_shielded_note_token",
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
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite existing files in the output directory.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    vk_id_prefix = args.vk_id_prefix or _default_vk_id_prefix(
        args.contract_name
    )
    prover = ShieldedNoteProver.build_random_bundle(
        contract_name=args.contract_name,
        vk_id_prefix=vk_id_prefix,
    )
    manifest = shielded_registry_manifest(prover)

    bundle_path = output_dir / "shielded-note-bundle.json"
    manifest_path = output_dir / "shielded-note-registry-manifest.json"
    instructions_path = output_dir / "shielded-note-deployment.md"

    _write_text(bundle_path, prover.bundle_json, overwrite=args.overwrite)
    _write_text(
        manifest_path,
        json.dumps(manifest, sort_keys=True, indent=2) + "\n",
        overwrite=args.overwrite,
    )
    _write_text(
        instructions_path,
        _deployment_instructions(manifest),
        overwrite=args.overwrite,
    )

    print(f"Generated shielded-note bundle: {bundle_path}")
    print(f"Generated registry manifest: {manifest_path}")
    print(f"Generated operator guide: {instructions_path}")
    print()
    print("Bundle warning:")
    print(manifest["warning"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
