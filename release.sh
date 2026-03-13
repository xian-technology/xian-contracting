#!/usr/bin/env bash

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}==>${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}WARNING:${NC} $1"
}

print_error() {
    echo -e "${RED}ERROR:${NC} $1"
}

if [[ $# -ne 1 ]]; then
    print_error "Please provide a version bump type: patch, minor, or major"
    echo "Usage: ./release.sh [patch|minor|major]"
    exit 1
fi

bump_type="$1"
if [[ "${bump_type}" != "patch" && "${bump_type}" != "minor" && "${bump_type}" != "major" ]]; then
    print_error "Invalid version bump type. Please use: patch, minor, or major"
    exit 1
fi

branch="$(git branch --show-current)"
if [[ "${branch}" != "master" ]]; then
    print_error "Please switch to the master branch before creating a release"
    exit 1
fi

if [[ -n "$(git status --porcelain)" ]]; then
    print_error "Working directory is not clean. Please commit or stash changes first."
    exit 1
fi

if ! command -v uv >/dev/null 2>&1; then
    print_error "uv could not be found. Please install it first."
    exit 1
fi

current_version="$(
    python3 - <<'PY'
import re
from pathlib import Path

text = Path("pyproject.toml").read_text(encoding="utf-8")
match = re.search(r'^version = "([^"]+)"$', text, re.MULTILINE)
if not match:
    raise SystemExit("version not found in pyproject.toml")
print(match.group(1))
PY
)"

new_version="$(
    CURRENT_VERSION="${current_version}" BUMP_TYPE="${bump_type}" python3 - <<'PY'
import os

version = os.environ["CURRENT_VERSION"]
bump_type = os.environ["BUMP_TYPE"]
major, minor, patch = [int(part) for part in version.split(".")]

if bump_type == "major":
    major += 1
    minor = 0
    patch = 0
elif bump_type == "minor":
    minor += 1
    patch = 0
else:
    patch += 1

print(f"{major}.{minor}.{patch}")
PY
)"

print_status "Pulling latest changes from master..."
git pull origin master

print_status "Current version: ${current_version}"
print_status "New version will be: ${new_version}"

last_tag="$(git describe --tags --abbrev=0 2>/dev/null || echo "none")"
if [[ "${last_tag}" != "none" ]]; then
    print_status "Generating changelog since ${last_tag}..."
    changelog="$(git log "${last_tag}"..HEAD --oneline --pretty=format:'- %s')"
else
    changelog="$(git log --oneline --pretty=format:'- %s')"
fi

echo
echo "Changelog:"
echo "${changelog}"
echo

print_status "Syncing dependencies..."
UV_CACHE_DIR=/tmp/uv-cache uv sync --group dev

print_status "Running tests..."
HOME="${PWD}/.tmp-home" UV_CACHE_DIR=/tmp/uv-cache uv run pytest

echo
print_status "Ready to release version ${new_version}"
read -r -p "Continue? (y/n) " reply
if [[ ! "${reply}" =~ ^[Yy]$ ]]; then
    print_warning "Release cancelled."
    exit 0
fi

print_status "Updating version..."
CURRENT_VERSION="${current_version}" NEW_VERSION="${new_version}" python3 - <<'PY'
import os
import re
from pathlib import Path

path = Path("pyproject.toml")
text = path.read_text(encoding="utf-8")
updated = re.sub(
    rf'^version = "{re.escape(os.environ["CURRENT_VERSION"])}"$',
    f'version = "{os.environ["NEW_VERSION"]}"',
    text,
    count=1,
    flags=re.MULTILINE,
)
if updated == text:
    raise SystemExit("failed to update version in pyproject.toml")
path.write_text(updated, encoding="utf-8")
PY

release_notes="release_notes.md"
{
    echo "# Release Notes for v${new_version}"
    echo
    echo "## Changes"
    echo "${changelog}"
} > "${release_notes}"

print_status "Committing version bump..."
git add pyproject.toml "${release_notes}"
git commit -m "release(contracting): bump version to ${new_version}"

print_status "Creating and pushing tag v${new_version}..."
git tag -a "v${new_version}" -m "Version ${new_version}"
git push && git push --tags

rm -f "${release_notes}"

print_status "Release process initiated."
print_status "The publish workflow will build and upload v${new_version} automatically."
