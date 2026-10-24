"""Read the release version and its notes.

`version` prints the version declared by the project, and `notes` prints the
section of CHANGELOG.md for a version. Both fail loudly so that a release is
never published with a wrong tag or empty notes.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path

from ci_checks._common import fail

VERSION = re.compile(r"^\d+\.\d+\.\d+(?:[-.]?(?:a|b|rc|alpha|beta|dev)\.?\d*)?$")
PRERELEASE = re.compile(r"[a-z]", re.IGNORECASE)
_YAML_VERSION = re.compile(r"""^version:\s*["']?([^"'\s#]+)["']?\s*(?:#.*)?$""", re.MULTILINE)


class ReleaseError(Exception):
    """Raised when the version or the notes cannot be determined."""


def find_version_file(root: Path) -> Path:
    """Return the only integration manifest of the repository."""
    manifests = sorted(root.glob("custom_components/*/manifest.json"))
    if len(manifests) != 1:
        raise ReleaseError(
            f"Found {len(manifests)} integration manifests; set version-file explicitly."
        )
    return manifests[0]


def read_version(path: Path) -> str:
    """Return the version declared in a manifest, app config, pyproject or text file."""
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        version = json.loads(text).get("version")
    elif path.suffix in {".yaml", ".yml"}:
        match = _YAML_VERSION.search(text)
        version = match.group(1) if match else None
    elif path.suffix == ".toml":
        version = tomllib.loads(text).get("project", {}).get("version")
    else:
        version = text.strip().splitlines()[0] if text.strip() else None
    if not isinstance(version, str) or not VERSION.match(version):
        raise ReleaseError(f"{path.name} does not declare a valid version.")
    return version


def release_notes(changelog: str, version: str) -> str:
    """Return the body of the changelog section for a version."""
    heading = re.compile(rf"^##\s+\[?v?{re.escape(version)}\]?(?:\s|$)")
    lines = changelog.splitlines()
    for index, line in enumerate(lines):
        if heading.match(line):
            body = []
            for following in lines[index + 1 :]:
                if following.startswith("## "):
                    break
                body.append(following)
            notes = "\n".join(body).strip()
            if not notes:
                raise ReleaseError(f"The changelog section for {version} is empty.")
            return notes + "\n"
    raise ReleaseError(f"The changelog has no section for {version}.")


def main(argv: list[str] | None = None) -> int:
    """Print the version or the release notes."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=Path.cwd())
    commands = parser.add_subparsers(dest="command", required=True)
    version_parser = commands.add_parser("version")
    version_parser.add_argument("--file", default="")
    notes_parser = commands.add_parser("notes")
    notes_parser.add_argument("--version", required=True)
    notes_parser.add_argument("--changelog", default="CHANGELOG.md")
    args = parser.parse_args(argv)

    try:
        if args.command == "version":
            path = args.root / args.file if args.file else find_version_file(args.root)
            version = read_version(path)
            print(f"version={version}")
            print(f"prerelease={'true' if PRERELEASE.search(version) else 'false'}")
        else:
            changelog = (args.root / args.changelog).read_text(encoding="utf-8")
            print(release_notes(changelog, args.version), end="")
    except (OSError, ReleaseError, ValueError) as err:
        # Standard output is captured into step outputs and notes; errors go
        # to standard error so that they show in the log.
        return fail(str(err))
    return 0


if __name__ == "__main__":
    sys.exit(main())
