"""Read the release version and its notes.

`version` prints the version declared by the project and whether the checked
out commit changed it, `newer` fails unless a version is greater than every
version tag read from standard input, and `notes` prints the section of
CHANGELOG.md for a version. They fail loudly so that a release is never
published with a wrong tag, from the wrong commit or with empty notes.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tomllib
from collections.abc import Iterable
from pathlib import Path

from ci_checks._common import fail, git

VERSION = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:[-.]?(a|b|rc|alpha|beta|dev)\.?(\d*))?$")
PRERELEASE = re.compile(r"[a-z]", re.IGNORECASE)
# Pre-release phases in the order of PEP 440; a release comes after all of them.
_PHASES = {"dev": 0, "a": 1, "alpha": 1, "b": 2, "beta": 2, "rc": 3}
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
    return parse_version(path, path.read_text(encoding="utf-8"))


def parse_version(path: Path, text: str) -> str:
    """Return the version declared in the content of a version file."""
    if path.suffix == ".json":
        data = json.loads(text)
        version = data.get("version") if isinstance(data, dict) else None
    elif path.suffix in {".yaml", ".yml"}:
        match = _YAML_VERSION.search(text)
        version = match.group(1) if match else None
    elif path.suffix == ".toml":
        project = tomllib.loads(text).get("project")
        version = project.get("version") if isinstance(project, dict) else None
    else:
        version = text.strip().splitlines()[0] if text.strip() else None
    if not isinstance(version, str) or not VERSION.match(version):
        raise ReleaseError(f"{path.name} does not declare a valid version.")
    return version


def version_key(version: str) -> tuple[int, ...]:
    """Return a sort key that puts pre-releases before their release."""
    match = VERSION.match(version)
    if match is None:
        raise ReleaseError(f"{version} is not a valid version.")
    major, minor, patch, phase, number = match.groups()
    rank = _PHASES[phase] if phase else len(_PHASES)
    return (int(major), int(minor), int(patch), rank, int(number or 0))


def version_changed(root: Path, path: Path, version: str) -> bool:
    """Return whether the checked out commit changed the version of its first parent.

    The first commit of the repository, a new version file, or a parent
    without a valid version count as a change.
    """
    parents = git("rev-list", "--parents", "--max-count=1", "HEAD", cwd=root).split()[1:]
    if not parents:
        if git("rev-parse", "--is-shallow-repository", cwd=root).strip() == "true":
            raise ReleaseError("The parent commit is not checked out. Use fetch-depth: 2.")
        return True
    relative = path.resolve().relative_to(root.resolve()).as_posix()
    try:
        previous = parse_version(path, git("show", f"{parents[0]}:{relative}", cwd=root))
    except (subprocess.CalledProcessError, ReleaseError, ValueError):
        return True
    return previous != version


def check_newer(version: str, tags: Iterable[str]) -> None:
    """Fail unless the version is greater than every v<version> tag.

    Workflow runs can finish in any order, and the newest release becomes
    the latest one, so an older version must never be published after a
    newer one.
    """
    key = version_key(version)
    for ref in tags:
        tag = ref.strip().removeprefix("refs/tags/")
        if tag.startswith("v") and VERSION.match(tag[1:]) and version_key(tag[1:]) >= key:
            raise ReleaseError(
                f"{version} is not greater than the existing release {tag}. Bump the version."
            )


def release_notes(changelog: str, version: str) -> str:
    """Return the body of the changelog section for a version."""
    # "## [1.2.0] - 2026-01-31", "## v1.2.0", or "## [1.2.0](<compare link>) (date)".
    heading = re.compile(rf"^##\s+\[?v?{re.escape(version)}\]?(?:\([^)\s]*\))?(?:\s|$)")
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
    newer_parser = commands.add_parser("newer")
    newer_parser.add_argument("--version", required=True)
    notes_parser = commands.add_parser("notes")
    notes_parser.add_argument("--version", required=True)
    notes_parser.add_argument("--changelog", default="CHANGELOG.md")
    args = parser.parse_args(argv)

    try:
        if args.command == "version":
            path = args.root / args.file if args.file else find_version_file(args.root)
            version = read_version(path)
            changed = version_changed(args.root, path, version)
            print(f"version={version}")
            print(f"prerelease={'true' if PRERELEASE.search(version) else 'false'}")
            print(f"changed={'true' if changed else 'false'}")
        elif args.command == "newer":
            check_newer(args.version, sys.stdin)
        else:
            changelog = (args.root / args.changelog).read_text(encoding="utf-8")
            print(release_notes(changelog, args.version), end="")
    except (OSError, ReleaseError, ValueError, subprocess.CalledProcessError) as err:
        # Standard output is captured into step outputs and notes; errors go
        # to standard error so that they show in the log.
        return fail(str(err))
    return 0


if __name__ == "__main__":
    sys.exit(main())
