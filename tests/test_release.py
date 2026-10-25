"""Tests for the release helpers."""

from __future__ import annotations

import json
import os
import random
import subprocess
import sys
from pathlib import Path

import pytest

from ci_checks import release
from helpers import Repo

PUBLISH = Path(__file__).resolve().parent.parent / "actions" / "release" / "publish.sh"
SRC = Path(release.__file__).resolve().parent.parent
# A gh stand-in: logs its arguments, answers tag lookups from FAKE_GH_TAGS
# (a tag created by `release create` exists afterwards), and fails
# `release create` when FAKE_GH_CREATE_FAILS is set.
FAKE_GH = """\
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
log = Path(os.environ["FAKE_GH_LOG"])
created = [json.loads(line)[2] for line in log.read_text().splitlines()] if log.exists() else []
with log.open("a") as handle:
    handle.write(json.dumps(args) + "\\n")
tags = os.environ["FAKE_GH_TAGS"].split()
if args[:2] == ["release", "create"]:
    sys.exit(1 if os.environ.get("FAKE_GH_CREATE_FAILS") else 0)
if "--paginate" in args:
    print("\\n".join(f"refs/tags/{tag}" for tag in tags))
    sys.exit(0)
sys.exit(0 if args[1].rsplit("/", 1)[1] in tags + created else 1)
"""

CHANGELOG = """# Changelog

## [Unreleased]

## [1.2.0] - 2026-01-02

### Added

- A sensor.

## 1.1.0

- Initial release.

## [1.0.1](https://github.com/owner/repo/compare/v1.0.0...v1.0.1) (2026-01-01)

- A fix.

## [1.0.0]
"""


def write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("manifest.json", json.dumps({"domain": "demo", "version": "1.2.0"})),
        ("config.yaml", 'name: Demo\nversion: "1.2.0"  # bumped\nslug: demo\n'),
        ("pyproject.toml", '[project]\nname = "demo"\nversion = "1.2.0"\n'),
        ("VERSION", "1.2.0\n"),
    ],
)
def test_read_version(tmp_path: Path, name: str, content: str) -> None:
    assert release.read_version(write(tmp_path / name, content)) == "1.2.0"


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("manifest.json", json.dumps({"domain": "demo"})),
        ("config.yaml", "name: Demo\n"),
        ("manifest.json", "[]"),
        ("pyproject.toml", 'project = "demo"\n'),
        ("VERSION", ""),
        ("VERSION", "latest\n"),
    ],
)
def test_read_version_invalid(tmp_path: Path, name: str, content: str) -> None:
    with pytest.raises(release.ReleaseError):
        release.read_version(write(tmp_path / name, content))


def test_find_version_file(tmp_path: Path) -> None:
    with pytest.raises(release.ReleaseError):
        release.find_version_file(tmp_path)
    manifest = write(tmp_path / "custom_components/demo/manifest.json", "{}")
    assert release.find_version_file(tmp_path) == manifest


def test_release_notes() -> None:
    assert release.release_notes(CHANGELOG, "1.2.0") == "### Added\n\n- A sensor.\n"
    assert release.release_notes(CHANGELOG, "1.1.0") == "- Initial release.\n"
    assert release.release_notes(CHANGELOG, "1.0.1") == "- A fix.\n"
    with pytest.raises(release.ReleaseError, match="no section"):
        release.release_notes(CHANGELOG, "1.0")
    with pytest.raises(release.ReleaseError, match="empty"):
        release.release_notes(CHANGELOG, "1.0.0")
    with pytest.raises(release.ReleaseError, match="no section"):
        release.release_notes(CHANGELOG, "9.9.9")


def test_version_key() -> None:
    ordered = [
        "0.9.12",
        "1.0.0.dev1",
        "1.0.0a1",
        "1.0.0-alpha.2",
        "1.0.0b1",
        "1.0.0-beta.3",
        "1.0.0rc1",
        "1.0.0rc10",
        "1.0.0",
        "1.0.1",
        "1.2.0",
        "1.10.0",
        "10.0.0",
    ]
    shuffled = random.Random(3).sample(ordered, len(ordered))
    assert sorted(shuffled, key=release.version_key) == ordered
    assert release.version_key("1.0.0-alpha.1") == release.version_key("1.0.0a1")
    with pytest.raises(release.ReleaseError):
        release.version_key("latest")


def test_check_newer() -> None:
    tags = ["refs/tags/v1.2.0", "refs/tags/v1.10.0b1\n", "refs/tags/latest", "refs/tags/v2"]
    release.check_newer("1.10.0", tags)
    release.check_newer("1.10.0rc1", tags)
    release.check_newer("1.0.0", [])
    for version in ("1.10.0b1", "1.10.0a1", "1.2.0", "1.1.9"):
        with pytest.raises(release.ReleaseError, match="not greater than the existing release"):
            release.check_newer(version, tags)


def commit_version(repo: Repo, version: str, extra: str = "") -> str:
    repo.write("custom_components/demo/manifest.json", json.dumps({"version": version}))
    repo.write("notes.txt", extra)
    return repo.commit()


def test_version_changed(repo: Repo, tmp_path: Path) -> None:
    manifest = repo.root / "custom_components/demo/manifest.json"
    commit_version(repo, "1.0.0")
    assert release.version_changed(repo.root, manifest, "1.0.0")
    commit_version(repo, "1.1.0")
    assert release.version_changed(repo.root, manifest, "1.1.0")
    commit_version(repo, "1.1.0", "feature")
    assert not release.version_changed(repo.root, manifest, "1.1.0")

    repo.write("VERSION", "2.0.0\n")
    repo.commit()
    assert release.version_changed(repo.root, repo.root / "VERSION", "2.0.0")
    repo.write("custom_components/demo/manifest.json", "{")
    repo.commit()
    commit_version(repo, "1.1.0")
    assert release.version_changed(repo.root, manifest, "1.1.0")

    clone = tmp_path / "shallow"
    repo.git("clone", "--quiet", "--depth=1", f"file://{repo.root}", str(clone))
    with pytest.raises(release.ReleaseError, match="fetch-depth: 2"):
        release.version_changed(clone, clone / "custom_components/demo/manifest.json", "1.1.0")
    deeper = tmp_path / "deeper"
    repo.git("clone", "--quiet", "--depth=2", f"file://{repo.root}", str(deeper))
    assert release.version_changed(deeper, deeper / "custom_components/demo/manifest.json", "1.1.0")


def test_main(repo: Repo, capsys: pytest.CaptureFixture[str]) -> None:
    tmp_path = repo.root
    write(tmp_path / "custom_components/demo/manifest.json", json.dumps({"version": "2.0.0b1"}))
    write(tmp_path / "CHANGELOG.md", "## [2.0.0b1]\n\n- Beta.\n")
    repo.commit()
    root = ["--root", str(tmp_path)]

    assert release.main([*root, "version"]) == 0
    assert capsys.readouterr().out == "version=2.0.0b1\nprerelease=true\nchanged=true\n"

    assert release.main([*root, "notes", "--version", "2.0.0b1"]) == 0
    assert capsys.readouterr().out == "- Beta.\n"

    assert release.main([*root, "notes", "--version", "3.0.0"]) == 1
    assert "::error::The changelog has no section for 3.0.0." in capsys.readouterr().err

    assert release.main([*root, "version", "--file", "missing.json"]) == 1


def test_main_newer(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(sys, "stdin", ["refs/tags/v1.0.0\n", "refs/tags/v1.1.0\n"])
    assert release.main(["newer", "--version", "1.2.0"]) == 0
    assert release.main(["newer", "--version", "1.1.0"]) == 1
    assert "1.1.0 is not greater than the existing release v1.1.0." in capsys.readouterr().err


def publish(
    tmp_path: Path,
    tags: str,
    *,
    changed: bool = True,
    prerelease: bool = False,
    fails: bool = False,
) -> tuple[subprocess.CompletedProcess[str], list[list[str]]]:
    """Run publish.sh for version 1.2.0 with a stand-in gh, and return its gh calls."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    gh = bin_dir / "gh"
    gh.write_text(f"#!{sys.executable}\n{FAKE_GH}", encoding="utf-8")
    gh.chmod(0o755)
    (bin_dir / "python3").unlink(missing_ok=True)
    (bin_dir / "python3").symlink_to(sys.executable)
    version = "1.2.0b1" if prerelease else "1.2.0"
    write(tmp_path / "CHANGELOG.md", f"## [{version}]\n\n- A fix.\n")
    log = tmp_path / "gh.log"
    log.unlink(missing_ok=True)
    env = {
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "PYTHONPATH": str(SRC),
        "FAKE_GH_LOG": str(log),
        "FAKE_GH_TAGS": tags,
        "GITHUB_REPOSITORY": "owner/repo",
        "SHA": "a" * 40,
        "VERSION": version,
        "PRERELEASE": "true" if prerelease else "false",
        "CHANGED": "true" if changed else "false",
        "CHANGELOG": "CHANGELOG.md",
    }
    if fails:
        env["FAKE_GH_CREATE_FAILS"] = "1"
    result = subprocess.run(
        ["bash", str(PUBLISH)], cwd=tmp_path, env=env, capture_output=True, text=True, check=False
    )
    calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
    return result, calls


def created(calls: list[list[str]]) -> list[list[str]]:
    return [call[2:] for call in calls if call[:2] == ["release", "create"]]


def test_publish_latest(tmp_path: Path) -> None:
    result, calls = publish(tmp_path, "v1.0.0 v1.1.0 latest")
    assert result.returncode == 0, result.stderr
    [args] = created(calls)
    assert args[0] == "v1.2.0"
    assert args[args.index("--target") + 1] == "a" * 40
    assert args[-1] == "--latest"
    assert "--prerelease" not in args
    assert "::notice::Published v1.2.0." in result.stdout


def test_publish_pre_release(tmp_path: Path) -> None:
    result, calls = publish(tmp_path, "v1.1.0", prerelease=True)
    assert result.returncode == 0, result.stderr
    [args] = created(calls)
    assert args[0] == "v1.2.0b1"
    assert args[-2:] == ["--prerelease", "--latest=false"]


def test_publish_only_from_the_commit_that_changed_the_version(tmp_path: Path) -> None:
    result, calls = publish(tmp_path, "v1.1.0", changed=False)
    assert result.returncode == 0
    assert "does not change the version (1.2.0); nothing to release." in result.stdout
    assert calls == []


def test_publish_existing_tag(tmp_path: Path) -> None:
    result, calls = publish(tmp_path, "v1.2.0 v1.3.0")
    assert result.returncode == 0
    assert "Tag v1.2.0 already exists" in result.stdout
    assert created(calls) == []


def test_publish_refuses_an_older_version(tmp_path: Path) -> None:
    result, calls = publish(tmp_path, "v1.1.0 v1.3.0")
    assert result.returncode == 1
    assert "1.2.0 is not greater than the existing release v1.3.0." in result.stderr
    assert created(calls) == []


def test_publish_race(tmp_path: Path) -> None:
    # Another run created the tag: the failed create is not an error.
    result, calls = publish(tmp_path, "v1.1.0", fails=True)
    assert result.returncode == 0
    assert "Tag v1.2.0 was created by another run" in result.stdout
    assert len(created(calls)) == 1
