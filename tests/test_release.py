"""Tests for the release helpers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ci_checks import release

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


def test_main(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    write(tmp_path / "custom_components/demo/manifest.json", json.dumps({"version": "2.0.0b1"}))
    write(tmp_path / "CHANGELOG.md", "## [2.0.0b1]\n\n- Beta.\n")
    root = ["--root", str(tmp_path)]

    assert release.main([*root, "version"]) == 0
    assert capsys.readouterr().out == "version=2.0.0b1\nprerelease=true\n"

    assert release.main([*root, "notes", "--version", "2.0.0b1"]) == 0
    assert capsys.readouterr().out == "- Beta.\n"

    assert release.main([*root, "notes", "--version", "3.0.0"]) == 1
    assert "::error::The changelog has no section for 3.0.0." in capsys.readouterr().err

    assert release.main([*root, "version", "--file", "missing.json"]) == 1
