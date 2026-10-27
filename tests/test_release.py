"""Tests for the release helpers."""

from __future__ import annotations

import json
import os
import random
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from ci_checks import release
from helpers import Repo

PUBLISH = Path(__file__).resolve().parent.parent / "actions" / "release" / "publish.sh"
SRC = Path(release.__file__).resolve().parent.parent
# A gh stand-in: logs its arguments and answers tag lookups from FAKE_GH_TAGS.
# A release that `release create` makes, or that a PATCH publishes, gets its
# tag. FAKE_GH_FAIL names the steps that fail; with FAKE_GH_RACE, another run
# has created the tag by then.
FAKE_GH = """\
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
log = Path(os.environ["FAKE_GH_LOG"])
with log.open("a") as handle:
    handle.write(json.dumps(args) + "\\n")
made = Path(f"{log}.tags")
tags = os.environ["FAKE_GH_TAGS"].split() + (made.read_text().split() if made.exists() else [])
method = args[args.index("--method") + 1] if "--method" in args else "GET"
if args[:2] == ["release", "create"]:
    step = "create"
elif method == "POST":
    step = "upload" if "--input" in args else "draft"
else:
    step = {"PATCH": "publish", "DELETE": "delete"}.get(method, "read")
failed = step in os.environ["FAKE_GH_FAIL"].split()
if step in ("create", "publish") and (not failed or os.environ.get("FAKE_GH_RACE")):
    with made.open("a") as handle:
        handle.write(os.environ["FAKE_GH_TAG"] + "\\n")
if failed:
    sys.exit(1)
if step == "draft":
    print("7 https://uploads.example/repos/owner/repo/releases/7/assets{?name,label}")
elif "--paginate" in args:
    print("\\n".join(f"refs/tags/{tag}" for tag in tags))
elif step == "read":
    sys.exit(0 if args[1].rsplit("/", 1)[1] in tags else 1)
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
    fail: str = "",
    race: bool = False,
    asset: bool = False,
    plan: bool = False,
    notes: str = "- A fix.\n",
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
    write(tmp_path / "CHANGELOG.md", f"## [{version}]\n\n{notes}")
    log = tmp_path / "gh.log"
    log.unlink(missing_ok=True)
    Path(f"{log}.tags").unlink(missing_ok=True)
    output = tmp_path / "output"
    output.unlink(missing_ok=True)
    env = {
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "PYTHONPATH": str(SRC),
        "FAKE_GH_LOG": str(log),
        "FAKE_GH_TAGS": tags,
        "FAKE_GH_TAG": f"v{version}",
        "FAKE_GH_FAIL": fail,
        "GITHUB_REPOSITORY": "owner/repo",
        "GITHUB_OUTPUT": str(output),
        "SHA": "a" * 40,
        "VERSION": version,
        "PRERELEASE": "true" if prerelease else "false",
        "CHANGED": "true" if changed else "false",
        "CHANGELOG": "CHANGELOG.md",
        "PLAN": "true" if plan else "false",
        "ASSET": str(tmp_path / "dist" / "demo.zip") if asset else "",
    }
    if race:
        env["FAKE_GH_RACE"] = "1"
    if asset and not (tmp_path / "dist").exists():
        write(tmp_path / "dist" / "demo.zip", "zip")
    result = subprocess.run(
        ["bash", str(PUBLISH)], cwd=tmp_path, env=env, capture_output=True, text=True, check=False
    )
    calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
    if output.exists():
        result.stdout += output.read_text()
    return result, calls


def created(calls: list[list[str]]) -> list[list[str]]:
    return [call[2:] for call in calls if call[:2] == ["release", "create"]]


def writes(calls: list[list[str]]) -> list[list[str]]:
    """Return the API calls that change releases, without the token-free reads."""
    return [call for call in calls if "--method" in call]


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
    assert "release=false" in result.stdout
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
    result, calls = publish(tmp_path, "v1.1.0", fail="create", race=True)
    assert result.returncode == 0
    assert "Tag v1.2.0 was created by another run" in result.stdout
    assert len(created(calls)) == 1


def test_publish_create_fails(tmp_path: Path) -> None:
    result, calls = publish(tmp_path, "v1.1.0", fail="create")
    assert result.returncode == 1
    assert len(created(calls)) == 1


@pytest.mark.parametrize("asset", [False, True])
def test_plan(tmp_path: Path, asset: bool) -> None:
    result, calls = publish(tmp_path, "v1.1.0", plan=True, asset=asset)
    assert result.returncode == 0, result.stderr
    assert "::notice::v1.2.0 will be released." in result.stdout
    assert result.stdout.endswith("release=true\n")
    assert created(calls) == []
    assert writes(calls) == []


def test_plan_existing_tag(tmp_path: Path) -> None:
    result, calls = publish(tmp_path, "v1.2.0", plan=True)
    assert result.returncode == 0
    assert result.stdout.endswith("release=false\n")
    assert writes(calls) == []


def test_plan_checks_the_notes(tmp_path: Path) -> None:
    # Nothing is built for a release whose notes are missing.
    result, _ = publish(tmp_path, "v1.1.0", plan=True, notes="")
    assert result.returncode == 1
    assert "The changelog section for 1.2.0 is empty." in result.stderr
    assert "release=" not in result.stdout


@pytest.mark.parametrize("prerelease", [False, True])
def test_publish_asset(tmp_path: Path, prerelease: bool) -> None:
    result, calls = publish(tmp_path, "v1.1.0", asset=True, prerelease=prerelease)
    assert result.returncode == 0, result.stderr
    assert created(calls) == []
    draft, upload, publish_call = writes(calls)
    tag = "v1.2.0b1" if prerelease else "v1.2.0"
    assert draft[:3] == ["api", "--method", "POST"]
    assert draft[3] == "repos/owner/repo/releases"
    assert f"tag_name={tag}" in draft
    assert f"target_commitish={'a' * 40}" in draft
    assert "draft=true" in draft
    assert f"prerelease={'true' if prerelease else 'false'}" in draft
    assert upload[3] == "https://uploads.example/repos/owner/repo/releases/7/assets?name=demo.zip"
    assert upload[upload.index("--input") + 1] == str(tmp_path / "dist" / "demo.zip")
    assert publish_call[:4] == ["api", "--method", "PATCH", "repos/owner/repo/releases/7"]
    assert "draft=false" in publish_call
    assert f"make_latest={'false' if prerelease else 'true'}" in publish_call
    assert f"::notice::Published {tag} with demo.zip." in result.stdout


@pytest.mark.parametrize("step", ["upload", "publish"])
def test_publish_asset_failure_deletes_the_draft(tmp_path: Path, step: str) -> None:
    result, calls = publish(tmp_path, "v1.1.0", asset=True, fail=step)
    assert result.returncode == 1
    assert writes(calls)[-1] == [
        "api",
        "--method",
        "DELETE",
        "repos/owner/repo/releases/7",
        "--silent",
    ]


def test_publish_asset_race(tmp_path: Path) -> None:
    # Another run published the version first: only the draft is deleted.
    result, calls = publish(tmp_path, "v1.1.0", asset=True, fail="publish", race=True)
    assert result.returncode == 0
    assert "Tag v1.2.0 was created by another run" in result.stdout
    assert writes(calls)[-1][2:4] == ["DELETE", "repos/owner/repo/releases/7"]


def test_publish_asset_draft_fails(tmp_path: Path) -> None:
    result, calls = publish(tmp_path, "v1.1.0", asset=True, fail="draft")
    assert result.returncode == 1
    assert len(writes(calls)) == 1


def test_publish_delete_failure_is_a_warning(tmp_path: Path) -> None:
    result, _ = publish(tmp_path, "v1.1.0", asset=True, fail="upload delete")
    assert result.returncode == 1
    assert "::warning::Could not delete the draft release 7." in result.stdout


def test_publish_missing_asset(tmp_path: Path) -> None:
    (tmp_path / "dist").mkdir()
    result, calls = publish(tmp_path, "v1.1.0", asset=True)
    assert result.returncode == 1
    assert "demo.zip does not exist." in result.stdout
    assert writes(calls) == []


def test_check_asset(tmp_path: Path) -> None:
    folder = tmp_path / "custom_components" / "demo"
    assert release.check_asset(tmp_path, "custom_components/demo", "demo.zip") == folder
    for path, name, message in [
        ("dist", "demo.tar.gz", "must be a plain file name"),
        ("dist", "sub/demo.zip", "must be a plain file name"),
        ("dist", ".zip", "must be a plain file name"),
        ("../dist", "demo.zip", "must be a folder inside the repository"),
        (str(tmp_path / "dist"), "demo.zip", "must be a folder inside the repository"),
        (".", "demo.zip", "must not be the root"),
    ]:
        with pytest.raises(release.ReleaseError, match=message):
            release.check_asset(tmp_path, path, name)


def test_check_asset_matches_hacs(tmp_path: Path) -> None:
    hacs = tmp_path / "hacs.json"
    write(hacs, json.dumps({"name": "Demo", "filename": "other.zip"}))
    release.check_asset(tmp_path, "dist", "demo.zip")
    write(hacs, json.dumps({"name": "Demo", "zip_release": True, "filename": "demo.zip"}))
    release.check_asset(tmp_path, "dist", "demo.zip")
    for data in ({"zip_release": True, "filename": "other.zip"}, {"zip_release": True}):
        write(hacs, json.dumps(data))
        with pytest.raises(release.ReleaseError, match=r"hacs\.json installs from"):
            release.check_asset(tmp_path, "dist", "demo.zip")
    write(hacs, "[]")
    release.check_asset(tmp_path, "dist", "demo.zip")


def test_make_zip(tmp_path: Path) -> None:
    folder = tmp_path / "dist"
    write(folder / "manifest.json", "{}")
    write(folder / "frontend" / "app.js", "export {};\n")
    tool = write(folder / "tool.sh", "#!/bin/sh\n")
    tool.chmod(0o755)
    (folder / "empty").mkdir()
    first = tmp_path / "out" / "demo.zip"
    assert release.make_zip(folder, first) == 3
    with zipfile.ZipFile(first) as archive:
        assert archive.namelist() == ["frontend/app.js", "manifest.json", "tool.sh"]
        assert archive.read("frontend/app.js") == b"export {};\n"
        modes = {info.filename: info.external_attr >> 16 for info in archive.infolist()}
        assert modes == {"frontend/app.js": 0o644, "manifest.json": 0o644, "tool.sh": 0o755}
    # The same files give the same zip, whatever their dates.
    os.utime(folder / "manifest.json", (0, 0))
    second = tmp_path / "again.zip"
    release.make_zip(folder, second)
    assert second.read_bytes() == first.read_bytes()


def test_make_zip_refuses(tmp_path: Path) -> None:
    folder = tmp_path / "dist"
    with pytest.raises(release.ReleaseError, match=r"does not exist\. Did the build run\?"):
        release.make_zip(folder, tmp_path / "demo.zip")
    folder.mkdir()
    (folder / "empty").mkdir()
    with pytest.raises(release.ReleaseError, match="is empty"):
        release.make_zip(folder, tmp_path / "demo.zip")
    write(tmp_path / "secret.txt", "outside")
    (folder / "link").symlink_to(tmp_path / "secret.txt")
    with pytest.raises(release.ReleaseError, match="holds a link: link"):
        release.make_zip(folder, tmp_path / "demo.zip")
    assert not (tmp_path / "demo.zip").exists()


def test_main_asset(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = ["--root", str(tmp_path)]
    asset = ["asset", "--path", "dist", "--name", "demo.zip"]
    # Checking the settings needs no folder yet: the build makes it.
    assert release.main([*root, *asset]) == 0
    assert capsys.readouterr().out == ""
    write(tmp_path / "dist" / "index.js", "export {};\n")
    output = tmp_path / "out"
    assert release.main([*root, *asset, "--output", str(output)]) == 0
    assert capsys.readouterr().out == "Zipped 1 file(s) of dist into demo.zip.\n"
    assert zipfile.is_zipfile(output / "demo.zip")
    assert release.main([*root, "asset", "--path", "dist", "--name", "demo"]) == 1
    assert "must be a plain file name" in capsys.readouterr().err
