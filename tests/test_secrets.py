"""Tests for the secret scan."""

from __future__ import annotations

import base64
import codecs
import gzip
import json
import os
import random
import shutil
import subprocess
import sys
import zlib
from pathlib import Path

import pytest

from ci_checks import secrets
from ci_checks._common import EMPTY_SHA, Reporter
from ci_checks.denylist import Denylist
from helpers import EventWriter, Repo, pr_event
from media import make_pdf, make_zip, pdf_stream

CONFIG = Path(__file__).resolve().parent.parent / "actions" / "privacy" / "gitleaks.toml"
INSTALL = CONFIG.parent.parent / "setup-tools" / "install.sh"
GITLEAKS = shutil.which("gitleaks")
# CI installs gitleaks, so these tests only skip on a machine without it.
needs_gitleaks = pytest.mark.skipif(
    GITLEAKS is None and not os.environ.get("CI"), reason="gitleaks is not installed"
)
# Tokens in the format of GitHub personal access tokens, split so that this
# file holds none.
TOKEN = "ghp_" + "Bluefinch0Example1Token2Value3Abcd45"
OTHER_TOKEN = "ghp_" + "Greyfinch9Sample8Token7Value6Wxyz543"
APP_TOKEN = "ghs_" + "Bluefinch0Example1App2Token3Value456"
# An npm canary version, which looks like a generic key next to a package
# name, and a random value; split too, since the shared CI scans this file.
CANARY = "14.0.0-canary" + ".53b3cad2f.0"
RANDOM_VALUE = "Zx81kQp0Lm2Vb7" + "Nc4Rt6Yw9Hs3Jd5"
Capture = pytest.CaptureFixture[str]
# A gitleaks stand-in that records how it was called and answers from
# FAKE_GITLEAKS: per command ("git" or "dir"), the log (by default, for
# "dir", the size of the scanned files), the report (null to write none,
# with {source} in a path standing for the scanned directory) and the exit
# code.
FAKE_GITLEAKS = """\
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
call = {"args": args, "cwd": os.getcwd(), "cwd_empty": not os.listdir(),
        "secrets": "CI_SECRETS" in os.environ}
with Path(os.environ["FAKE_GITLEAKS_CALLS"]).open("a") as calls:
    calls.write(json.dumps(call) + "\\n")
answer = json.loads(os.environ["FAKE_GITLEAKS"])[args[0]]
size = sum(path.stat().st_size for path in Path(args[1]).rglob("*") if path.is_file())
print(answer.get("log", f"10:00PM INF scanned ~{size} bytes"), file=sys.stderr)
report = answer.get("report", [])
if report is not None:
    report = [dict(item, File=item["File"].replace("{source}", args[1])) for item in report]
    Path(args[args.index("--report-path") + 1]).write_text(json.dumps(report))
sys.exit(answer.get("exit", 0))
"""
SCANNED = "10:00PM INF 2 commits scanned."


@pytest.fixture
def fake_gitleaks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    script = tmp_path / "gitleaks"
    script.write_text(f"#!{sys.executable}\n{FAKE_GITLEAKS}", encoding="utf-8")
    script.chmod(0o755)
    monkeypatch.setenv("FAKE_GITLEAKS_CALLS", str(tmp_path / "calls.jsonl"))
    monkeypatch.setenv("FAKE_GITLEAKS", json.dumps({"git": {"log": SCANNED}, "dir": {}}))
    return script


def fake_answers(monkeypatch: pytest.MonkeyPatch, git: dict, directory: dict | None = None) -> None:
    monkeypatch.setenv("FAKE_GITLEAKS", json.dumps({"git": git, "dir": directory or {}}))


def fake_calls(tmp_path: Path) -> list[dict]:
    lines = (tmp_path / "calls.jsonl").read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines]


def scan(repo: Repo, gitleaks: Path | str | None, *args: str) -> int:
    return secrets.main(
        [
            "--root",
            str(repo.root),
            "--config",
            str(CONFIG),
            "--gitleaks",
            str(gitleaks or GITLEAKS or "gitleaks"),
            *args,
        ]
    )


def output(capsys: Capture) -> str:
    captured = capsys.readouterr()
    return captured.out + captured.err


def secret_line(token: str = TOKEN) -> str:
    return f'token = "{token}"\n'


def test_fingerprint() -> None:
    sha = "a" * 40
    assert secrets.Finding("jwt", 3, sha, "a b/c:d.py").fingerprint == f"{sha}:a b/c:d.py:jwt:3"
    assert secrets.Finding("jwt", 2, sha).fingerprint == f"{sha}::jwt:2"
    assert secrets.Finding("jwt", 1, field="title").fingerprint == ""


def test_parse_ignore() -> None:
    sha = "0123456789abcdef0123456789abcdef01234567"
    text = (
        f"  {sha}:docs/a b:c.md:generic-api-key:12  \n"
        "\n"
        "# Example token in an old test fixture.\n"
        f"{sha}::jwt:1\n"
        f"{sha}:x.py:jwt\n"
        "*:*:jwt:1\n"
        f"{sha.upper()}:x.py:jwt:1\n"
    )
    fingerprints, malformed = secrets.parse_ignore(text)
    assert fingerprints == {f"{sha}:docs/a b:c.md:generic-api-key:12", f"{sha}::jwt:1"}
    assert malformed == [5, 6, 7]


def test_history_changes(repo: Repo) -> None:
    moved = "".join(f"line {number}\n" for number in range(10))
    repo.write("a.txt", "a\n")
    repo.write("gone.txt", "x\n")
    repo.write("old-name.txt", moved)
    repo.write("same-name.txt", moved)
    (repo.root / "link").symlink_to("a.txt")
    first = repo.commit()
    repo.git("checkout", "--quiet", "-b", "feature")
    repo.write("b.txt", "b\n")
    repo.git("rm", "--quiet", "gone.txt")
    repo.git("mv", "old-name.txt", "new-name.txt")
    repo.write("new-name.txt", moved + "edited\n")
    repo.git("mv", "same-name.txt", "renamed.txt")
    feature = repo.commit()
    repo.git("checkout", "--quiet", "main")
    repo.write("a.txt", "a\nmore\n")
    main = repo.commit()
    repo.git("merge", "--quiet", "--no-ff", "--no-commit", "feature")
    repo.write("added-by-merge.txt", "m\n")
    merge = repo.commit("Merge branch 'feature'")

    def blob(path: str, revision: str = "HEAD") -> str:
        return repo.git("rev-parse", f"{revision}:{path}").strip()

    empty, old_a = EMPTY_SHA, blob("a.txt", first)
    # The merge counts with what its first parent lacks. A renamed file
    # counts with what changed, so not at all when only its name did.
    # Deletions and symbolic links write no file content.
    assert sorted(secrets.history_changes(repo.root, merge)) == sorted(
        [
            (first, "a.txt", empty, old_a),
            (first, "gone.txt", empty, blob("gone.txt", first)),
            (first, "old-name.txt", empty, blob("old-name.txt", first)),
            (first, "same-name.txt", empty, blob("same-name.txt", first)),
            (feature, "b.txt", empty, blob("b.txt")),
            (feature, "new-name.txt", blob("old-name.txt", first), blob("new-name.txt")),
            (main, "a.txt", old_a, blob("a.txt")),
            (merge, "b.txt", empty, blob("b.txt")),
            (merge, "new-name.txt", blob("old-name.txt", first), blob("new-name.txt")),
            (merge, "added-by-merge.txt", empty, blob("added-by-merge.txt")),
        ]
    )


def test_unreadable_files(repo: Repo, monkeypatch: pytest.MonkeyPatch) -> None:
    repo.write("utf16.ps1", ("token\r\nline\r\n").encode("utf-16"))
    repo.write("utf32.txt", codecs.BOM_UTF32_LE + "wide\n".encode("utf-32-le"))
    repo.write("plain.txt", "token\n")
    repo.write("same.txt", "trailing\n")
    repo.write("end\\", "trailing\n")
    repo.write("binary.bin\\", b"\0\1\2token")
    repo.write("big.ps1", ("x" * 50).encode("utf-16"))
    repo.write("converted.ps1", "one\ntwo\n")
    repo.write("was-binary.ps1", b"\0one\n")
    repo.write("shortened.ps1", "one\ntwo\n".encode("utf-16"))
    first = repo.commit()
    repo.write("utf16.ps1", ("token\r\nline two\r\n").encode("utf-16"))
    repo.write("converted.ps1", "one\ntwo\nthree\n".encode("utf-16"))
    repo.write("was-binary.ps1", "one\n".encode("utf-16"))
    repo.write("shortened.ps1", "one\n".encode("utf-16"))
    repo.write("end\\", "trailing\nmore\n")
    repo.git("mv", "utf32.txt", "renamed.txt")
    second = repo.commit()
    monkeypatch.setattr(secrets, "MAX_SCAN_BYTES", 80)

    # Like a diff, a later version only holds the lines it adds, at their
    # line numbers, and a renamed or shortened file nothing.
    assert sorted(secrets.unreadable_files(repo.root, second)) == sorted(
        [
            (first, "end\\", "trailing\n"),
            (first, "shortened.ps1", "one\ntwo\n"),
            (first, "utf16.ps1", "token\r\nline\r\n"),
            (first, "utf32.txt", "wide\n"),
            (second, "converted.ps1", "\n\nthree\n"),
            (second, "end\\", "\nmore\n"),
            (second, "utf16.ps1", "\nline two\r\n"),
            (second, "was-binary.ps1", "one\n"),
        ]
    )


def test_unreadable_files_read_archives_and_wide_text_without_a_bom(repo: Repo) -> None:
    png = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR"
    repo.write("bundle.zip", make_zip(("a/config.py", b"token\n"), ("logo.png", png)))
    repo.write("notes.gz", gzip.compress(b"one\n"))
    repo.write("nested.zip", make_zip(("inner.zip", make_zip(("deep.txt", b"deep\n")))))
    repo.write("export.ps1", "token\r\n".encode("utf-16-le"))
    repo.write("doc.pdf", make_pdf(pdf_stream(zlib.compress(b"BT (token) Tj ET"))))
    first = repo.commit()
    repo.write("bundle.zip", make_zip(("a/config.py", b"token\nmore\n")))
    second = repo.commit()
    assert sorted(secrets.unreadable_files(repo.root, second)) == sorted(
        [
            (first, "bundle.zip", "token\n"),
            (first, "doc.pdf", "BT (token) Tj ET"),
            (first, "export.ps1", "token\r\n"),
            (first, "nested.zip", "deep\n"),
            (first, "notes.gz", "one\n"),
            (second, "bundle.zip", "\nmore\n"),
        ]
    )


def test_without_allow_marker() -> None:
    assert secrets._without_allow_marker("a gitleaks:gitleaks:allowallow b") == "a  b"
    assert secrets._without_allow_marker("Gitleaks:Allow") == "Gitleaks:Allow"


def test_report(capsys: Capture) -> None:
    sha = "1" * 40
    old = "2" * 40
    findings = [
        secrets.Finding("github-pat", 3, sha, "docs/quillmore/a.txt"),
        secrets.Finding("github-pat", 4, sha, "src/a.py"),
        secrets.Finding("jwt", 2, sha),
        secrets.Finding("github-pat", 1, field="body"),
        secrets.Finding("generic-api-key", 7, old, "quillmore.json"),
        secrets.Finding("jwt", 9, sha, "tests/fixture.json"),
    ]
    ignore = {
        f"{old}:quillmore.json:generic-api-key:7",
        f"{sha}:tests/fixture.json:jwt:9",
        f"{old}:quillmore/stale.json:jwt:1",
    }
    reporter = Reporter("Secrets")
    secrets.report(findings, ignore, lambda commit: commit == old, Denylist("Quillmore"), reporter)
    out = capsys.readouterr().out
    assert reporter.count == 5
    assert "quillmore" not in out.lower()
    assert out.splitlines() == [
        "::error::Commit 111111111111: docs/[redacted]/a.txt:3: possible secret (github-pat). "
        f"Revoke it and tell a maintainer. Fingerprint: {sha}:docs/[redacted]/a.txt:github-pat:3",
        "::error file=src/a.py,line=4::Commit 111111111111: src/a.py:4: possible secret "
        f"(github-pat). Revoke it and tell a maintainer. Fingerprint: {sha}:src/a.py:github-pat:4",
        "::error::Commit 111111111111: message line 2: possible secret (jwt). Revoke it and tell "
        f"a maintainer. Fingerprint: {sha}::jwt:2",
        "::error::Pull request body, line 1: possible secret (github-pat). Edit it out, then "
        "revoke it and tell a maintainer.",
        "::warning::Known false positive ignored by secrets-ignore: "
        f"{old}:[redacted]:generic-api-key:7",
        "::error file=tests/fixture.json,line=9::Commit 111111111111: tests/fixture.json:9: "
        "possible secret (jwt). Revoke it and tell a maintainer. secrets-ignore only applies to "
        f"commits already on the base branch. Fingerprint: {sha}:tests/fixture.json:jwt:9",
        f"::warning::secrets-ignore lists {old}:[redacted]/stale.json:jwt:1, which matches no "
        "finding.",
    ]


def test_main_passes_its_own_options(
    repo: Repo, fake_gitleaks: Path, event: EventWriter, tmp_path: Path, capsys: Capture
) -> None:
    repo.write("README.md", "# Demo\n")
    repo.commit()
    event({})
    assert scan(repo, fake_gitleaks) == 0
    assert output(capsys).endswith("Secrets: no problem found.\n")
    history, texts = fake_calls(tmp_path)
    assert history["args"][:3] == [
        "git",
        "--log-opts=--text --no-textconv --no-ext-diff --diff-merges=first-parent HEAD",
        str(repo.root / ".git"),
    ]
    assert texts["args"][0] == "dir"
    for call in (history, texts):
        args = call["args"]
        # Outside the repository, with this configuration and no ignore file.
        assert args[args.index("--config") + 1] == str(CONFIG)
        assert args[args.index("--gitleaks-ignore-path") + 1] == call["cwd"]
        assert call["cwd_empty"]
        assert "--redact" in args
        assert not call["secrets"]


def test_main_reads_every_denylist_secret_and_keeps_them_from_gitleaks(
    repo: Repo,
    fake_gitleaks: Path,
    monkeypatch: pytest.MonkeyPatch,
    event: EventWriter,
    tmp_path: Path,
    capsys: Capture,
) -> None:
    repo.write("quillmore/settings.json", "{}\n")
    sha = repo.commit()
    event({})
    finding = {"RuleID": "jwt", "StartLine": 1, "Commit": sha, "File": "quillmore/settings.json"}
    fake_answers(monkeypatch, {"log": SCANNED, "report": [finding]})
    names = {"PRIVACY_DENYLIST_1": "Quillmore", "OTHER_TOKEN": "unrelated"}
    monkeypatch.setenv("CI_SECRETS", json.dumps(names))
    assert scan(repo, fake_gitleaks) == 1
    out = output(capsys)
    assert "quillmore" not in out.lower()
    assert "[redacted]/settings.json" in out
    assert not any(call["secrets"] for call in fake_calls(tmp_path))


def test_main_rejects_malformed_secrets(
    repo: Repo,
    fake_gitleaks: Path,
    monkeypatch: pytest.MonkeyPatch,
    event: EventWriter,
    capsys: Capture,
) -> None:
    repo.write("README.md", "# Demo\n")
    repo.commit()
    event({})
    monkeypatch.setenv("CI_SECRETS", "[not an object]")
    assert scan(repo, fake_gitleaks) == 1
    out = output(capsys)
    assert "::error::CI_SECRETS does not hold valid JSON." in out
    assert "not an object" not in out


@pytest.mark.parametrize(
    ("answer", "expected"),
    [
        (
            {"log": "10:00PM ERR [git] fatal: bad object\n10:00PM INF 0 commits scanned."},
            "gitleaks failed (exit code 0).%0A10:00PM ERR [git] fatal: bad object",
        ),
        ({"log": SCANNED, "exit": 2}, "gitleaks failed (exit code 2)."),
        ({"log": SCANNED, "report": None}, "gitleaks failed (exit code 0)."),
        ({"log": "10:00PM INF 0 commits scanned."}, "gitleaks scanned no commit"),
        ({"log": "10:00PM INF no leaks found"}, "gitleaks scanned no commit"),
    ],
)
def test_main_fails_closed(
    repo: Repo,
    fake_gitleaks: Path,
    monkeypatch: pytest.MonkeyPatch,
    event: EventWriter,
    capsys: Capture,
    answer: dict,
    expected: str,
) -> None:
    repo.write("README.md", "# Demo\n")
    repo.commit()
    event({})
    fake_answers(monkeypatch, answer)
    assert scan(repo, fake_gitleaks) == 1
    out = output(capsys)
    assert f"::error::{expected}" in out
    assert "no problem found" not in out


@pytest.mark.parametrize(
    "log", ["10:00PM INF scanned ~10 bytes (10 bytes) in 1ms", "10:00PM INF no leaks found"]
)
def test_main_fails_when_gitleaks_skips_texts(
    repo: Repo,
    fake_gitleaks: Path,
    monkeypatch: pytest.MonkeyPatch,
    event: EventWriter,
    capsys: Capture,
    log: str,
) -> None:
    repo.write("README.md", "# Demo\n")
    repo.commit("docs: add a readme")
    event({})
    fake_answers(monkeypatch, {"log": SCANNED}, {"log": log})
    assert scan(repo, fake_gitleaks) == 1
    out = output(capsys)
    assert "::error::gitleaks skipped some of the commit messages" in out
    assert "no problem found" not in out


def test_gitleaks_errors_hide_denylisted_terms(
    fake_gitleaks: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake_answers(monkeypatch, {}, {"log": "10:00PM ERR cannot read quillmore/a\n10:00PM ERR x"})
    work = tmp_path / "work"
    work.mkdir()
    gitleaks = secrets.Gitleaks(str(fake_gitleaks), CONFIG, work, Denylist("Quillmore"))
    with pytest.raises(secrets.CheckError) as error:
        gitleaks.run("dir", str(tmp_path))
    assert str(error.value).splitlines() == [
        "gitleaks failed (exit code 0).",
        "[a line with a denylisted term]",
        "10:00PM ERR x",
    ]


def test_main_rejects_malformed_ignore_entries(
    repo: Repo, fake_gitleaks: Path, event: EventWriter, capsys: Capture
) -> None:
    repo.write("README.md", "# Demo\n")
    repo.commit()
    event({})
    assert scan(repo, fake_gitleaks, "--ignore", "# Known false positives\nsettings.env\n") == 1
    out = output(capsys)
    assert "::error::secrets-ignore line 2 is not a commit:path:rule:line fingerprint." in out
    assert "Secrets: 1 problem(s) found." in out


def test_main_ignores_only_commits_on_the_base_branch(
    repo: Repo,
    fake_gitleaks: Path,
    monkeypatch: pytest.MonkeyPatch,
    event: EventWriter,
    capsys: Capture,
) -> None:
    repo.write("fixture.json", "{}\n")
    old = repo.commit()
    base = repo.commit()
    head = repo.commit()
    report = [
        {"RuleID": "jwt", "StartLine": 1, "Commit": sha, "File": "fixture.json"}
        for sha in (old, head)
    ]
    fake_answers(monkeypatch, {"log": SCANNED, "report": report})
    ignore = f"{old}:fixture.json:jwt:1\n{head}:fixture.json:jwt:1\n"

    event(pr_event(base, head))
    assert scan(repo, fake_gitleaks, "--ignore", ignore) == 1
    out = output(capsys)
    assert f"::warning::Known false positive ignored by secrets-ignore: {old}:" in out
    assert f"::error file=fixture.json,line=1::Commit {head[:12]}:" in out
    assert "Secrets: 1 problem(s) found." in out

    event({})
    assert scan(repo, fake_gitleaks, "--ignore", ignore) == 0


def test_main_fails_without_gitleaks(
    repo: Repo, event: EventWriter, tmp_path: Path, capsys: Capture
) -> None:
    repo.write("README.md", "# Demo\n")
    repo.commit()
    event({})
    assert scan(repo, tmp_path / "missing") == 1
    assert "::error::gitleaks could not run" in output(capsys)


def test_main_fails_when_the_tip_is_missing(
    repo: Repo, fake_gitleaks: Path, event: EventWriter, tmp_path: Path, capsys: Capture
) -> None:
    repo.write("README.md", "# Demo\n")
    base = repo.commit()
    event(pr_event(base, "0123456789abcdef0123456789abcdef01234567"))
    assert scan(repo, fake_gitleaks) == 1
    assert "0123456789abcdef0123456789abcdef01234567, is not in the checkout" in output(capsys)
    assert not (tmp_path / "calls.jsonl").exists()


def test_main_rejects_shallow_clones(
    repo: Repo, fake_gitleaks: Path, event: EventWriter, tmp_path: Path, capsys: Capture
) -> None:
    repo.write("README.md", "# Demo\n")
    repo.commit()
    repo.commit()
    clone = tmp_path / "shallow"
    repo.git("clone", "--quiet", "--depth=1", f"file://{repo.root}", str(clone))
    event({})
    argv = ["--root", str(clone), "--config", str(CONFIG), "--gitleaks", str(fake_gitleaks)]
    assert secrets.main(argv) == 1
    assert "fetch-depth: 0" in output(capsys)
    assert not (tmp_path / "calls.jsonl").exists()


def test_main_maps_text_findings(
    repo: Repo,
    fake_gitleaks: Path,
    monkeypatch: pytest.MonkeyPatch,
    event: EventWriter,
    tmp_path: Path,
    capsys: Capture,
) -> None:
    repo.write("README.md", "# Demo\n")
    base = repo.commit()
    repo.write("notes.ps1", "note\n".encode("utf-16"))
    head = repo.commit("feat: add notes")
    event(pr_event(base, head, title="feat: add notes", body="Body"))
    fake_answers(
        monkeypatch,
        {"log": SCANNED},
        {
            # Each text starts with a line feed, which gitleaks counts.
            "report": [
                {"RuleID": "jwt", "StartLine": 3, "File": f"{{source}}/messages/{head}"},
                {"RuleID": "jwt", "StartLine": 2, "File": "{source}/pull-request/title"},
                {"RuleID": "jwt", "StartLine": 4, "File": "{source}/files/0"},
            ]
        },
    )
    assert scan(repo, fake_gitleaks) == 1
    out = output(capsys)
    assert f"Commit {head[:12]}: message line 2: possible secret (jwt)." in out
    assert "Pull request title, line 1: possible secret (jwt)." in out
    assert f"::error file=notes.ps1,line=3::Commit {head[:12]}: notes.ps1:3:" in out
    assert "Secrets: 3 problem(s) found." in out


@needs_gitleaks
def test_gitleaks_finds_what_a_merge_adds(repo: Repo, event: EventWriter, capsys: Capture) -> None:
    repo.write("README.md", "# Demo\n")
    repo.commit()
    repo.git("checkout", "--quiet", "-b", "feature")
    repo.write("a.txt", "a\n")
    repo.commit()
    repo.git("checkout", "--quiet", "main")
    repo.write("b.txt", "b\n")
    repo.commit()
    repo.git("checkout", "--quiet", "feature")
    repo.git("merge", "--quiet", "--no-commit", "main")
    repo.write("settings.env", secret_line())
    merge = repo.commit("Merge branch 'main' into feature")
    event({})
    assert scan(repo, None) == 1
    out = output(capsys)
    assert out.count("possible secret") == 1
    assert f"Commit {merge[:12]}: settings.env:1: possible secret (github-pat)." in out


@needs_gitleaks
def test_gitleaks_finds_a_conflict_resolution(
    repo: Repo, event: EventWriter, capsys: Capture
) -> None:
    repo.write("conf.txt", "a\nb\nc\n")
    repo.commit()
    repo.git("checkout", "--quiet", "-b", "feature")
    repo.write("conf.txt", "a\nfeature\nc\n")
    repo.commit()
    repo.git("checkout", "--quiet", "main")
    repo.write("conf.txt", "a\nmain\nc\n")
    repo.commit()
    repo.git("checkout", "--quiet", "feature")
    with pytest.raises(subprocess.CalledProcessError):
        repo.git("merge", "--quiet", "main")
    repo.write("conf.txt", f"a\n{secret_line()}c\n")
    merge = repo.commit("Merge branch 'main' into feature")
    event({})
    assert scan(repo, None) == 1
    assert f"Commit {merge[:12]}: conf.txt:2: possible secret (github-pat)." in output(capsys)


# The paths of the global allowlist of the default gitleaks configuration.
ALLOWLISTED_PATHS = [
    "frontend/package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "Pipfile.lock",
    "custom_components/demo/icons/icon.svg",
    "node_modules/x/index.js",
    "venv/lib/settings.py",
    "demo-1.0.dist-info/notes.txt",
    "docs/gitleaks.toml.example",
    "go.sum",
]


@needs_gitleaks
def test_gitleaks_has_no_global_allowlist(repo: Repo, event: EventWriter, capsys: Capture) -> None:
    for path in ALLOWLISTED_PATHS:
        repo.write(path, secret_line())
    head = repo.commit()
    event({})
    assert scan(repo, None) == 1
    out = output(capsys)
    for path in ALLOWLISTED_PATHS:
        assert f"Commit {head[:12]}: {path}:1: possible secret (github-pat)." in out
    assert f"Secrets: {len(ALLOWLISTED_PATHS)} problem(s) found." in out


def realistic_integration(repo: Repo) -> None:
    """Write files like those of an integration with a frontend card."""
    rng = random.Random(7)

    def digest(size: int) -> str:
        return base64.b64encode(rng.randbytes(size)).decode()

    def hexdigest() -> str:
        return rng.randbytes(32).hex()

    packages = {
        f"node_modules/{name}": {
            "version": version,
            "resolved": f"https://registry.npmjs.org/{name}/-/{name.rsplit('/')[-1]}-{version}.tgz",
            "integrity": f"sha512-{digest(64)}",
            "dependencies": {"js-tokens": "^4.0.0", "auth-helpers": "~0.9.0"},
            "license": "MIT",
        }
        for name, version in [
            ("@bluefinch/card-tokens", "2.1.0"),
            ("js-tokens", "4.0.0"),
            ("keyboard-shortcuts", "1.3.2"),
            ("auth-helpers", "0.9.1"),
            ("secret-sauce-icons", "3.0.0"),
        ]
    }
    lock = {
        "name": "bluefinch-card",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": packages,
    }
    repo.write("frontend/package-lock.json", json.dumps(lock, indent=2) + "\n")
    poetry = "".join(
        f'[[package]]\nname = "{name}"\nversion = "{version}"\noptional = false\n'
        f'python-versions = ">=3.12"\nfiles = [\n'
        f'    {{file = "{name}-{version}-py3-none-any.whl", hash = "sha256:{hexdigest()}"}},\n'
        f'    {{file = "{name}-{version}.tar.gz", hash = "sha256:{hexdigest()}"}},\n'
        "]\n\n"
        for name, version in [("keyring", "25.6.0"), ("oauthlib", "3.2.2"), ("pyjwt", "2.10.1")]
    )
    repo.write("poetry.lock", f'{poetry}[metadata]\ncontent-hash = "{hexdigest()}"\n')
    repo.write(
        "custom_components/bluefinch/icons/icon.svg",
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">'
        '<path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2z"/>'
        f'<image href="data:image/png;base64,{digest(300)}"/></svg>\n',
    )
    repo.write(
        "custom_components/bluefinch/diagnostics.py",
        "from homeassistant.const import CONF_ACCESS_TOKEN, CONF_API_KEY, CONF_PASSWORD\n"
        "TO_REDACT = {CONF_ACCESS_TOKEN, CONF_API_KEY, CONF_PASSWORD, 'refresh_token'}\n",
    )
    repo.write(
        "custom_components/bluefinch/translations/en.json",
        '{"config": {"error": {"invalid_auth": "Invalid authentication",'
        ' "token_expired": "The access token expired"},'
        ' "step": {"user": {"data": {"api_key": "API key", "password": "Password"}}}}}\n',
    )
    repo.write(
        "tests/test_config_flow.py",
        'MOCK_ENTRY = {"api_key": "test-api-key", "password": "test-password"}\n'
        'HEADERS = {"Authorization": "Bearer mock-access-token"}\n',
    )
    repo.write(
        ".github/workflows/release.yml",
        "jobs:\n  release:\n    steps:\n      - run: gh release list\n        env:\n"
        "          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n          API_KEY: $API_KEY\n",
    )


@needs_gitleaks
def test_gitleaks_accepts_a_realistic_integration(
    repo: Repo, event: EventWriter, capsys: Capture
) -> None:
    realistic_integration(repo)
    base = repo.commit("feat: add the integration")
    repo.write("README.md", "# Bluefinch\n\nSet `api_key: !secret bluefinch_api_key`.\n")
    head = repo.commit("docs: explain the API key\n\nThe token is stored in the config entry.")
    event(pr_event(base, head, title="docs: explain the API key", body="Set the token in the UI."))
    assert scan(repo, None) == 0
    assert output(capsys).endswith("Secrets: no problem found.\n")


@needs_gitleaks
def test_gitleaks_reads_messages_and_pull_request_text(
    repo: Repo, event: EventWriter, capsys: Capture
) -> None:
    repo.write("README.md", "# Demo\n")
    base = repo.commit()
    head = repo.commit(f"fix: use the token\n\nSet {secret_line()}")
    event(pr_event(base, head, title=f"fix: use {OTHER_TOKEN}", body=f"Line\r\n{secret_line()}"))
    assert scan(repo, None) == 1
    out = output(capsys)
    assert f"Commit {head[:12]}: message line 3: possible secret (github-pat)." in out
    assert "Pull request title, line 1: possible secret (github-pat)." in out
    assert "Pull request body, line 2: possible secret (github-pat)." in out
    assert TOKEN not in out
    assert OTHER_TOKEN not in out


@needs_gitleaks
def test_gitleaks_reads_files_git_calls_binary(
    repo: Repo, event: EventWriter, capsys: Capture
) -> None:
    repo.write(".gitattributes", "*.env binary\n")
    repo.write("settings.env", secret_line())
    repo.write("export.ps1", ("header\r\n" + secret_line()).encode("utf-16"))
    repo.write("nul.cfg", secret_line().encode() + b"\0\n")
    repo.write("end\\", secret_line())
    head = repo.commit()
    event({})
    assert scan(repo, None) == 1
    out = output(capsys)
    for where in ("settings.env:1", "export.ps1:2", "nul.cfg:1", "end\\:1"):
        assert f"Commit {head[:12]}: {where}: possible secret (github-pat)." in out


@needs_gitleaks
def test_gitleaks_reads_texts_it_skips_in_a_directory(
    repo: Repo, event: EventWriter, capsys: Capture
) -> None:
    # gitleaks skips a file whose name contains an archive extension (.br in
    # .bridge, .tar, .zip) or whose content starts like a binary format.
    repo.write("README.md", "# Demo\n")
    base = repo.commit()
    repo.write("lamp.bridge.ps1", ("header\r\n" + secret_line()).encode("utf-16"))
    repo.write("backup.tar.ps1", secret_line().encode("utf-16"))
    repo.write("dump.reg", ("%PDF-1.7\r\n" + secret_line()).encode("utf-16"))
    repo.write("notes.zip\\", secret_line())
    head = repo.commit(f"MZ notes\n\n{secret_line()}")
    event(pr_event(base, head, body=f"%PDF-1.7\n{secret_line()}"))
    assert scan(repo, None) == 1
    out = output(capsys)
    for where in (
        "lamp.bridge.ps1:2",
        "backup.tar.ps1:1",
        "dump.reg:2",
        "notes.zip\\:1",
        "message line 3",
    ):
        assert f"Commit {head[:12]}: {where}: possible secret (github-pat)." in out
    assert "Pull request body, line 2: possible secret (github-pat)." in out
    assert "Secrets: 6 problem(s) found." in out


@needs_gitleaks
def test_gitleaks_allow_cannot_hide_texts(repo: Repo, event: EventWriter, capsys: Capture) -> None:
    repo.write("README.md", "# Demo\n")
    base = repo.commit()
    marked = secret_line().replace("\n", " # gitleaks:allow\n")
    repo.write("export.ps1", marked.encode("utf-16"))
    head = repo.commit(f"fix: use the token\n\n{marked}")
    event(pr_event(base, head, body=f"Set {marked}"))
    assert scan(repo, None) == 1
    out = output(capsys)
    assert f"Commit {head[:12]}: export.ps1:1: possible secret (github-pat)." in out
    assert f"Commit {head[:12]}: message line 3: possible secret (github-pat)." in out
    assert "Pull request body, line 1: possible secret (github-pat)." in out
    assert "Secrets: 3 problem(s) found." in out


@needs_gitleaks
def test_gitleaks_reads_archives(repo: Repo, event: EventWriter, capsys: Capture) -> None:
    base = repo.commit()
    repo.write("dist/bundle.zip", make_zip(("config.py", ("header\n" + secret_line()).encode())))
    head = repo.commit()
    event(pr_event(base, head))
    assert scan(repo, None) == 1
    out = output(capsys)
    assert f"Commit {head[:12]}: dist/bundle.zip:2: possible secret (github-pat)." in out


@needs_gitleaks
def test_gitleaks_reports_wide_files_once(repo: Repo, event: EventWriter, capsys: Capture) -> None:
    repo.write("export.ps1", ("header\r\n" + secret_line()).encode("utf-16"))
    old = repo.commit()
    base = repo.commit()
    repo.write(
        "export.ps1", ("edited\r\n" + secret_line() + secret_line(OTHER_TOKEN)).encode("utf-16")
    )
    edit = repo.commit()
    (repo.root / "scripts").mkdir()
    repo.git("mv", "export.ps1", "scripts/export.ps1")
    head = repo.commit()
    known = f"{old}:export.ps1:github-pat:2"
    event(pr_event(base, head))
    # Neither the edit of another line nor the rename reports the known
    # false positive again; the line that the edit adds is reported.
    assert scan(repo, None, "--ignore", known) == 1
    out = output(capsys)
    assert f"::warning::Known false positive ignored by secrets-ignore: {known}" in out
    assert f"Commit {edit[:12]}: export.ps1:3: possible secret (github-pat)." in out
    assert "Secrets: 1 problem(s) found." in out


@needs_gitleaks
def test_gitleaks_accepts_versions_in_lock_files_only(
    repo: Repo, event: EventWriter, capsys: Capture
) -> None:
    version = f'"@bluefinch/tokens": "{CANARY}"'
    repo.write(
        "frontend/package-lock.json",
        f'{{\n  "dependencies": {{\n    {version},\n    "api-token": "{RANDOM_VALUE}"\n  }}\n}}\n',
    )
    repo.write(
        "pnpm-lock.yaml",
        "snapshots:\n  '@bluefinch/card@1.0.0':\n    dependencies:\n"
        f"      '@bluefinch/tokens': {CANARY}\n",
    )
    repo.write(
        "bun.lock", f'{{"packages": {{"@bluefinch/card": [{{"dependencies": {{{version}}}}}]}}}}\n'
    )
    repo.write("src/versions.json", f"{{{version}}}\n")
    head = repo.commit()
    event({})
    assert scan(repo, None) == 1
    out = output(capsys)
    for where in ("frontend/package-lock.json:4", "src/versions.json:1"):
        assert f"Commit {head[:12]}: {where}: possible secret (generic-api-key)." in out
    assert "Secrets: 2 problem(s) found." in out


@needs_gitleaks
def test_gitleaks_has_no_path_allowlist_for_github_tokens(
    repo: Repo, event: EventWriter, capsys: Capture
) -> None:
    # The default configuration skips GitHub tokens in this file, at any depth.
    path = "docs/@octokit/auth-token/README.md"
    repo.write(path, secret_line() + secret_line(APP_TOKEN))
    head = repo.commit()
    event({})
    assert scan(repo, None) == 1
    out = output(capsys)
    assert f"Commit {head[:12]}: {path}:1: possible secret (github-pat)." in out
    assert f"Commit {head[:12]}: {path}:2: possible secret (github-app-token)." in out


@needs_gitleaks
def test_repository_files_cannot_hide_a_secret(
    repo: Repo, event: EventWriter, capsys: Capture
) -> None:
    repo.write("settings.env", secret_line())
    leak = repo.commit()
    fingerprint = f"{leak}:settings.env:github-pat:1"
    repo.write(".gitleaksignore", fingerprint + "\n")
    repo.write(".gitleaks.toml", '[extend]\nuseDefault = true\n[allowlist]\npaths = [".*"]\n')
    repo.commit()
    event({})
    assert scan(repo, None) == 1
    assert f"Fingerprint: {fingerprint}" in output(capsys)


@needs_gitleaks
def test_gitleaks_fails_on_an_empty_history(
    repo: Repo, event: EventWriter, capsys: Capture
) -> None:
    repo.commit()
    event({})
    assert scan(repo, None) == 1
    assert "gitleaks scanned no commit" in output(capsys)


@needs_gitleaks
def test_secrets_ignore(repo: Repo, event: EventWriter, capsys: Capture) -> None:
    repo.write("tests/fixture.json", secret_line())
    old = repo.commit()
    repo.write("README.md", "# Demo\n")
    base = repo.commit()
    repo.write("new.json", secret_line(OTHER_TOKEN))
    head = repo.commit()
    known = f"{old}:tests/fixture.json:github-pat:1"
    added = f"{head}:new.json:github-pat:1"

    event(pr_event(base, head))
    assert scan(repo, None, "--ignore", f"{known}\n{added}\n") == 1
    out = output(capsys)
    assert f"::warning::Known false positive ignored by secrets-ignore: {known}" in out
    assert f"already on the base branch. Fingerprint: {added}" in out
    assert "Secrets: 1 problem(s) found." in out

    event({})
    assert scan(repo, None, "--ignore", f"{known}\n{added}\n") == 0


def pinned_gitleaks() -> str:
    script = INSTALL.read_text(encoding="utf-8")
    block = script[script.index("    gitleaks)") :]
    return block[block.index('version="') + 9 : block.index('"\n', block.index('version="'))]


def test_rules_come_from_the_installed_gitleaks_version() -> None:
    header = CONFIG.read_text(encoding="utf-8").split("\n\n", 1)[0]
    assert f"tag v{pinned_gitleaks()}, the version that actions/setup-tools/install.sh" in header


@needs_gitleaks
def test_local_gitleaks_is_the_pinned_version() -> None:
    assert GITLEAKS
    found = subprocess.run([GITLEAKS, "version"], capture_output=True, text=True, check=True)
    assert found.stdout.strip() == pinned_gitleaks()
