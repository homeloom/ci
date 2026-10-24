"""Tests for the shared helpers."""

from __future__ import annotations

import codecs
from pathlib import Path

import pytest

from ci_checks import _common
from ci_checks._common import Reporter
from helpers import DEPENDABOT, EventWriter, Repo, pr_event


def test_tracked_files_and_text(repo: Repo) -> None:
    repo.write("a.txt", "hello\r\nworld\x0cpage\n")
    repo.write("dir/b.bin", "\0binary")
    repo.commit()
    (repo.root / "untracked.txt").write_text("ignored", encoding="utf-8")

    assert _common.tracked_files(repo.root) == ["a.txt", "dir/b.bin"]
    lines = list(_common.iter_lines(repo.root, ["a.txt", "dir/b.bin", "missing.txt"]))
    assert lines == [("a.txt", 1, "hello"), ("a.txt", 2, "world\x0cpage")]


def test_read_helpers_skip_large_files_and_symlinks(repo: Repo) -> None:
    repo.write("big.txt", "x" * (_common.MAX_TEXT_BYTES + 1))
    repo.write("small.txt", "ok")
    (repo.root / "link.txt").symlink_to(repo.root / "small.txt")

    assert _common.read_text(repo.root / "big.txt") is None
    assert _common.read_bytes(repo.root / "big.txt", _common.MAX_SCAN_BYTES) is not None
    assert _common.read_text(repo.root / "link.txt") is None
    assert _common.read_bytes(repo.root / "missing.txt", 10) is None
    assert _common.read_text(repo.root / "small.txt") == "ok"


def test_decode_text() -> None:
    assert _common.decode_text(b"caf\xc3\xa9") == "café"
    assert _common.decode_text(b"\0\x01") is None
    assert _common.decode_text(codecs.BOM_UTF16_LE + "hé\n".encode("utf-16-le")) == "hé\n"
    assert _common.decode_text(codecs.BOM_UTF16_BE + "hé".encode("utf-16-be")) == "hé"
    assert _common.decode_text(codecs.BOM_UTF32_LE + "hé".encode("utf-32-le")) == "hé"


def test_split_lines() -> None:
    assert _common.split_lines("a\r\nb\n\nc") == ["a", "b", "", "c"]
    assert _common.split_lines("a\n") == ["a"]
    assert _common.split_lines("") == []


def test_split_list_and_globs() -> None:
    assert _common.split_list(None) == []
    assert _common.split_list(" a, b\nc ") == ["a", "b", "c"]
    assert _common.matches_any("tests/data/x.py", ["tests/*"])
    assert not _common.matches_any("src/x.py", ["tests/*"])


def test_pragma() -> None:
    assert _common.allowed_by_pragma("x = 1  # ci-allow: email, url", "url")
    assert not _common.allowed_by_pragma("x = 1  # ci-allow: email", "url")
    assert not _common.allowed_by_pragma("x = 1", "url")


def test_event_helpers(event: EventWriter) -> None:
    assert _common.load_event() == {}

    payload = pr_event("base", "head", title="t", body="b", login="dependabot[bot]", fork=True)
    event(payload)
    loaded = _common.load_event()
    pr = _common.pull_request(loaded)
    assert pr is not None
    assert (pr.title, pr.body, pr.head_ref) == ("t", "b", "feature")
    assert pr.is_dependency_bot
    assert pr.from_fork
    assert _common.history_tip(loaded) == "head"
    assert _common.new_commit_range(loaded) == ["base..head"]

    assert not _common.pull_request(pr_event("a", "b", login="claude[bot]")).is_dependency_bot
    assert _common.pull_request({}) is None
    assert _common.history_tip({}) == "HEAD"
    assert _common.new_commit_range({"before": "a", "after": "b"}) == ["a..b"]
    assert _common.new_commit_range({"before": _common.EMPTY_SHA, "after": "b"}) == ["b"]
    assert _common.new_commit_range({}) == ["HEAD"]


def test_new_commit_range_after_force_push(repo: Repo) -> None:
    head = repo.commit()
    push = {"before": "1" * 40, "after": head}
    assert _common.new_commit_range(push, repo.root) == [head]
    first = repo.commit()
    second = repo.commit()
    assert _common.new_commit_range({"before": first, "after": second}, repo.root) == [
        f"{first}..{second}"
    ]


def test_require_full_history(repo: Repo, tmp_path: Path) -> None:
    repo.commit()
    repo.commit()
    _common.require_full_history(repo.root)
    clone = tmp_path / "shallow"
    repo.git("clone", "--quiet", "--depth=1", f"file://{repo.root}", str(clone))
    with pytest.raises(_common.CheckError, match="fetch-depth: 0"):
        _common.require_full_history(clone)


def test_commits(repo: Repo) -> None:
    repo.commit(
        "feat: first\n\nBody line.\x1e with a separator", name="Alice", email="a@example.com"
    )
    repo.commit("chore(deps): bump x", name="dependabot[bot]", email=DEPENDABOT)
    repo.commit("chore: spoofed", name="x", email="1+renovate[bot]@users.noreply.github.com")
    commits = _common.commits(repo.root, ["HEAD"])
    assert [c.is_dependency_bot for c in commits] == [False, True, False]
    commit = commits[2]
    assert commit.author_name == "Alice"
    assert commit.author_email == "a@example.com"
    assert commit.message == "feat: first\n\nBody line.\x1e with a separator"
    assert len(commit.short) == 12
    assert _common.commits(repo.root, ["HEAD..HEAD"]) == []


def test_dependency_bot_commits(repo: Repo) -> None:
    human = repo.commit()
    bot = repo.commit("chore(deps): bump x", name="dependabot[bot]", email=DEPENDABOT)
    new = _common.commits(repo.root, ["HEAD"])
    assert _common.dependency_bot_commits({}, new) == {bot}
    in_bot_pr = pr_event(human, bot, login="dependabot[bot]")
    assert _common.dependency_bot_commits(in_bot_pr, new) == {bot}
    assert _common.dependency_bot_commits(pr_event(human, bot), new) == set()


def test_changes(repo: Repo) -> None:
    base = repo.commit()
    repo.write("a.txt", "one\ntwo\n")
    repo.write("b.bin", b"\0\0")
    first = repo.commit()
    repo.write("a.txt", "one\n++ plus\nthree\n")
    repo.write("odd name é.txt", "x\n")
    repo.write("tab\there.txt", "y\n")
    repo.write("empty.txt", "")
    second = repo.commit()
    repo.git("rm", "--quiet", "odd name é.txt")
    third = repo.commit()

    found = {(c.sha, c.path): c for c in _common.changes(repo.root, [f"{base}..HEAD"])}
    assert set(found) == {
        (third, "odd name é.txt"),
        (second, "a.txt"),
        (second, "odd name é.txt"),
        (second, "tab\there.txt"),
        (second, "empty.txt"),
        (first, "a.txt"),
        (first, "b.bin"),
    }
    assert found[(second, "a.txt")].added == ((2, "++ plus"), (3, "three"))
    assert found[(first, "a.txt")].added == ((1, "one"), (2, "two"))
    assert found[(second, "tab\there.txt")].added == ((1, "y"),)
    assert found[(third, "odd name é.txt")].blob == ""
    assert found[(second, "empty.txt")].added == ()
    assert found[(second, "empty.txt")].blob
    contents = _common.blob_contents(repo.root, [found[(first, "b.bin")].blob, "f" * 40], 10)
    assert contents == {found[(first, "b.bin")].blob: b"\0\0", "f" * 40: None}
    assert _common.blob_contents(repo.root, [found[(second, "a.txt")].blob], 1) == {
        found[(second, "a.txt")].blob: None
    }
    assert _common.blob_contents(repo.root, [], 10) == {}


def test_changes_ignore_attributes_and_textconv(repo: Repo) -> None:
    base = repo.commit()
    repo.write(".gitattributes", "*.snap -diff\n")
    repo.write("data.snap", "secret line\n")
    head = repo.commit()
    found = {c.path: c.added for c in _common.changes(repo.root, [f"{base}..{head}"])}
    assert found["data.snap"] == ((1, "secret line"),)


def test_changes_of_merges_keep_only_new_lines(repo: Repo) -> None:
    repo.write("a.txt", "base\n")
    base = repo.commit()
    repo.git("checkout", "--quiet", "-b", "side")
    repo.write("a.txt", "base\nside\n")
    repo.commit()
    repo.git("checkout", "--quiet", "main")
    repo.write("b.txt", "main\n")
    repo.commit()
    repo.git("merge", "--quiet", "--no-commit", "side")
    repo.write("b.txt", "main\nresolution\n")
    repo.git("add", "--all")
    merge = repo.commit("Merge side")
    found = [c for c in _common.changes(repo.root, [f"{base}..HEAD"]) if c.sha == merge]
    assert [(c.path, c.added) for c in found] == [("b.txt", ((2, "resolution"),))]


def test_unquote() -> None:
    assert (
        _common._unquote(r"tab\there \"q\" back\\slash \303\251") == 'tab\there "q" back\\slash é'
    )


def test_reporter(capsys: pytest.CaptureFixture[str]) -> None:
    reporter = Reporter("Demo")
    reporter.warning("careful")
    reporter.error("bad\nthing 100%", "dir/a,b:c.txt", 3)
    reporter.error("no location")
    assert reporter.finish() == 1
    out = capsys.readouterr().out
    assert "::warning::careful" in out
    assert "::error file=dir/a%2Cb%3Ac.txt,line=3::bad%0Athing 100%25" in out
    assert "::error::no location" in out
    assert "Demo: 2 problem(s) found." in out

    assert Reporter("Clean").finish() == 0


def test_fail(capsys: pytest.CaptureFixture[str]) -> None:
    assert _common.fail("broken") == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "::error::broken" in captured.err
