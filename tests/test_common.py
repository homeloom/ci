"""Tests for the shared helpers."""

from __future__ import annotations

from ci_checks import _common
from ci_checks._common import Reporter
from helpers import Repo, pr_event


def test_tracked_files_and_text(repo: Repo) -> None:
    repo.write("a.txt", "hello\nworld\n")
    repo.write("dir/b.bin", "\0binary")
    repo.commit()
    (repo.root / "untracked.txt").write_text("ignored", encoding="utf-8")

    assert _common.tracked_files(repo.root) == ["a.txt", "dir/b.bin"]
    lines = list(_common.iter_lines(repo.root, ["a.txt", "dir/b.bin", "missing.txt"]))
    assert lines == [("a.txt", 1, "hello"), ("a.txt", 2, "world")]


def test_read_text_skips_large_files_and_symlinks(repo: Repo) -> None:
    repo.write("big.txt", "x" * (_common.MAX_FILE_BYTES + 1))
    repo.write("small.txt", "ok")
    (repo.root / "link.txt").symlink_to(repo.root / "small.txt")

    assert _common.read_text(repo.root / "big.txt") is None
    assert _common.read_text(repo.root / "link.txt") is None
    assert _common.read_text(repo.root / "small.txt") == "ok"


def test_split_list_and_globs() -> None:
    assert _common.split_list(None) == []
    assert _common.split_list(" a, b\nc ") == ["a", "b", "c"]
    assert _common.matches_any("tests/data/x.py", ["tests/*"])
    assert not _common.matches_any("src/x.py", ["tests/*"])


def test_pragma() -> None:
    assert _common.allowed_by_pragma("x = 1  # ci-allow: email, url", "url")
    assert not _common.allowed_by_pragma("x = 1  # ci-allow: email", "url")
    assert not _common.allowed_by_pragma("x = 1", "url")


def test_event_helpers(event) -> None:
    assert _common.load_event() == {}

    payload = pr_event("base", "head", title="t", body="b", bot=True, fork=True)
    event(payload)
    loaded = _common.load_event()
    pr = _common.pull_request(loaded)
    assert pr is not None
    assert (pr.title, pr.body, pr.head_ref) == ("t", "b", "feature")
    assert pr.author_is_bot
    assert pr.from_fork
    assert _common.history_tip(loaded) == "head"
    assert _common.new_commit_range(loaded) == ["base..head"]

    assert _common.pull_request({}) is None
    assert _common.history_tip({}) == "HEAD"
    assert _common.new_commit_range({"before": "a", "after": "b"}) == ["a..b"]
    assert _common.new_commit_range({"before": _common.EMPTY_SHA, "after": "b"}) == ["-1", "HEAD"]


def test_commits(repo: Repo) -> None:
    repo.commit("feat: first\n\nBody line.", name="Alice", email="alice@example.com")
    commits = _common.commits(repo.root, ["HEAD"])
    assert len(commits) == 1
    commit = commits[0]
    assert commit.author_name == "Alice"
    assert commit.author_email == "alice@example.com"
    assert commit.message.startswith("feat: first")
    assert "Body line." in commit.message
    assert len(commit.short) == 12


def test_reporter(capsys) -> None:
    reporter = Reporter("Demo")
    reporter.notice("note")
    reporter.warning("careful")
    reporter.error("bad\nthing 100%", "dir/a,b:c.txt", 3)
    reporter.error("no location")
    assert reporter.finish() == 1
    out = capsys.readouterr().out
    assert "::notice::note" in out
    assert "::warning::careful" in out
    assert "::error file=dir/a%2Cb%3Ac.txt,line=3::bad%0Athing 100%25" in out
    assert "::error::no location" in out
    assert "Demo: 2 problem(s) found." in out

    assert Reporter("Clean").finish() == 0
