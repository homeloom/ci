"""Tests for the shared helpers."""

from __future__ import annotations

import codecs
import json
import os
import subprocess
from pathlib import Path

import pytest

from ci_checks import _common
from ci_checks._common import Reporter
from helpers import DEPENDABOT, EventWriter, Repo, merge_resolving_a_submodule, pr_event


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
    assert _common.decode_text(b"\xef\xbb\xbfhi") == "hi"
    # Bytes that are not UTF-8 are read as Windows-1252, as spreadsheets save them.
    assert _common.decode_text("Quillène;Zorbël\n".encode("cp1252")) == "Quillène;Zorbël\n"
    assert _common.decode_text(b"caf\xc3\xa9 and caf\xe9 \x81") == "café and café \x81"
    # UTF-16 without a byte order mark, as some Windows tools write it.
    assert _common.decode_text("host: é\r\n".encode("utf-16-le")) == "host: é\r\n"
    assert _common.decode_text("host: é\r\n".encode("utf-16-be")) == "host: é\r\n"
    assert _common.decode_text("\x01\x02\x03\x04\x05".encode("utf-16-le")) is None
    assert _common.decode_text(b"a\0") is None
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


def test_event_copy_with_current_text(
    event: EventWriter, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    event(pr_event("base", "head", title="old"))
    current = tmp_path / "current.json"
    current.write_text(json.dumps(pr_event("base", "head", title="new")), encoding="utf-8")
    monkeypatch.setenv("CI_EVENT_PATH", str(current))
    assert _common.pull_request(_common.load_event()).title == "new"
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


def test_replaced_head(repo: Repo) -> None:
    first = repo.commit()
    second = repo.commit()
    assert _common.replaced_head(pr_event(first, second, before=first), repo.root) is None
    # A rebase leaves the previous head out of the history of the new one.
    repo.git("reset", "--quiet", "--hard", first)
    rebased = repo.commit("fix: rebased")
    rewritten = pr_event(first, rebased, before=second)
    assert _common.replaced_head(rewritten, repo.root) == second
    # The checkout usually lacks the replaced commits altogether.
    missing = pr_event(first, rebased, before="e" * 40)
    assert _common.replaced_head(missing, repo.root) == "e" * 40
    opened = pr_event(first, rebased)
    assert _common.replaced_head(opened, repo.root) is None
    assert _common.replaced_head({**rewritten, "before": _common.EMPTY_SHA}, repo.root) is None
    assert _common.replaced_head({"before": second, "after": rebased}, repo.root) is None


def test_require_full_history(repo: Repo, tmp_path: Path) -> None:
    repo.commit()
    repo.commit()
    _common.require_full_history(repo.root)
    clone = tmp_path / "shallow"
    repo.git("clone", "--quiet", "--depth=1", f"file://{repo.root}", str(clone))
    with pytest.raises(_common.CheckError, match="fetch-depth: 0"):
        _common.require_full_history(clone)


@pytest.mark.parametrize("encoding", ["ISO-8859-1", "x-unknown"])
def test_commits_read_raw_objects(repo: Repo, encoding: str) -> None:
    base = repo.commit()
    tree = repo.git("write-tree").strip()
    raw = (
        f"tree {tree}\nparent {base}\n"
        "author Zorbl\xe9 <1+z@users.noreply.github.com> 1700000000 +0000\n"
        "committer Zorbl\xe9 <1+z@users.noreply.github.com> 1700000000 +0000\n"
        f"encoding {encoding}\n\nfix: ok\0hidden 10.0.0.2\n"
    ).encode("latin-1")
    sha = (
        subprocess.run(
            ["git", "hash-object", "-t", "commit", "-w", "--literally", "--stdin"],
            cwd=repo.root,
            input=raw,
            capture_output=True,
            check=True,
        )
        .stdout.decode()
        .strip()
    )
    [commit] = _common.commits(repo.root, [f"{base}..{sha}"])
    assert commit.author_name == "Zorbl\N{LATIN SMALL LETTER E WITH ACUTE}"
    assert commit.message == "fix: ok\0hidden 10.0.0.2"
    assert _common._identity(b"no address") == (b"no address", b"")


def test_commits(repo: Repo) -> None:
    repo.commit(
        "feat: first\n\nBody line.\x1e with a separator", name="Zorblequix", email="z@example.com"
    )
    repo.commit("chore(deps): bump x", name="dependabot[bot]", email=DEPENDABOT)
    repo.commit("chore: spoofed", name="x", email="1+renovate[bot]@users.noreply.github.com")
    commits = _common.commits(repo.root, ["HEAD"])
    assert [c.is_dependency_bot for c in commits] == [False, True, False]
    commit = commits[2]
    assert commit.author_name == "Zorblequix"
    assert commit.author_email == "z@example.com"
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


def changes_of(repo: Repo, base: str) -> dict[tuple[str, str], _common.Change]:
    return {(c.sha, c.path): c for c in _common.changes(repo.root, [f"{base}..HEAD"])}


def test_changes(repo: Repo) -> None:
    base = repo.commit()
    repo.write("a.txt", "one\ntwo\n")
    repo.write("b.bin", b"\0\0")
    first = repo.commit()
    repo.write("a.txt", "one\n++ plus\nthree\n")
    repo.write("odd name \N{LATIN SMALL LETTER E WITH ACUTE}.txt", "x\n")
    repo.write("tab\there.txt", "y\n")
    repo.write("empty.txt", "")
    second = repo.commit()
    repo.git("rm", "--quiet", "odd name \N{LATIN SMALL LETTER E WITH ACUTE}.txt")
    third = repo.commit()

    found = changes_of(repo, base)
    odd = "odd name \N{LATIN SMALL LETTER E WITH ACUTE}.txt"
    assert set(found) == {
        (third, odd),
        (second, "a.txt"),
        (second, odd),
        (second, "tab\there.txt"),
        (second, "empty.txt"),
        (first, "a.txt"),
        (first, "b.bin"),
    }
    assert found[(second, "a.txt")].added == {2, 3}
    assert found[(first, "a.txt")].added == {1, 2}
    assert found[(first, "a.txt")].mode == "100644"
    assert found[(second, "tab\there.txt")].added == {1}
    assert found[(third, odd)].blob == ""
    assert found[(second, "empty.txt")].added == set()
    assert found[(second, "empty.txt")].blob
    # Git does not diff binary content: every line of it counts as added.
    assert found[(first, "b.bin")].added is None
    binary = found[(first, "b.bin")].blob
    assert _common.blob_contents(repo.root, [binary, "f" * 40], 10) == {binary: b"\0\0"}
    assert _common.blob_contents(repo.root, [found[(second, "a.txt")].blob], 1) == {
        found[(second, "a.txt")].blob: None
    }
    assert _common.blob_contents(repo.root, [], 10) == {}


def test_changes_treat_files_git_will_not_diff_as_new(repo: Repo) -> None:
    base = repo.commit()
    repo.write(".gitattributes", "*.snap -diff\n")
    repo.write("data.snap", "secret line\n")
    repo.commit()
    found = {path: c.added for (_, path), c in changes_of(repo, base).items()}
    assert found["data.snap"] is None
    assert found[".gitattributes"] == {1}


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
    assert [(c.path, c.added, c.mode) for c in found] == [("b.txt", {2}, "100644")]


def test_changes_keep_carriage_returns_inside_lines(repo: Repo) -> None:
    base = repo.commit()
    # Classic Mac line endings, a progress bar, and a record separator after
    # a carriage return, which must not end the file early.
    repo.write("devices.csv", b"name,ip\rnas,10.0.0.2\r")
    repo.write("install.log", b"progress 10%\r\x1edone\nhost 10.0.0.2\nowner x\n")
    head = repo.commit()
    found = changes_of(repo, base)
    assert found[(head, "devices.csv")].added == {1}
    assert found[(head, "install.log")].added == {1, 2, 3}


def test_changes_and_tracked_files_keep_odd_file_names(repo: Repo) -> None:
    base = repo.commit()
    carriage = "notes\r.txt"
    latin = os.fsdecode(b"caf\xe9.txt")
    repo.write(carriage, "x\n")
    (repo.root / latin).write_bytes(b"y\n")
    head = repo.commit()
    assert _common.tracked_files(repo.root) == sorted([carriage, latin])
    assert {path for _, path in changes_of(repo, base)} == {carriage, latin}
    assert (repo.root / carriage).read_bytes() == b"x\n"
    assert _common.display_path(latin) == "caf\N{LATIN SMALL LETTER E WITH ACUTE}.txt"
    assert head


def test_changes_mark_submodules(repo: Repo, tmp_path: Path) -> None:
    other = Repo(tmp_path / "other")
    other.commit()
    base = repo.commit()
    repo.git(
        "-c", "protocol.file.allow=always", "submodule", "add", "--quiet", str(other.root), "sub"
    )
    head = repo.commit()
    found = changes_of(repo, base)
    assert found[(head, "sub")].mode == _common.GITLINK_MODE
    assert found[(head, ".gitmodules")].added == {1, 2, 3}


def test_changes_read_the_mode_of_merges_from_their_tree(repo: Repo) -> None:
    base, merge = merge_resolving_a_submodule(repo)
    repo.write("vendor/notes.txt", "kept\n")
    after = repo.commit()
    found = changes_of(repo, base)
    assert found[(merge, "vendor/lib")].mode == _common.GITLINK_MODE
    assert found[(after, "vendor/notes.txt")].mode == "100644"


def test_changes_report_git_errors(repo: Repo) -> None:
    repo.commit()
    with pytest.raises(subprocess.CalledProcessError):
        _common.changes(repo.root, ["no-such-revision"])


def test_unquote() -> None:
    assert (
        _common._unquote(rb"tab\there \"q\" back\\slash \303\251 \r")
        == b'tab\there "q" back\\slash \xc3\xa9 \r'
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


def test_reporter_prints_file_names_that_are_not_utf8(capsys: pytest.CaptureFixture[str]) -> None:
    reporter = Reporter("Demo")
    name = os.fsdecode(b"caf\xe9.txt")
    reporter.error(f"{name}: bad", name, 1)
    reporter.warning(name)
    assert "::error file=café.txt,line=1::café.txt: bad" in capsys.readouterr().out


def test_fail(capsys: pytest.CaptureFixture[str]) -> None:
    assert _common.fail("broken") == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "::error::broken" in captured.err
