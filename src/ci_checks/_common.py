"""Helpers shared by the checks: git access, file selection, reporting."""

from __future__ import annotations

import codecs
import fnmatch
import json
import os
import re
import subprocess
import sys
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

MAX_TEXT_BYTES = 1_000_000
MAX_SCAN_BYTES = 20_000_000
BINARY_SNIFF_BYTES = 8192
EMPTY_SHA = "0" * 40
# Dependency update bots whose commits quote upstream text. Usernames with
# brackets are reserved for GitHub Apps, so no person can use these logins.
DEPENDENCY_BOTS = frozenset({"dependabot[bot]"})
_PRAGMA = re.compile(r"ci-allow:\s*([a-z0-9-]+(?:\s*,\s*[a-z0-9-]+)*)")
_HUNK = re.compile(r"^(@{2,}) (?:-\d+(?:,\d+)? )+\+(\d+)(?:,\d+)? @{2,}")
_INDEX = re.compile(r"^index (?:[0-9a-f]+,)*[0-9a-f]+\.\.([0-9a-f]+)")


@dataclass(frozen=True)
class Commit:
    """A commit with the fields the checks look at."""

    sha: str
    author_name: str
    author_email: str
    committer_name: str
    committer_email: str
    message: str

    @property
    def short(self) -> str:
        """Return the abbreviated SHA used in messages."""
        return self.sha[:12]

    @property
    def is_dependency_bot(self) -> bool:
        """Return whether the author address is the one of a dependency update bot."""
        local, _, domain = self.author_email.lower().rpartition("@")
        return domain == "users.noreply.github.com" and local.rpartition("+")[2] in DEPENDENCY_BOTS


@dataclass(frozen=True)
class Change:
    """A file written by a commit, with the lines the commit added to it.

    `blob` is the id of the new content, or empty when the commit deleted the
    file or only changed its mode.
    """

    sha: str
    path: str
    blob: str
    added: tuple[tuple[int, str], ...]


@dataclass(frozen=True)
class PullRequest:
    """The pull request fields the checks look at."""

    title: str
    body: str
    head_ref: str
    author_login: str
    from_fork: bool

    @property
    def is_dependency_bot(self) -> bool:
        """Return whether a dependency update bot opened the pull request."""
        return self.author_login in DEPENDENCY_BOTS


class CheckError(Exception):
    """Raised when a check cannot run, for example on a shallow clone."""


def git(*args: str, cwd: Path | None = None) -> str:
    """Run git and return its standard output."""
    result = subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return result.stdout


def require_full_history(root: Path) -> None:
    """Fail clearly when the checkout does not hold the whole history."""
    if git("rev-parse", "--is-shallow-repository", cwd=root).strip() == "true":
        raise CheckError("The checkout is shallow. Check out with fetch-depth: 0.")


def tracked_files(root: Path) -> list[str]:
    """Return the paths tracked by git, relative to the repository root."""
    output = git("ls-files", "-z", cwd=root)
    return sorted(path for path in output.split("\0") if path)


def matches_any(path: str, patterns: Iterable[str]) -> bool:
    """Return whether a path matches one of the glob patterns."""
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)


def split_list(value: str | None) -> list[str]:
    """Split a whitespace or comma separated input into items."""
    if not value:
        return []
    return [item for item in re.split(r"[\s,]+", value) if item]


def read_bytes(path: Path, limit: int) -> bytes | None:
    """Return the content of a regular file, or None if it is missing or too large."""
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
            return None
        return path.read_bytes()
    except OSError:
        return None


def decode_text(data: bytes) -> str | None:
    """Return the text of file content, or None when it is binary.

    UTF-16 and UTF-32 with a byte order mark are decoded too, because Windows
    editors and shells write them; anything else is read as UTF-8.
    """
    for boms, encoding in (
        ((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE), "utf-32"),
        ((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE), "utf-16"),
    ):
        if data.startswith(boms):
            return data.decode(encoding, errors="replace")
    if b"\0" in data[:BINARY_SNIFF_BYTES]:
        return None
    return data.decode("utf-8", errors="replace")


def read_text(path: Path, limit: int = MAX_TEXT_BYTES) -> str | None:
    """Return the text of a file, or None for binary or oversized files."""
    data = read_bytes(path, limit)
    return None if data is None else decode_text(data)


def split_lines(text: str) -> list[str]:
    """Split text into lines on line feeds only, as git and editors number them."""
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()
    return [line.removesuffix("\r") for line in lines]


def iter_lines(root: Path, paths: Iterable[str]) -> Iterator[tuple[str, int, str]]:
    """Yield (path, line number, line) for every text file."""
    for path in paths:
        text = read_text(root / path)
        if text is None:
            continue
        for number, line in enumerate(split_lines(text), start=1):
            yield path, number, line


def allowed_by_pragma(line: str, category: str) -> bool:
    """Return whether a line opts out of a category with `ci-allow: <category>`."""
    for match in _PRAGMA.finditer(line):
        names = {name.strip() for name in match.group(1).split(",")}
        if category in names:
            return True
    return False


def load_event() -> dict:
    """Return the payload of the event that triggered the workflow."""
    path = os.environ.get("GITHUB_EVENT_PATH")
    if not path or not Path(path).is_file():
        return {}
    with Path(path).open(encoding="utf-8") as handle:
        return json.load(handle)


def pull_request(event: dict) -> PullRequest | None:
    """Return the pull request of the event, if any."""
    pr = event.get("pull_request")
    if not pr:
        return None
    user = pr.get("user") or {}
    head_repo = (pr.get("head") or {}).get("repo") or {}
    base_repo = (pr.get("base") or {}).get("repo") or {}
    return PullRequest(
        title=pr.get("title") or "",
        body=pr.get("body") or "",
        head_ref=(pr.get("head") or {}).get("ref") or "",
        author_login=user.get("login") or "",
        from_fork=head_repo.get("full_name") != base_repo.get("full_name"),
    )


def history_tip(event: dict) -> str:
    """Return the commit whose history is scanned.

    For pull requests this is the head commit, which skips the synthetic
    merge commit that GitHub checks out by default.
    """
    pr = event.get("pull_request")
    if pr:
        return pr["head"]["sha"]
    return "HEAD"


def new_commit_range(event: dict, root: Path | None = None) -> list[str]:
    """Return git log arguments selecting the commits introduced by the event.

    The first push of a branch, a force push whose previous tip is gone, and
    events without a push (such as a manual run) select the whole history.
    """
    pr = event.get("pull_request")
    if pr:
        return [f"{pr['base']['sha']}..{pr['head']['sha']}"]
    before = event.get("before")
    after = event.get("after") or "HEAD"
    if before and before != EMPTY_SHA and _is_commit(before, root):
        return [f"{before}..{after}"]
    return [after]


def dependency_bot_commits(event: dict, new: Iterable[Commit]) -> set[str]:
    """Return the new commits written by a dependency update bot.

    Anyone can write a bot address into a commit, so in a pull request the
    commits only count when the bot also opened the pull request. On a push,
    the branch ruleset already makes every commit go through a pull request.
    """
    pr = pull_request(event)
    if pr is not None and not pr.is_dependency_bot:
        return set()
    return {commit.sha for commit in new if commit.is_dependency_bot}


def _is_commit(revision: str, root: Path | None) -> bool:
    if root is None:
        return True
    try:
        git("cat-file", "-e", f"{revision}^{{commit}}", cwd=root)
    except subprocess.CalledProcessError:
        return False
    return True


_RECORD = "\x1e"
_ESCAPES = {"a": 7, "b": 8, "t": 9, "n": 10, "v": 11, "f": 12, "r": 13, '"': 34, "\\": 92}


def commits(root: Path, revisions: list[str]) -> list[Commit]:
    """Return the commits selected by git log revision arguments."""
    # Git refuses NUL bytes in names, addresses and messages, so it is a safe
    # separator for both fields and records.
    fmt = "%x00".join(["%H", "%an", "%ae", "%cn", "%ce", "%B"])
    output = git("log", "-z", f"--format={fmt}", *revisions, "--", cwd=root)
    fields = output.split("\0")
    result = []
    for start in range(0, len(fields) - 5, 6):
        sha, an, ae, cn, ce, message = fields[start : start + 6]
        result.append(Commit(sha, an, ae, cn, ce, message.strip("\n")))
    return result


def changes(root: Path, revisions: list[str]) -> list[Change]:
    """Return the files written by the selected commits, with their added lines.

    Lines that a later commit removes are included, because the commit that
    added them stays reachable after the pull request is merged. Every file
    is diffed as text, whatever its attributes say; for merges, only the
    lines that differ from every parent count, which is what the merge
    itself introduced.
    """
    output = git(
        "-c",
        "core.quotePath=false",
        "log",
        "--patch",
        "--cc",
        "--text",
        "--no-textconv",
        "--no-ext-diff",
        "--no-renames",
        "--no-color",
        "--full-index",
        "--unified=0",
        f"--format={_RECORD}%H",
        *revisions,
        "--",
        cwd=root,
    )
    result: list[Change] = []
    sha = path = blob = ""
    added: list[tuple[int, str]] = []
    open_file = in_header = False
    parents = line = 0

    def close() -> None:
        if open_file:
            result.append(Change(sha, path, blob, tuple(added)))

    for raw in output.split("\n"):
        if raw.startswith(_RECORD):
            close()
            sha, open_file = raw[1:], False
        elif raw.startswith(("diff --git ", "diff --cc ", "diff --combined ")):
            close()
            path, blob, added = _header_path(raw), "", []
            open_file = in_header = True
        elif not open_file:
            continue
        elif hunk := _HUNK.match(raw):
            in_header = False
            parents, line = len(hunk.group(1)) - 1, int(hunk.group(2))
        elif in_header:
            if index := _INDEX.match(raw):
                blob = "" if set(index.group(1)) == {"0"} else index.group(1)
            elif raw == "+++ /dev/null":
                blob = ""
        elif len(raw) >= parents and not raw.startswith("\\"):
            markers = raw[:parents]
            if "-" in markers:
                continue  # A line of a parent that the commit removed.
            if markers == "+" * parents:
                added.append((line, raw[parents:]))
            line += 1
    close()
    return result


def _header_path(header: str) -> str:
    """Return the path named by a diff header line."""
    if header.startswith("diff --git "):
        # Without renames both sides name the same path: "a/<p> b/<p>".
        rest = header[len("diff --git ") :]
        if rest.startswith('"'):
            half = (len(rest) - 8) // 2
            return _unquote(rest[3 : 3 + half])
        half = (len(rest) - 5) // 2
        return rest[2 : 2 + half]
    rest = header.split(" ", 2)[2]
    return _unquote(rest[1:-1]) if rest.startswith('"') else rest


def _unquote(text: str) -> str:
    """Decode the C-style escapes that git uses in quoted paths."""
    out = bytearray()
    index = 0
    while index < len(text):
        char = text[index]
        if char == "\\" and index + 1 < len(text):
            escape = text[index + 1]
            if escape in "01234567":
                out.append(int(text[index + 1 : index + 4], 8) & 0xFF)
                index += 4
                continue
            if escape in _ESCAPES:
                out.append(_ESCAPES[escape])
                index += 2
                continue
        out.extend(char.encode("utf-8"))
        index += 1
    return out.decode("utf-8", errors="replace")


def blob_contents(root: Path, blobs: Iterable[str], limit: int) -> dict[str, bytes | None]:
    """Return the content of git blobs, or None for those missing or over the limit."""
    wanted = sorted(set(blobs))
    if not wanted:
        return {}
    request = "".join(f"{blob}\n" for blob in wanted).encode()
    checked = subprocess.run(
        ["git", "cat-file", "--batch-check"],
        cwd=root,
        input=request,
        capture_output=True,
        check=True,
    ).stdout.decode()
    result: dict[str, bytes | None] = dict.fromkeys(wanted)
    small = []
    for entry in checked.splitlines():
        fields = entry.split()
        if len(fields) == 3 and fields[1] == "blob" and int(fields[2]) <= limit:
            small.append(fields[0])
    if not small:
        return result
    request = "".join(f"{blob}\n" for blob in small).encode()
    output = subprocess.run(
        ["git", "cat-file", "--batch"], cwd=root, input=request, capture_output=True, check=True
    ).stdout
    position = 0
    while position < len(output):
        end = output.index(b"\n", position)
        blob, _, size = output[position:end].decode().split()
        start = end + 1
        result[blob] = output[start : start + int(size)]
        position = start + int(size) + 1
    return result


class Reporter:
    """Collect findings and print them as GitHub annotations."""

    def __init__(self, check: str) -> None:
        self.check = check
        self.count = 0

    def error(self, message: str, path: str | None = None, line: int | None = None) -> None:
        """Report a problem, optionally attached to a file and line."""
        self.count += 1
        location = ""
        if path:
            location = f" file={_escape_property(path)}"
            if line:
                location += f",line={line}"
        print(f"::error{location}::{_escape_data(message)}")

    def warning(self, message: str) -> None:
        """Report something that needs attention without failing the check."""
        print(f"::warning::{_escape_data(message)}")

    def finish(self) -> int:
        """Print a summary and return the exit code."""
        if self.count:
            print(f"{self.check}: {self.count} problem(s) found.")
            return 1
        print(f"{self.check}: no problem found.")
        return 0


def fail(message: str) -> int:
    """Print an error that stops a check and return its exit code."""
    print(f"::error::{_escape_data(message)}", file=sys.stderr)
    return 1


def _escape_data(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_property(value: str) -> str:
    return _escape_data(value).replace(":", "%3A").replace(",", "%2C")
