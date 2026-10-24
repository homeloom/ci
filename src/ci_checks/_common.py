"""Helpers shared by the checks: git access, file selection, reporting."""

from __future__ import annotations

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
_PRAGMA = re.compile(r"ci-allow:\s*([a-z0-9-]+(?:\s*,\s*[a-z0-9-]+)*)")
_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


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
    def is_bot(self) -> bool:
        """Return whether a GitHub App such as Dependabot authored the commit."""
        return self.author_email.lower().endswith("[bot]@users.noreply.github.com")


@dataclass(frozen=True)
class Addition:
    """A line added by a commit."""

    sha: str
    path: str
    line: int
    text: str


@dataclass(frozen=True)
class PullRequest:
    """The pull request fields the checks look at."""

    title: str
    body: str
    head_ref: str
    author_is_bot: bool
    from_fork: bool


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


def read_text(path: Path) -> str | None:
    """Return the text of a file, or None for binary or oversized files."""
    data = read_bytes(path, MAX_TEXT_BYTES)
    if data is None or b"\0" in data[:BINARY_SNIFF_BYTES]:
        return None
    return data.decode("utf-8", errors="replace")


def iter_lines(root: Path, paths: Iterable[str]) -> Iterator[tuple[str, int, str]]:
    """Yield (path, line number, line) for every text file."""
    for path in paths:
        text = read_text(root / path)
        if text is None:
            continue
        for number, line in enumerate(text.splitlines(), start=1):
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
        author_is_bot=user.get("type") == "Bot",
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

    After a force push the previous tip may be missing from the clone; only
    the new tip is selected then.
    """
    pr = event.get("pull_request")
    if pr:
        return [f"{pr['base']['sha']}..{pr['head']['sha']}"]
    before = event.get("before")
    after = event.get("after")
    if before and after and before != EMPTY_SHA and _is_commit(before, root):
        return [f"{before}..{after}"]
    return ["-1", after or "HEAD"]


def _is_commit(revision: str, root: Path | None) -> bool:
    if root is None:
        return True
    try:
        git("cat-file", "-e", f"{revision}^{{commit}}", cwd=root)
    except subprocess.CalledProcessError:
        return False
    return True


_FIELD = "\x1f"
_RECORD = "\x1e"


def commits(root: Path, revisions: list[str]) -> list[Commit]:
    """Return the commits selected by git log revision arguments."""
    fmt = _FIELD.join(["%H", "%an", "%ae", "%cn", "%ce", "%B"]) + _RECORD
    output = git("log", f"--format={fmt}", *revisions, "--", cwd=root)
    result = []
    for record in output.split(_RECORD):
        record = record.strip("\n")
        if not record:
            continue
        sha, an, ae, cn, ce, message = record.split(_FIELD, 5)
        result.append(Commit(sha, an, ae, cn, ce, message))
    return result


def additions(root: Path, revisions: list[str]) -> Iterator[Addition]:
    """Yield the lines added by the selected commits, merges excluded.

    Lines that a later commit removes are included, because the commit that
    added them stays reachable after the pull request is merged.
    """
    output = git(
        "-c",
        "core.quotePath=false",
        "log",
        "--no-merges",
        "--no-renames",
        "--no-color",
        "--no-ext-diff",
        "--unified=0",
        "--patch",
        f"--format={_RECORD}%H",
        *revisions,
        "--",
        cwd=root,
    )
    sha = path = ""
    line = 0
    in_header = False
    # str.splitlines() would also split on the record separator.
    for raw in output.split("\n"):
        if raw.startswith(_RECORD):
            sha, path, in_header = raw[1:], "", False
        elif raw.startswith("diff --git "):
            path, in_header = "", True
        elif in_header:
            if raw.startswith("+++ "):
                # Git appends a tab to names with spaces, and quotes unusual names.
                target = raw[4:].rstrip("\t").strip('"')
                path = target[2:] if target.startswith("b/") else ""
            elif raw.startswith("@@"):
                in_header = False
                line = _hunk_start(raw)
        elif raw.startswith("@@"):
            line = _hunk_start(raw)
        elif raw.startswith("+") and path:
            yield Addition(sha, path, line, raw[1:])
            line += 1


def _hunk_start(header: str) -> int:
    match = _HUNK.match(header)
    return int(match.group(1)) if match else 0


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
