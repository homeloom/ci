"""Helpers shared by the checks: git access, file selection, reporting."""

from __future__ import annotations

import codecs
import fnmatch
import json
import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

MAX_TEXT_BYTES = 1_000_000
MAX_SCAN_BYTES = 20_000_000
BINARY_SNIFF_BYTES = 8192
EMPTY_SHA = "0" * 40
GITLINK_MODE = "160000"
# Dependency update bots whose commits quote upstream text. Usernames with
# brackets are reserved for GitHub Apps, so no person can use these logins.
DEPENDENCY_BOTS = frozenset({"dependabot[bot]"})
# Error handler that reads bytes which are not UTF-8 as Windows-1252, the
# encoding that Windows tools and spreadsheet exports use in Western Europe,
# so that accented text in those files can still be checked.
LEGACY = "ci-legacy"
_CP1252 = tuple(bytes([byte]).decode("cp1252", errors="ignore") or chr(byte) for byte in range(256))
_PRAGMA = re.compile(r"ci-allow:\s*([a-z0-9-]+(?:\s*,\s*[a-z0-9-]+)*)")
_HUNK = re.compile(rb"^(@{2,}) (?:-\d+(?:,\d+)? )+\+(\d+)(?:,(\d+))? @{2,}")
_INDEX = re.compile(rb"^index (?:[0-9a-f]+,)*[0-9a-f]+\.\.([0-9a-f]+)(?: (\d+))?$")
_MODE = re.compile(rb"^(?:new file|new|deleted file) mode (\d+)$")


def _read_legacy(error: UnicodeError) -> tuple[str, int]:
    if not isinstance(error, UnicodeDecodeError):
        raise error
    chunk = error.object[error.start : error.end]
    return "".join(_CP1252[byte] for byte in chunk), error.end


codecs.register_error(LEGACY, _read_legacy)


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
    """A file written by a commit, with the numbers of the lines it added.

    `blob` is the id of the new content, or empty when the commit deleted the
    file. `added` is None when git found the content binary and did not diff
    it, so that every line of the content counts as added. Paths are file
    system strings, as `os.fsdecode` returns them.
    """

    sha: str
    path: str
    blob: str
    mode: str
    added: frozenset[int] | None


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


def git_bytes(*args: str, cwd: Path | None = None, stdin: bytes | None = None) -> bytes:
    """Run git and return its standard output as bytes."""
    return subprocess.run(
        ["git", *args], cwd=cwd, input=stdin, check=True, capture_output=True
    ).stdout


def git(*args: str, cwd: Path | None = None) -> str:
    """Run git and return its standard output, without changing line endings."""
    return git_bytes(*args, cwd=cwd).decode("utf-8", LEGACY)


def display_path(path: str) -> str:
    """Return a file system path as text, reading names that are not UTF-8 as Windows-1252."""
    return os.fsencode(path).decode("utf-8", LEGACY)


def require_full_history(root: Path) -> None:
    """Fail clearly when the checkout does not hold the whole history."""
    if git("rev-parse", "--is-shallow-repository", cwd=root).strip() == "true":
        raise CheckError("The checkout is shallow. Check out with fetch-depth: 0.")


def tracked_files(root: Path) -> list[str]:
    """Return the paths tracked by git, relative to the repository root."""
    output = git_bytes("ls-files", "-z", cwd=root)
    return sorted(os.fsdecode(path) for path in output.split(b"\0") if path)


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

    UTF-16 and UTF-32 are decoded too, because Windows editors and shells
    write them: with a byte order mark, or UTF-16 without one when every
    other byte is zero. Anything else is read as UTF-8, with the bytes that
    are not UTF-8 read as Windows-1252.
    """
    for boms, encoding in (
        ((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE), "utf-32"),
        ((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE), "utf-16"),
    ):
        if data.startswith(boms):
            return data.decode(encoding, errors="replace")
    if b"\0" not in data[:BINARY_SNIFF_BYTES]:
        return data.decode("utf-8-sig", LEGACY)
    return _utf16_without_bom(data)


def _utf16_without_bom(data: bytes) -> str | None:
    sample = data[: BINARY_SNIFF_BYTES - BINARY_SNIFF_BYTES % 2]
    pairs = len(sample) // 2
    even, odd = sample[0::2].count(0), sample[1::2].count(0)
    for encoding, zeros, others in (("utf-16-le", odd, even), ("utf-16-be", even, odd)):
        if pairs >= 4 and zeros >= pairs * 0.9 and others <= pairs * 0.02:
            text = data[: len(data) - len(data) % 2].decode(encoding, errors="replace")
            controls = sum(char < " " and char not in "\t\n\r\f" for char in text)
            return text if controls <= len(text) * 0.01 else None
    return None


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


_RECORD = b"\x1e"
_ESCAPES = {"a": 7, "b": 8, "t": 9, "n": 10, "v": 11, "f": 12, "r": 13, '"': 34, "\\": 92}


def commits(root: Path, revisions: list[str]) -> list[Commit]:
    """Return the commits selected by git log revision arguments.

    The commit objects are read as stored, so that a message with a NUL byte,
    which git log would cut short, is checked whole.
    """
    shas = git("rev-list", *revisions, "--", cwd=root).split()
    objects = _cat_file(root, shas, limit=None)
    return [_parse_commit(sha, objects[sha] or b"") for sha in shas]


def _parse_commit(sha: str, data: bytes) -> Commit:
    header, _, body = data.partition(b"\n\n")
    people: dict[bytes, bytes] = {}
    encoding = "utf-8"
    for line in header.split(b"\n"):
        key, _, value = line.partition(b" ")
        if key in (b"author", b"committer"):
            people.setdefault(key, value)
        elif key == b"encoding":
            encoding = value.decode("ascii", errors="replace")

    def decode(raw: bytes) -> str:
        try:
            if codecs.lookup(encoding).name != "utf-8":
                return raw.decode(encoding, errors="replace")
        except LookupError:
            pass
        return raw.decode("utf-8", LEGACY)

    an, ae = _identity(people.get(b"author", b""))
    cn, ce = _identity(people.get(b"committer", b""))
    return Commit(sha, decode(an), decode(ae), decode(cn), decode(ce), decode(body).strip("\n"))


def _identity(value: bytes) -> tuple[bytes, bytes]:
    """Split "Name <address> timestamp zone" into the name and the address."""
    start, end = value.find(b"<"), value.rfind(b">")
    if start < 0 or end < start:
        return value, b""
    return value[:start].strip(), value[start + 1 : end]


def changes(root: Path, revisions: list[str]) -> list[Change]:
    """Return the files written by the selected commits, with the lines they added.

    Lines that a later commit removes are included, because the commit that
    added them stays reachable after the pull request is merged. For merges,
    only the lines that differ from every parent count, which is what the
    merge itself introduced. The patch is read as bytes, line by line, so
    that carriage returns and odd bytes in files or names cannot shift it.
    """
    command = [
        "git",
        "-c",
        "core.quotePath=false",
        "log",
        "--patch",
        "--cc",
        "--no-textconv",
        "--no-ext-diff",
        "--no-renames",
        "--no-color",
        "--full-index",
        "--src-prefix=a/",
        "--dst-prefix=b/",
        "--unified=0",
        "--format=%x1e%H",
        *revisions,
        "--",
    ]
    result: list[Change] = []
    sha = path = blob = mode = ""
    added: set[int] | None = set()
    open_file = in_header = False
    parents = line = 0

    def close() -> None:
        if open_file:
            lines = None if added is None else frozenset(added)
            result.append(Change(sha, path, blob, mode, lines))

    with tempfile.TemporaryFile() as errors:
        process = subprocess.Popen(command, cwd=root, stdout=subprocess.PIPE, stderr=errors)
        assert process.stdout is not None  # noqa: S101 - set by stdout=PIPE above.
        for raw in process.stdout:
            raw = raw.removesuffix(b"\n")
            if raw.startswith(_RECORD):
                close()
                sha, open_file = raw[1:].decode("ascii"), False
            elif raw.startswith((b"diff --git ", b"diff --cc ", b"diff --combined ")):
                close()
                path, blob, mode, added = os.fsdecode(_header_path(raw)), "", "", set()
                open_file = in_header = True
            elif not open_file:
                continue
            elif hunk := _HUNK.match(raw):
                in_header = False
                parents, line = len(hunk.group(1)) - 1, int(hunk.group(2))
            elif in_header:
                if index := _INDEX.match(raw):
                    blob = "" if set(index.group(1)) == {ord("0")} else index.group(1).decode()
                    mode = (index.group(2) or mode.encode()).decode()
                elif changed := _MODE.match(raw):
                    mode = changed.group(1).decode()
                elif raw == b"+++ /dev/null":
                    blob = ""
                elif raw.startswith(b"Binary files "):
                    added = None
            elif added is not None and len(raw) >= parents and not raw.startswith(b"\\"):
                markers = raw[:parents]
                if b"-" in markers:
                    continue  # A line of a parent that the commit removed.
                if markers == b"+" * parents:
                    added.add(line)
                line += 1
        close()
        if process.wait():
            errors.seek(0)
            raise subprocess.CalledProcessError(process.returncode, command, stderr=errors.read())
    return result


def _header_path(header: bytes) -> bytes:
    """Return the path named by a diff header line."""
    if header.startswith(b"diff --git "):
        # Without renames both sides name the same path: "a/<p> b/<p>".
        rest = header[len(b"diff --git ") :]
        if rest.startswith(b'"'):
            half = (len(rest) - 8) // 2
            return _unquote(rest[3 : 3 + half])
        half = (len(rest) - 5) // 2
        return rest[2 : 2 + half]
    rest = header.split(b" ", 2)[2]
    return _unquote(rest[1:-1]) if rest.startswith(b'"') else rest


def _unquote(text: bytes) -> bytes:
    """Decode the C-style escapes that git uses in quoted paths."""
    out = bytearray()
    index = 0
    while index < len(text):
        char = text[index : index + 1]
        if char == b"\\" and index + 1 < len(text):
            escape = chr(text[index + 1])
            if escape in "01234567":
                out.append(int(text[index + 1 : index + 4], 8) & 0xFF)
                index += 4
                continue
            if escape in _ESCAPES:
                out.append(_ESCAPES[escape])
                index += 2
                continue
        out += char
        index += 1
    return bytes(out)


def blob_contents(root: Path, blobs: Iterable[str], limit: int) -> dict[str, bytes | None]:
    """Return the content of git blobs, with None for those over the limit.

    Blobs that are missing from the repository are left out.
    """
    return _cat_file(root, sorted(set(blobs)), limit, kind="blob")


def _cat_file(
    root: Path, ids: list[str], limit: int | None, kind: str | None = None
) -> dict[str, bytes | None]:
    if not ids:
        return {}
    request = "".join(f"{object_id}\n" for object_id in ids).encode()
    checked = git_bytes("cat-file", "--batch-check", cwd=root, stdin=request).decode()
    result: dict[str, bytes | None] = {}
    wanted = []
    for entry in checked.splitlines():
        fields = entry.split()
        if len(fields) != 3 or (kind and fields[1] != kind):
            continue
        if limit is not None and int(fields[2]) > limit:
            result[fields[0]] = None
        else:
            wanted.append(fields[0])
    if not wanted:
        return result
    request = "".join(f"{object_id}\n" for object_id in wanted).encode()
    output = git_bytes("cat-file", "--batch", cwd=root, stdin=request)
    position = 0
    while position < len(output):
        end = output.index(b"\n", position)
        object_id, _, size = output[position:end].decode().split()
        start = end + 1
        result[object_id] = output[start : start + int(size)]
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
            location = f" file={_escape_property(display_path(path))}"
            if line:
                location += f",line={line}"
        print(f"::error{location}::{_escape_data(_printable(message))}")

    def warning(self, message: str) -> None:
        """Report something that needs attention without failing the check."""
        print(f"::warning::{_escape_data(_printable(message))}")

    def finish(self) -> int:
        """Print a summary and return the exit code."""
        if self.count:
            print(f"{self.check}: {self.count} problem(s) found.")
            return 1
        print(f"{self.check}: no problem found.")
        return 0


def fail(message: str) -> int:
    """Print an error that stops a check and return its exit code."""
    print(f"::error::{_escape_data(_printable(message))}", file=sys.stderr)
    return 1


def _printable(value: str) -> str:
    """Return text that can be printed, with file names that are not UTF-8 decoded."""
    return value.encode("utf-8", "surrogateescape").decode("utf-8", LEGACY)


def _escape_data(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_property(value: str) -> str:
    return _escape_data(value).replace(":", "%3A").replace(",", "%2C")
