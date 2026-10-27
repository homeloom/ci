"""Scan the history, the commit messages and the pull request text for secrets.

gitleaks reads the diff of every commit in the history of the scanned
commit, with the rules of the action's own configuration. It runs from an
empty directory on the git directory, so a .gitleaks.toml or .gitleaksignore
in the repository has no effect. Commit messages, the pull request title and
body, and the lines that commits add to the files gitleaks cannot read in a
diff (UTF-16 or UTF-32 text, the text files inside ZIP, gzip and PDF files,
paths ending with a backslash) are written to a temporary directory and
scanned there with the same rules. They are written
under generated names, so the few rules limited to some file names, such as
YAML files, do not apply to them.

Findings name the commit, file, rule and line, never the secret. A known
false positive that is already in the history of the base branch can be
ignored by listing its fingerprint. In the repository content, only
gitleaks' own gitleaks:allow comment hides a line, and the privacy check
warns about each line that adds it, in text and binary files alike (PDF
files included); it fails files over MAX_SCAN_BYTES, which it cannot read.
The comment is removed from the texts of the directory scan.
"""

from __future__ import annotations

import argparse
import codecs
import difflib
import json
import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from ci_checks._common import (
    BINARY_SNIFF_BYTES,
    EMPTY_SHA,
    MAX_SCAN_BYTES,
    CheckError,
    Commit,
    PullRequest,
    Reporter,
    blob_contents,
    commits,
    decode_text,
    fail,
    git,
    history_tip,
    load_event,
    pull_request,
    require_full_history,
)
from ci_checks.denylist import Denylist, denylist_sources
from ci_checks.unpack import PACKED_SIGNATURES, unpack

# gitleaks passes these to `git log` after splitting them on spaces. A merge
# is diffed against its first parent, so that what the merge itself adds (a
# conflict resolution, a file added before committing the merge) is scanned
# once; -m would report each of those lines once per parent. --text reads
# every file as text, whatever a .gitattributes file of the repository says.
LOG_OPTIONS = "--text --no-textconv --no-ext-diff --diff-merges=first-parent"
_WIDE_BOMS = (codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE, codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)
_REGULAR_FILE = frozenset({"100644", "100755"})
_BLOB_CHUNK = 256
# gitleaks skips a line that carries this marker. The privacy check warns
# about it on the lines added to files that git can diff; nothing would
# question it in the texts of the directory scan, so it is removed from them.
_ALLOW_MARKER = "gitleaks:allow"
# gitleaks exits with 0 when git fails, and only says so in its log.
_LOG_ERROR = re.compile(r"^\S+ (?:ERR|FTL) ")
_COMMITS_SCANNED = re.compile(r" INF (\d+) commits scanned")
_BYTES_SCANNED = re.compile(r" INF scanned ~(\d+) bytes")
_FINGERPRINT = re.compile(r"([0-9a-f]{40}):(.*):([\w.-]+):(\d+)")


@dataclass(frozen=True)
class Finding:
    """A possible secret: the rule that matched and where.

    A finding in a file has a commit and a path, one in a commit message a
    commit only, and one in the pull request text a field only.
    """

    rule: str
    line: int
    commit: str = ""
    path: str = ""
    field: str = ""

    @property
    def fingerprint(self) -> str:
        """Return commit:path:rule:line, with an empty path for a commit message.

        The pull request text is not in the history, so it has none.
        """
        if not self.commit:
            return ""
        return f"{self.commit}:{self.path}:{self.rule}:{self.line}"


class Gitleaks:
    """Run gitleaks with one configuration, away from the scanned repository."""

    def __init__(self, executable: str, config: Path, work: Path, denylist: Denylist) -> None:
        self.executable = executable
        self.config = config
        self.denylist = denylist
        self.empty = work / "empty"
        self.empty.mkdir()
        self.report = work / "report.json"

    def run(self, *args: str) -> tuple[list[dict], str]:
        """Return the findings and the log of a scan, or fail on any error it logs."""
        self.report.unlink(missing_ok=True)
        command = [
            self.executable,
            *args,
            "--no-banner",
            "--no-color",
            "--redact",
            "--exit-code",
            "0",
            "--config",
            str(self.config),
            "--gitleaks-ignore-path",
            str(self.empty),
            "--report-format",
            "json",
            "--report-path",
            str(self.report),
        ]
        try:
            result = subprocess.run(
                command,
                cwd=self.empty,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
            )
        except OSError as err:
            raise CheckError(f"gitleaks could not run: {err}") from err
        log = result.stdout + result.stderr
        errors = [line for line in log.splitlines() if _LOG_ERROR.match(line)]
        if result.returncode != 0 or errors or not self.report.is_file():
            shown = [
                "[a line with a denylisted term]" if self.denylist.matches(line) else line
                for line in errors
            ]
            raise CheckError(
                "\n".join([f"gitleaks failed (exit code {result.returncode}).", *shown])
            )
        return json.loads(self.report.read_text(encoding="utf-8")), log


def scan_history(gitleaks: Gitleaks, root: Path, tip: str) -> list[Finding]:
    """Scan the diff of every commit in the history of `tip`."""
    git_dir = git("rev-parse", "--absolute-git-dir", cwd=root).strip()
    report, log = gitleaks.run("git", f"--log-opts={LOG_OPTIONS} {tip}", git_dir)
    scanned = _COMMITS_SCANNED.search(log)
    if not scanned or scanned.group(1) == "0":
        raise CheckError("gitleaks scanned no commit, so the history was not checked.")
    return [
        Finding(item["RuleID"], item["StartLine"], item["Commit"], item["File"]) for item in report
    ]


def history_changes(root: Path, tip: str) -> list[tuple[str, str, str, str]]:
    """Return (commit, path, old blob, new blob) for each file written in the history.

    As in the gitleaks scan, a merge is compared with its first parent and a
    renamed file with its old version. The old blob of a new file is
    EMPTY_SHA.
    """
    output = git(
        "log",
        "-z",
        "--raw",
        "--no-abbrev",
        "--find-renames",
        "--diff-merges=first-parent",
        "--format=%H",
        tip,
        "--",
        cwd=root,
    )
    result = []
    sha = ""
    tokens = iter(output.split("\0"))
    for token in tokens:
        token = token.lstrip("\n")
        if token.startswith(":"):
            # ":<old mode> <new mode> <old blob> <new blob> <status>", then the
            # path, or the old and the new path of a rename.
            _, mode, old, new, status = token[1:].split(" ")
            path = next(tokens)
            if status.startswith("R"):
                path = next(tokens)
            if mode in _REGULAR_FILE and old != new:
                result.append((sha, path, old, new))
        elif token:
            sha = token
    return result


def _read_blobs(root: Path, blobs: Iterable[str]) -> Iterator[tuple[str, bytes]]:
    """Yield the content of each blob of at most MAX_SCAN_BYTES.

    The history holds every version of every file, lock files included, and
    blob_contents keeps all it reads in memory, so blobs are read a chunk at
    a time.
    """
    wanted = sorted(set(blobs) - {EMPTY_SHA})
    for start in range(0, len(wanted), _BLOB_CHUNK):
        chunk = blob_contents(root, wanted[start : start + _BLOB_CHUNK], MAX_SCAN_BYTES)
        for blob, data in chunk.items():
            if data is not None:
                yield blob, data


def _added_lines(old: str, new: str) -> str:
    """Return `new` with only the lines that a diff from `old` shows as added.

    The other lines are left empty, so that line numbers stay those of `new`.
    """
    old_lines = old.split("\n")
    new_lines = new.split("\n")
    added = [""] * len(new_lines)
    matcher = difflib.SequenceMatcher(None, old_lines, new_lines)
    for tag, _, _, start, end in matcher.get_opcodes():
        if tag in {"replace", "insert"}:
            added[start:end] = new_lines[start:end]
    return "\n".join(added)


def _hidden_text(data: bytes) -> str | None:
    """Return the text that gitleaks cannot read in a diff of this content, or None.

    That is wide text (UTF-16, with or without a byte order mark, or UTF-32)
    and the text files that ZIP, gzip and PDF files hold compressed. git
    log ignores --max-archive-depth, which only applies to directory scans.
    """
    if data.startswith(_WIDE_BOMS) or b"\0" in data[:BINARY_SNIFF_BYTES]:
        text = decode_text(data)
        if text is not None:
            return text
    texts = [
        decode_text(part.data)
        for part in unpack(data).parts
        if not part.data.startswith(PACKED_SIGNATURES)
    ]
    texts = [text for text in texts if text is not None]
    return "\n".join(texts) if texts else None


def unreadable_files(root: Path, tip: str) -> list[tuple[str, str, str]]:
    """Return (commit, path, text) for the history files that gitleaks cannot read.

    Git diffs wide text as binary, gitleaks does not open the archives of a
    diff, and gitleaks 8.30.1 drops the diff of a path that ends with a
    backslash. As in a diff, the text holds the lines that the commit added,
    so that a later commit does not report again what an earlier one added;
    the other lines are empty. The text of an archive is that of its text
    members, one after the other, so its line numbers count in them.
    """
    changes = history_changes(root, tip)
    backslash = {new for _, path, _, new in changes if path.endswith("\\")}
    texts: dict[str, str] = {}
    hidden = set()
    for blob, data in _read_blobs(root, {new for _, _, _, new in changes}):
        text = _hidden_text(data)
        if text is not None:
            hidden.add(blob)
        elif blob in backslash:
            text = decode_text(data)
        if text is not None:
            texts[blob] = text
    unreadable = [
        (sha, path, old, new)
        for sha, path, old, new in changes
        if new in texts and (new in hidden or path.endswith("\\"))
    ]
    # A file converted to UTF-16 has an older version that is not, and a
    # binary one has no line in common with the text.
    older = {old for _, _, old, _ in unreadable if old not in texts}
    for blob, data in _read_blobs(root, older):
        texts[blob] = _hidden_text(data) or decode_text(data) or ""
    result = []
    for sha, path, old, new in unreadable:
        added = _added_lines(texts.get(old, ""), texts[new])
        if added.strip():
            result.append((sha, path, added))
    return result


def _without_allow_marker(text: str) -> str:
    """Return text without the comment that makes gitleaks skip a line."""
    while _ALLOW_MARKER in text:
        text = text.replace(_ALLOW_MARKER, "")
    return text


def scan_texts(
    gitleaks: Gitleaks,
    work: Path,
    messages: Iterable[Commit],
    pr: PullRequest | None,
    files: Iterable[tuple[str, str, str]],
) -> list[Finding]:
    """Scan commit messages, the pull request text and history files written out as text."""
    entries = [
        (f"messages/{commit.sha}", commit.message, Finding("", 0, commit.sha))
        for commit in messages
    ]
    if pr is not None:
        entries.append(("pull-request/title", pr.title, Finding("", 0, field="title")))
        entries.append(("pull-request/body", pr.body, Finding("", 0, field="body")))
    entries += [
        (f"files/{index}", text, Finding("", 0, sha, path))
        for index, (sha, path, text) in enumerate(files)
    ]
    texts = work / "texts"
    written = 0
    for relative, text, _ in entries:
        # gitleaks skips, without saying so, a file whose name contains an
        # archive extension such as .br or .zip, or whose content starts like
        # a PDF, an executable or another binary format. So the names are
        # generated, each text starts with a line feed, and the scan must
        # have read every byte.
        data = b"\n" + _without_allow_marker(text).encode("utf-8", errors="replace")
        target = texts / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        written += len(data)
    report, log = gitleaks.run("dir", str(texts))
    scanned = _BYTES_SCANNED.search(log)
    if not scanned or int(scanned.group(1)) < written:
        raise CheckError(
            "gitleaks skipped some of the commit messages, pull request text and files"
            " given to it, so they were not checked."
        )
    sources = {relative: source for relative, _, source in entries}
    findings = []
    for item in report:
        source = sources[PurePosixPath(item["File"]).relative_to(texts).as_posix()]
        # The line feed at the start is line 1.
        line = item["StartLine"] - 1
        findings.append(Finding(item["RuleID"], line, source.commit, source.path, source.field))
    return findings


def parse_ignore(text: str) -> tuple[set[str], list[int]]:
    """Return the fingerprints listed one per line, and the numbers of malformed lines.

    Blank lines and lines starting with # are skipped.
    """
    fingerprints = set()
    malformed = []
    for number, raw in enumerate(text.splitlines(), start=1):
        entry = raw.strip()
        if not entry or entry.startswith("#"):
            continue
        if _FINGERPRINT.fullmatch(entry):
            fingerprints.add(entry)
        else:
            malformed.append(number)
    return fingerprints, malformed


def _shown(fingerprint: str, denylist: Denylist) -> str:
    """Return a fingerprint with the denylisted parts of its path redacted."""
    match = _FINGERPRINT.fullmatch(fingerprint)
    if match is None or not denylist.matches(match.group(2)):
        return fingerprint
    sha, path, rule, line = match.groups()
    return f"{sha}:{denylist.redact_path(path)}:{rule}:{line}"


def _report_finding(finding: Finding, advice: str, denylist: Denylist, reporter: Reporter) -> None:
    """Report a finding, without the denylisted parts of its path."""
    rule = f"possible secret ({finding.rule})"
    if finding.field:
        # The pull request text is not in the history, so it has no
        # fingerprint and cannot be ignored.
        reporter.error(
            f"Pull request {finding.field}, line {finding.line}: {rule}. "
            "Edit it out, then revoke it and tell a maintainer."
        )
        return
    where = f"Commit {finding.commit[:12]}: "
    annotated = None
    if not finding.path:
        where += f"message line {finding.line}"
    elif denylist.matches(finding.path):
        where += f"{denylist.redact_path(finding.path)}:{finding.line}"
    else:
        where += f"{finding.path}:{finding.line}"
        annotated = finding.path
    reporter.error(
        f"{where}: {rule}. {advice} Fingerprint: {_shown(finding.fingerprint, denylist)}",
        annotated,
        finding.line,
    )


def report(
    findings: Iterable[Finding],
    ignore: set[str],
    ignorable: Callable[[str], bool],
    denylist: Denylist,
    reporter: Reporter,
) -> None:
    """Report the findings, except the listed false positives of ignorable commits."""
    listed = set()
    for finding in findings:
        advice = "Revoke it and tell a maintainer."
        if finding.fingerprint in ignore:
            listed.add(finding.fingerprint)
            if ignorable(finding.commit):
                shown = _shown(finding.fingerprint, denylist)
                reporter.warning(f"Known false positive ignored by secrets-ignore: {shown}")
                continue
            advice += " secrets-ignore only applies to commits already on the base branch."
        _report_finding(finding, advice, denylist, reporter)
    for fingerprint in sorted(ignore - listed):
        shown = _shown(fingerprint, denylist)
        reporter.warning(f"secrets-ignore lists {shown}, which matches no finding.")


def _is_ancestor(root: Path, commit: str, descendant: str) -> bool:
    try:
        git("merge-base", "--is-ancestor", commit, descendant, cwd=root)
    except subprocess.CalledProcessError:
        return False
    return True


def main(argv: list[str] | None = None) -> int:
    """Run the secret scan from the command line."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--config", type=Path, required=True, help="gitleaks configuration file")
    parser.add_argument(
        "--ignore", default="", help="fingerprints of known false positives, one per line"
    )
    parser.add_argument("--gitleaks", default="gitleaks", help="gitleaks executable")
    args = parser.parse_args(argv)

    # The denylist only hides findings that would show a denylisted term.
    try:
        denylist = Denylist("\n".join(denylist_sources(os.environ)))
    except CheckError as err:
        return fail(str(err))
    reporter = Reporter("Secrets")
    event = load_event()
    pr = pull_request(event)
    tip = history_tip(event)
    ignore, malformed = parse_ignore(args.ignore)
    for number in malformed:
        reporter.error(f"secrets-ignore line {number} is not a commit:path:rule:line fingerprint.")
    try:
        require_full_history(args.root)
        try:
            git("cat-file", "-e", f"{tip}^{{commit}}", cwd=args.root)
        except subprocess.CalledProcessError:
            raise CheckError(f"The commit to scan, {tip}, is not in the checkout.") from None
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            gitleaks = Gitleaks(args.gitleaks, args.config.resolve(), work, denylist)
            findings = scan_history(gitleaks, args.root, tip)
            findings += scan_texts(
                gitleaks, work, commits(args.root, [tip]), pr, unreadable_files(args.root, tip)
            )
    except (CheckError, subprocess.CalledProcessError) as err:
        return fail(str(err))
    # In a pull request, only the commits already on the base branch can be
    # ignored, so that a pull request cannot hide a secret that it adds.
    base = event["pull_request"]["base"]["sha"] if pr is not None else tip
    report(findings, ignore, lambda sha: _is_ancestor(args.root, sha, base), denylist, reporter)
    return reporter.finish()


if __name__ == "__main__":
    sys.exit(main())
