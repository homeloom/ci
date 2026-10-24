"""Scan the history, the commit messages and the pull request text for secrets.

gitleaks reads the diff of every commit in the history of the scanned
commit, with the rules of the action's own configuration. It runs from an
empty directory on the git directory, so a .gitleaks.toml or .gitleaksignore
in the repository has no effect. Commit messages, the pull request title and
body, and the files of the history that gitleaks cannot read in a diff
(UTF-16 or UTF-32 text, paths ending with a backslash) are written to a
temporary directory and scanned there with the same rules.

Findings name the commit, file, rule and line, never the secret. A known
false positive that is already in the history of the base branch can be
ignored by listing its fingerprint; nothing in the repository content can
hide a finding.
"""

from __future__ import annotations

import argparse
import codecs
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
    MAX_SCAN_BYTES,
    CheckError,
    Commit,
    PullRequest,
    Reporter,
    commits,
    decode_text,
    fail,
    git,
    history_tip,
    load_event,
    pull_request,
    require_full_history,
)
from ci_checks.privacy import Denylist

# gitleaks passes these to `git log` after splitting them on spaces. A merge
# is diffed against its first parent, so that what the merge itself adds (a
# conflict resolution, a file added before committing the merge) is scanned
# once; -m would report each of those lines once per parent. --text reads
# every file as text, whatever a .gitattributes file of the repository says.
LOG_OPTIONS = "--text --no-textconv --no-ext-diff --diff-merges=first-parent"
_WIDE_BOMS = (codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE, codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)
_REGULAR_FILE = frozenset({"100644", "100755"})
_RECORD = "\x1e"
# gitleaks exits with 0 when git fails, and only says so in its log.
_LOG_ERROR = re.compile(r"^\S+ (?:ERR|FTL) ")
_COMMITS_SCANNED = re.compile(r" INF (\d+) commits scanned")
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


def history_files(root: Path, tip: str) -> list[tuple[str, str, str]]:
    """Return (commit, path, blob) for each file content written in the history.

    Each content comes with the first commit that wrote it at that path: a
    commit comes after its parents. A merge counts with what differs from its
    first parent, as in the gitleaks scan.
    """
    output = git(
        "log",
        "-z",
        "--reverse",
        "--topo-order",
        "--raw",
        "--no-abbrev",
        "--no-renames",
        "--diff-merges=first-parent",
        f"--format={_RECORD}%H",
        tip,
        "--",
        cwd=root,
    )
    result = []
    seen = set()
    sha = ""
    tokens = iter(output.split("\0"))
    for token in tokens:
        token = token.lstrip("\n")
        if token.startswith(_RECORD):
            sha = token[1:]
        elif token.startswith(":"):
            # ":<old mode> <new mode> <old blob> <new blob> <status>", then the path.
            _, mode, _, blob, _ = token[1:].split(" ")
            path = next(tokens)
            if mode in _REGULAR_FILE and (blob, path) not in seen:
                seen.add((blob, path))
                result.append((sha, path, blob))
    return result


def _read_blobs(root: Path, blobs: list[str]) -> Iterator[tuple[str, bytes]]:
    """Yield the content of each blob of at most MAX_SCAN_BYTES, one at a time.

    The history holds every version of every file, lock files included, so
    the contents are not all loaded at once.
    """
    request = "".join(f"{blob}\n" for blob in blobs).encode()
    checked = subprocess.run(
        ["git", "cat-file", "--batch-check"],
        cwd=root,
        input=request,
        capture_output=True,
        check=True,
    ).stdout.decode()
    small = [
        fields[0]
        for fields in map(str.split, checked.splitlines())
        if len(fields) == 3 and fields[1] == "blob" and int(fields[2]) <= MAX_SCAN_BYTES
    ]
    with subprocess.Popen(
        ["git", "cat-file", "--batch"], cwd=root, stdin=subprocess.PIPE, stdout=subprocess.PIPE
    ) as process:
        for blob in small:
            process.stdin.write(f"{blob}\n".encode())
            process.stdin.flush()
            size = int(process.stdout.readline().split()[2])
            yield blob, process.stdout.read(size + 1)[:size]
        process.stdin.close()


def unreadable_files(root: Path, tip: str) -> list[tuple[str, str, str]]:
    """Return (commit, path, text) for the history files that gitleaks cannot read.

    Git diffs UTF-16 and UTF-32 text as binary, and gitleaks 8.30.1 drops
    the diff of a path that ends with a backslash.
    """
    files = history_files(root, tip)
    backslash = {blob for _, path, blob in files if path.endswith("\\")}
    texts: dict[str, str] = {}
    wide = set()
    for blob, data in _read_blobs(root, sorted({blob for _, _, blob in files})):
        is_wide = data.startswith(_WIDE_BOMS)
        if is_wide or blob in backslash:
            text = decode_text(data)
            if text is not None:
                texts[blob] = text
                if is_wide:
                    wide.add(blob)
    return [
        (sha, path, texts[blob])
        for sha, path, blob in files
        if blob in texts and (blob in wide or path.endswith("\\"))
    ]


def _safe_path(path: str) -> str:
    """Return a relative path to write a history file to, keeping its name when safe."""
    parts = PurePosixPath(path).parts
    if not parts or path.startswith("/") or any(part in {".", ".."} for part in parts):
        return "file"
    return path


def scan_texts(
    gitleaks: Gitleaks,
    work: Path,
    messages: Iterable[Commit],
    pr: PullRequest | None,
    files: Iterable[tuple[str, str, str]],
) -> list[Finding]:
    """Scan commit messages, the pull request text and history files written out as text."""
    texts = work / "texts"
    sources: dict[str, Finding] = {}

    def add(relative: str, text: str, source: Finding) -> None:
        target = texts / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        sources[relative] = source

    for commit in messages:
        add(f"messages/{commit.sha}", commit.message, Finding("", 0, commit.sha))
    if pr is not None:
        add("pull-request/title", pr.title, Finding("", 0, field="title"))
        add("pull-request/body", pr.body, Finding("", 0, field="body"))
    for index, (sha, path, text) in enumerate(files):
        add(f"files/{index}/{_safe_path(path)}", text, Finding("", 0, sha, path))
    report, _ = gitleaks.run("dir", str(texts))
    findings = []
    for item in report:
        source = sources[PurePosixPath(item["File"]).relative_to(texts).as_posix()]
        findings.append(
            Finding(item["RuleID"], item["StartLine"], source.commit, source.path, source.field)
        )
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

    denylist = Denylist(os.environ.get("PRIVACY_DENYLIST", ""))
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
