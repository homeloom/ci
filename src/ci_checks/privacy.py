"""Look for personal data in files, commit history and pull request text.

Two kinds of checks run:

* Generic patterns: private IP addresses, e-mail addresses that are not
  noreply, phone numbers, URLs outside an allowlist, home directory paths,
  MAC addresses, Zigbee and Thread device addresses, and geographic
  coordinates. A line can opt out of one category with a
  `ci-allow: <category>` comment, and paths can be excluded with globs.
* A denylist of terms read from the PRIVACY_DENYLIST environment variable,
  one term per line. It applies everywhere and cannot be opted out of.

What is scanned:

* every tracked file and file path of the checked out tree;
* every line added by the commits of the pull request or push, including
  lines that a later commit removes, because those commits stay reachable;
* the author, committer and message of every commit in the history;
* the pull request title, body and branch name.

Findings only report where something was found, never the matched text,
so that the log does not repeat the data it is protecting.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import sys
import unicodedata
from collections.abc import Iterable, Iterator
from pathlib import Path, PurePosixPath

from ci_checks._common import (
    MAX_SCAN_BYTES,
    Addition,
    CheckError,
    Commit,
    PullRequest,
    Reporter,
    additions,
    allowed_by_pragma,
    commits,
    fail,
    history_tip,
    load_event,
    matches_any,
    new_commit_range,
    pull_request,
    read_bytes,
    read_text,
    require_full_history,
    split_list,
    tracked_files,
)

DEFAULT_ALLOWED_DOMAINS = (
    "astral.sh",
    "conventionalcommits.org",
    "github.com",
    "githubusercontent.com",
    "hacs.xyz",
    "home-assistant.io",
    "json-schema.org",
    "keepachangelog.com",
    "opensource.org",
    "pypi.org",
    "python.org",
    "pythonhosted.org",
    "schemastore.org",
    "semver.org",
    "shields.io",
    "spdx.org",
    "w3.org",
)
# Names reserved for documentation and testing (RFC 2606, RFC 6761) and the
# default local name of a fresh Home Assistant install.
RESERVED_DOMAINS = (
    "example.com",
    "example.net",
    "example.org",
    "example",
    "invalid",
    "localhost",
    "test",
    "homeassistant.local",
)
NOREPLY_EMAIL_DOMAINS = ("users.noreply.github.com",)
PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(net)
    for net in (
        "10.0.0.0/8",  # ci-allow: private-ip
        "100.64.0.0/10",  # ci-allow: private-ip
        "169.254.0.0/16",  # ci-allow: private-ip
        "172.16.0.0/12",  # ci-allow: private-ip
        "192.168.0.0/16",  # ci-allow: private-ip
        "fc00::/7",
    )
)
# Hardware addresses that are obviously placeholders.
PLACEHOLDER_HEX = {
    "0011223344556677",
    "001122334455",
    "0123456789ab",
    "0123456789abcdef",
    "112233445566",
    "1122334455667788",
    "123456789abc",
    "1234567890ab",
    "aabbccddeeff",
    "aabbccddeeff0011",
}
# Coordinates used by the Home Assistant test harness.
PLACEHOLDER_COORDINATES = {"32.87336", "-117.22743", "0.0", "0.00", "0.000"}
HOME_DIRECTORY_PLACEHOLDERS = {
    "admin",
    "app",
    "codespace",
    "default",
    "example",
    "ha",
    "homeassistant",
    "me",
    "name",
    "node",
    "pi",
    "public",
    "root",
    "runner",
    "ubuntu",
    "user",
    "username",
    "vscode",
    "you",
}
LICENSE_PREFIXES = ("LICENSE", "LICENCE", "COPYING", "NOTICE")

_IPV4 = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?!\w|\.\d)")
_IPV6_ULA = re.compile(r"(?<![\w:])(f[cd][0-9a-f]{2}:[0-9a-f:]*[0-9a-f])(?![\w:])", re.IGNORECASE)
_EMAIL = re.compile(
    r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b"
)
_URL = re.compile(r"https?://(?:[^\s/@\"'<>]*@)?(\[[0-9A-Fa-f:.]*\]|[A-Za-z0-9.-]*)", re.IGNORECASE)
_PHONE_INTERNATIONAL = re.compile(r"(?<![\w+])\+\d{1,3}(?:[ .-]?\(?\d{1,4}\)?){2,6}(?![\w])")
_PHONE_NATIONAL = re.compile(r"(?<![\w.])(?:0[1-9](?:[ .-]\d{2}){4}|0[67]\d{8})(?![\w.])")
_HOME_PATH = re.compile(
    r"(?<![\w.~%-])(?:/home|/Users|[A-Za-z]:\\{1,2}Users)[/\\]{1,2}([A-Za-z0-9._-]+)"
)
_MAC = re.compile(r"(?<![0-9A-Fa-f:-])((?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})(?![0-9A-Fa-f:-])")
_EUI64 = re.compile(r"(?<![\w:])(0x[0-9A-Fa-f]{16}|(?:[0-9A-Fa-f]{2}:){7}[0-9A-Fa-f]{2})(?![\w:])")
_COORDINATE = re.compile(
    r"\b(?:lat|latitude|lon|lng|long|longitude)[\"']?\s*[:=]\s*[\"']?(-?\d{1,3}\.\d{3,})",
    re.IGNORECASE,
)
_NOREPLY_LOCAL = re.compile(
    r"^(?:[\w.+-]*[._+-])?(?:no-?reply|do-?not-?reply)(?:[._+-][\w.+-]*)?$", re.IGNORECASE
)

CATEGORIES = (
    "private-ip",
    "email",
    "phone",
    "url",
    "home-path",
    "mac",
    "device-id",
    "coordinates",
)


def _domain_allowed(host: str, domains: Iterable[str]) -> bool:
    return any(host == domain or host.endswith("." + domain) for domain in domains)


def is_noreply_email(address: str) -> bool:
    """Return whether an e-mail address cannot reach a person."""
    local, _, domain = address.strip().lower().rpartition("@")
    if not local:
        return False
    if _domain_allowed(domain, NOREPLY_EMAIL_DOMAINS + RESERVED_DOMAINS):
        return True
    return bool(_NOREPLY_LOCAL.match(local))


def _is_placeholder_hex(value: str) -> bool:
    digits = re.sub(r"^0x|[:-]", "", value.lower())
    return len(set(digits)) <= 2 or digits in PLACEHOLDER_HEX


def _private_ip(text: str) -> bool:
    candidates = [m.group(1) for m in _IPV4.finditer(text)]
    candidates += [m.group(1) for m in _IPV6_ULA.finditer(text)]
    for candidate in candidates:
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if any(address in network for network in PRIVATE_NETWORKS):
            return True
    return False


def _email(text: str) -> bool:
    for match in _EMAIL.finditer(text):
        if text[match.end() : match.end() + 1] == ":":
            continue  # SSH remote such as git@github.com:owner/repo.
        if not is_noreply_email(match.group(0)):
            return True
    return False


def _phone(text: str) -> bool:
    for match in _PHONE_INTERNATIONAL.finditer(text):
        digits = sum(char.isdigit() for char in match.group(0))
        if 8 <= digits <= 15:
            return True
    return bool(_PHONE_NATIONAL.search(text))


def _url(text: str, allowed_domains: Iterable[str]) -> bool:
    domains = tuple(allowed_domains) + RESERVED_DOMAINS
    for match in _URL.finditer(text):
        host = match.group(1).lower().rstrip(".")
        if not host or host.startswith("["):
            continue  # Template, or IPv6 literal handled by the IP check.
        if "." not in host:
            continue  # Single label such as http://supervisor/ in an app.
        try:
            ipaddress.ip_address(host)
            continue  # IP literal, handled by the IP check.
        except ValueError:
            pass
        if not _domain_allowed(host, domains):
            return True
    return False


def _home_path(text: str) -> bool:
    return any(
        m.group(1).lower() not in HOME_DIRECTORY_PLACEHOLDERS for m in _HOME_PATH.finditer(text)
    )


def _mac(text: str) -> bool:
    for match in _MAC.finditer(text):
        mac = match.group(1).lower().replace("-", ":")
        if _is_placeholder_hex(mac) or mac.startswith("00:00:5e:00:53:"):
            continue  # Placeholder, or the RFC 7042 documentation range.
        return True
    return False


def _device_id(text: str) -> bool:
    return any(not _is_placeholder_hex(m.group(1)) for m in _EUI64.finditer(text))


def _coordinates(text: str) -> bool:
    return any(m.group(1) not in PLACEHOLDER_COORDINATES for m in _COORDINATE.finditer(text))


def generic_findings(text: str, allowed_domains: Iterable[str]) -> list[str]:
    """Return the categories of personal data found in a piece of text."""
    checks = {
        "private-ip": _private_ip,
        "email": _email,
        "phone": _phone,
        "url": lambda value: _url(value, allowed_domains),
        "home-path": _home_path,
        "mac": _mac,
        "device-id": _device_id,
        "coordinates": _coordinates,
    }
    return [name for name, check in checks.items() if check(text)]


# Letters that Unicode does not decompose into a base letter and an accent.
_FOLD = str.maketrans(
    {
        "\u00f8": "o",  # o with stroke
        "\u00e6": "ae",
        "\u0153": "oe",
        "\u0142": "l",  # l with stroke
        "\u0111": "d",  # d with stroke
        "\u00f0": "d",  # eth
        "\u00fe": "th",  # thorn
        "\u0131": "i",  # dotless i
        "\u2018": "'",
        "\u2019": "'",
        "\u02bc": "'",
    }
)


def normalize(text: str) -> str:
    """Fold case, accents and special letters so that spelling variants match."""
    decomposed = unicodedata.normalize("NFKD", text)
    stripped = "".join(char for char in decomposed if not unicodedata.combining(char))
    return stripped.casefold().translate(_FOLD)


class Denylist:
    """Terms that must never appear.

    Matching ignores case and accents, respects word boundaries, and lets
    the words of a term be separated by any punctuation, underscores or line
    breaks, so that "first last" also matches "first_last" and "First-Last".
    """

    def __init__(self, raw: str) -> None:
        terms = []
        for line in raw.splitlines():
            term = line.strip()
            if term and not term.startswith("#"):
                terms.append(term)
        self.terms = terms
        patterns = set()
        for term in terms:
            words = [word for word in re.split(r"[\W_]+", normalize(term)) if word]
            if words:
                patterns.add(r"[\W_]+".join(map(re.escape, words)))
        self._pattern: re.Pattern[str] | None = None
        if patterns:
            alternation = "|".join(sorted(patterns, key=len, reverse=True))
            self._pattern = re.compile(rf"(?<![^\W_])(?:{alternation})(?![^\W_])")

    def __bool__(self) -> bool:
        return self._pattern is not None

    def matches(self, text: str) -> bool:
        """Return whether a piece of text contains a term."""
        return bool(self._pattern and self._pattern.search(normalize(text)))

    def matching_lines(self, text: str) -> list[int]:
        """Return the line numbers where a term starts, terms spanning lines included."""
        if not self._pattern:
            return []
        folded = normalize(text)
        lines = {
            folded.count("\n", 0, match.start()) + 1 for match in self._pattern.finditer(folded)
        }
        return sorted(lines)

    def redact_path(self, path: str) -> str:
        """Return a path with the parts that contain a term replaced."""
        parts = ["[redacted]" if self.matches(part) else part for part in PurePosixPath(path).parts]
        redacted = "/".join(parts)
        return "[redacted path]" if self.matches(redacted) else redacted

    def mask_values(self) -> set[str]:
        """Return the spellings of each term that the runner should mask in logs."""
        values = set()
        for term in self.terms:
            for variant in (term, term.lower(), term.upper(), term.title(), normalize(term)):
                values.update({variant, variant.replace(" ", "_"), variant.replace(" ", "-")})
        return {value for value in values if len(value) >= 3}


def is_license_file(path: str) -> bool:
    """Return whether a path is a license text, which quotes its authors' sites."""
    return PurePosixPath(path).name.upper().startswith(LICENSE_PREFIXES)


class PrivacyCheck:
    """Run the privacy checks and report findings."""

    def __init__(
        self,
        root: Path,
        denylist: Denylist,
        allowed_domains: Iterable[str],
        exclude: Iterable[str],
        reporter: Reporter,
    ) -> None:
        self.root = root
        self.denylist = denylist
        self.allowed_domains = tuple(DEFAULT_ALLOWED_DOMAINS) + tuple(allowed_domains)
        self.exclude = tuple(exclude)
        self.reporter = reporter

    def _generic_applies(self, path: str) -> bool:
        return not matches_any(path, self.exclude) and not is_license_file(path)

    def _location(self, path: str) -> tuple[str, str | None]:
        """Return the path to show and the path to annotate, hiding denylisted parts."""
        if self.denylist.matches(path):
            return self.denylist.redact_path(path), None
        return path, path

    def _report_line(self, path: str, number: int, line: str) -> None:
        shown, annotated = self._location(path)
        for category in generic_findings(line, self.allowed_domains):
            if not allowed_by_pragma(line, category):
                self.reporter.error(
                    f"{shown}:{number}: possible personal data ({category}). Remove it, or "
                    f"add `ci-allow: {category}` to the line if it is not personal.",
                    annotated,
                    number,
                )

    def check_files(self, paths: Iterable[str]) -> None:
        """Check file paths, symbolic link targets and file contents."""
        for path in paths:
            shown, annotated = self._location(path)
            if annotated is None:
                self.reporter.error(f"{shown}: the file path contains a denylisted term.")
            full = self.root / path
            if full.is_symlink():
                self._check_symlink(path, str(full.readlink()))
                continue
            data = read_bytes(full, MAX_SCAN_BYTES)
            if data is None:
                if full.exists():
                    self.reporter.warning(
                        f"{shown}: larger than {MAX_SCAN_BYTES} bytes, not scanned."
                    )
                continue
            for number in self.denylist.matching_lines(data.decode("utf-8", errors="replace")):
                self.reporter.error(f"{shown}:{number}: denylisted term.", annotated, number)
            text = read_text(full)
            if text is None or not self._generic_applies(path):
                continue
            for number, line in enumerate(text.splitlines(), start=1):
                self._report_line(path, number, line)

    def _check_symlink(self, path: str, target: str) -> None:
        shown, annotated = self._location(path)
        if self.denylist.matches(target):
            self.reporter.error(f"{shown}: the link target contains a denylisted term.", annotated)
        if self._generic_applies(path):
            for category in generic_findings(target, self.allowed_domains):
                self.reporter.error(
                    f"{shown}: the link target may contain personal data ({category}).",
                    annotated,
                )

    def check_additions(self, added: Iterable[Addition], bots: set[str]) -> None:
        """Check lines added by new commits, including lines removed later.

        Lines that are still in the file at the same place were already
        checked with the files, so they are not reported twice.
        """
        current: dict[str, list[str]] = {}
        for addition in added:
            if addition.path not in current:
                text = read_text(self.root / addition.path)
                current[addition.path] = text.splitlines() if text is not None else []
            lines = current[addition.path]
            if 0 < addition.line <= len(lines) and lines[addition.line - 1] == addition.text:
                continue
            short = addition.sha[:12]
            shown, _ = self._location(addition.path)
            if self.denylist.matches(addition.path):
                self.reporter.error(f"Commit {short}: a file path contains a denylisted term.")
            if self.denylist.matches(addition.text):
                self.reporter.error(
                    f"Commit {short}: {shown}: an added line has a denylisted term."
                )
            if addition.sha in bots or not self._generic_applies(addition.path):
                continue
            for category in generic_findings(addition.text, self.allowed_domains):
                if not allowed_by_pragma(addition.text, category):
                    self.reporter.error(
                        f"Commit {short}: {shown}: an added line may contain personal "
                        f"data ({category}), even if a later commit removed it."
                    )

    def check_identities(self, history: Iterable[Commit]) -> None:
        """Check authors, committers and messages of the whole history against the denylist."""
        for commit in history:
            identities = (
                ("author", commit.author_name, commit.author_email),
                ("committer", commit.committer_name, commit.committer_email),
            )
            for role, name, email in identities:
                if self.denylist.matches(name) or self.denylist.matches(email):
                    self.reporter.error(
                        f"Commit {commit.short}: {role} contains a denylisted term."
                    )
                if not is_noreply_email(email):
                    self.reporter.error(
                        f"Commit {commit.short}: {role} e-mail is not a noreply address."
                    )
            if self.denylist.matches(commit.message):
                self.reporter.error(f"Commit {commit.short}: message contains a denylisted term.")

    def check_messages(self, new_commits: Iterable[Commit]) -> None:
        """Check the messages of new commits with the generic patterns.

        Bot commits are skipped: their trailers carry service addresses.
        """
        for commit in new_commits:
            if commit.is_bot:
                continue
            for category in generic_findings(commit.message, self.allowed_domains):
                self.reporter.error(
                    f"Commit {commit.short}: message may contain personal data ({category})."
                )

    def check_pull_request(self, pr: PullRequest) -> None:
        """Check the pull request title, body and branch name."""
        fields = (("title", pr.title), ("body", pr.body), ("branch name", pr.head_ref))
        for name, value in fields:
            if self.denylist.matches(value):
                self.reporter.error(f"Pull request {name} contains a denylisted term.")
        texts = [("title", pr.title)]
        if not pr.author_is_bot:
            # Bot bodies quote upstream release notes that the author does not control.
            texts.append(("body", pr.body))
        for name, value in texts:
            for category in generic_findings(value, self.allowed_domains):
                self.reporter.error(f"Pull request {name} may contain personal data ({category}).")


def mask_terms(denylist: Denylist) -> Iterator[str]:
    """Yield the workflow commands that mask each spelling of each term."""
    for value in sorted(denylist.mask_values()):
        yield f"::add-mask::{value}"


def main(argv: list[str] | None = None) -> int:
    """Run the privacy check from the command line."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--allowed-domains", default="", help="extra domains allowed in URLs")
    parser.add_argument("--exclude", default="", help="globs skipped by the generic patterns")
    parser.add_argument(
        "--require-denylist",
        default="true",
        choices=("true", "false"),
        help="fail when PRIVACY_DENYLIST is empty (fork pull requests only warn)",
    )
    args = parser.parse_args(argv)

    reporter = Reporter("Privacy")
    denylist = Denylist(os.environ.get("PRIVACY_DENYLIST", ""))
    for command in mask_terms(denylist):
        print(command)
    event = load_event()
    pr = pull_request(event)
    if not denylist:
        if pr is not None and pr.from_fork:
            reporter.warning(
                "PRIVACY_DENYLIST is not available to forks; the denylist was skipped."
            )
        elif args.require_denylist == "true":
            reporter.error(
                "PRIVACY_DENYLIST is empty. Pass the organization secret to the workflow, "
                "or set require-denylist to false."
            )

    try:
        require_full_history(args.root)
    except CheckError as err:
        return fail(str(err))
    check = PrivacyCheck(
        args.root,
        denylist,
        split_list(args.allowed_domains),
        split_list(args.exclude),
        reporter,
    )
    check.check_files(tracked_files(args.root))
    new_range = new_commit_range(event, args.root)
    new = commits(args.root, new_range)
    check.check_additions(additions(args.root, new_range), {c.sha for c in new if c.is_bot})
    check.check_identities(commits(args.root, [history_tip(event)]))
    check.check_messages(new)
    if pr is not None:
        check.check_pull_request(pr)
    return reporter.finish()


if __name__ == "__main__":
    sys.exit(main())
