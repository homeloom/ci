"""Look for personal data in files, commit history and pull request text.

Two kinds of checks run:

* Generic patterns (private IP addresses, e-mail addresses, phone numbers,
  URLs outside an allowlist, home directory paths, MAC addresses and
  geographic coordinates). A line can opt out of one category with a
  `ci-allow: <category>` comment, and paths can be excluded with globs.
* A denylist of terms read from the PRIVACY_DENYLIST environment variable,
  one term per line. It applies everywhere and cannot be opted out of.

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
from collections.abc import Iterable
from pathlib import Path

from ci_checks._common import (
    Commit,
    PullRequest,
    Reporter,
    allowed_by_pragma,
    commits,
    history_tip,
    load_event,
    matches_any,
    pull_request,
    read_text,
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
# Placeholder MAC addresses commonly used in documentation and tests.
PLACEHOLDER_MACS = {
    "00:00:00:00:00:00",
    "00:11:22:33:44:55",
    "01:23:45:67:89:ab",
    "11:22:33:44:55:66",
    "12:34:56:78:90:ab",
    "aa:bb:cc:dd:ee:ff",
    "ff:ff:ff:ff:ff:ff",
}
# Coordinates used by the Home Assistant test harness.
PLACEHOLDER_COORDINATES = {"32.87336", "-117.22743", "0.0", "0.00", "0.000"}
HOME_DIRECTORY_PLACEHOLDERS = {"runner", "user", "username", "me", "name", "public", "default"}

_IPV4 = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?!\w|\.\d)")
_IPV6_ULA = re.compile(r"(?<![\w:])(f[cd][0-9a-f]{2}:[0-9a-f:]*[0-9a-f])(?![\w:])", re.IGNORECASE)
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})\b")
_URL = re.compile(r"https?://([^\s/?#\"'<>()\[\]{}\\`|]*)", re.IGNORECASE)
_PHONE_INTERNATIONAL = re.compile(r"(?<![\w+])\+\d{1,3}(?:[ .-]?\(?\d{1,4}\)?){2,6}(?![\w])")
_PHONE_NATIONAL = re.compile(r"(?<![\w.])(?:0[1-9](?:[ .-]\d{2}){4}|0[67]\d{8})(?![\w.])")
_HOME_PATH = re.compile(r"(?:/home|/Users|[A-Za-z]:\\{1,2}Users)[/\\]{1,2}([A-Za-z0-9._-]+)")
_MAC = re.compile(r"(?<![0-9A-Fa-f:-])((?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})(?![0-9A-Fa-f:-])")
_COORDINATE = re.compile(
    r"\b(?:lat|latitude|lon|lng|long|longitude)[\"']?\s*[:=]\s*[\"']?(-?\d{1,3}\.\d{3,})",
    re.IGNORECASE,
)
_NOREPLY_LOCAL = re.compile(r"^(?:[\w.+-]*[._+-])?no-?reply(?:[._+-][\w.+-]*)?$", re.IGNORECASE)

CATEGORIES = ("private-ip", "email", "phone", "url", "home-path", "mac", "coordinates")


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
    return any(not is_noreply_email(m.group(0)) for m in _EMAIL.finditer(text))


def _phone(text: str) -> bool:
    for match in _PHONE_INTERNATIONAL.finditer(text):
        digits = sum(char.isdigit() for char in match.group(0))
        if 8 <= digits <= 15:
            return True
    return bool(_PHONE_NATIONAL.search(text))


def _url(text: str, allowed_domains: Iterable[str]) -> bool:
    domains = tuple(allowed_domains) + RESERVED_DOMAINS
    for match in _URL.finditer(text):
        authority = match.group(1).rpartition("@")[2]
        host = authority.lower()
        if host.startswith("["):
            continue  # IPv6 literal, handled by the IP check.
        host = host.split(":", 1)[0].rstrip(".")
        if not host or "$" in host or "%" in host or "*" in host:
            continue  # Placeholder or template.
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
        if mac in PLACEHOLDER_MACS or mac.startswith("00:00:5e:00:53:"):
            continue  # RFC 7042 documentation range.
        return True
    return False


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
        "coordinates": _coordinates,
    }
    return [name for name, check in checks.items() if check(text)]


def normalize(text: str) -> str:
    """Fold case and strip accents so that spelling variants still match."""
    decomposed = unicodedata.normalize("NFKD", text)
    stripped = "".join(char for char in decomposed if not unicodedata.combining(char))
    return stripped.casefold()


class Denylist:
    """Terms that must never appear, matched on word boundaries."""

    def __init__(self, raw: str) -> None:
        terms = []
        for line in raw.splitlines():
            term = line.strip()
            if term and not term.startswith("#"):
                terms.append(term)
        self.terms = terms
        if terms:
            parts = sorted({re.escape(normalize(t)).replace(r"\ ", r"\s+") for t in terms}, key=len)
            alternation = "|".join(reversed(parts))
            self._pattern: re.Pattern[str] | None = re.compile(
                rf"(?<![a-z0-9])(?:{alternation})(?![a-z0-9])"
            )
        else:
            self._pattern = None

    def __bool__(self) -> bool:
        return self._pattern is not None

    def matches(self, text: str) -> bool:
        return bool(self._pattern and self._pattern.search(normalize(text)))


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

    def check_files(self, paths: Iterable[str]) -> None:
        for path in paths:
            if self.denylist.matches(path):
                self.reporter.error("File path contains a denylisted term.", path)
            text = read_text(self.root / path)
            if text is None:
                continue
            generic = not matches_any(path, self.exclude)
            for number, line in enumerate(text.splitlines(), start=1):
                if self.denylist.matches(line):
                    self.reporter.error("Line contains a denylisted term.", path, number)
                if not generic:
                    continue
                for category in generic_findings(line, self.allowed_domains):
                    if not allowed_by_pragma(line, category):
                        self.reporter.error(
                            f"Possible personal data ({category}). Remove it, or add "
                            f"`ci-allow: {category}` to the line if it is not personal.",
                            path,
                            number,
                        )

    def check_commits(self, history: Iterable[Commit]) -> None:
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
            for category in generic_findings(commit.message, self.allowed_domains):
                self.reporter.error(
                    f"Commit {commit.short}: message may contain personal data ({category})."
                )

    def check_pull_request(self, pr: PullRequest) -> None:
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


def mask_terms(denylist: Denylist) -> None:
    """Ask the runner to mask each term in case another tool prints it."""
    for term in denylist.terms:
        print(f"::add-mask::{term}")


def main(argv: list[str] | None = None) -> int:
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
    event = load_event()
    pr = pull_request(event)
    if denylist:
        mask_terms(denylist)
    elif pr is not None and pr.from_fork:
        reporter.warning("PRIVACY_DENYLIST is not available to forks; the denylist was skipped.")
    elif args.require_denylist == "true":
        reporter.error(
            "PRIVACY_DENYLIST is empty. Pass the organization secret to the workflow, "
            "or set require-denylist to false."
        )

    check = PrivacyCheck(
        args.root,
        denylist,
        split_list(args.allowed_domains),
        split_list(args.exclude),
        reporter,
    )
    check.check_files(tracked_files(args.root))
    check.check_commits(commits(args.root, [history_tip(event)]))
    if pr is not None:
        check.check_pull_request(pr)
    return reporter.finish()


if __name__ == "__main__":
    sys.exit(main())
