"""Look for personal data in files, commit history and pull request text.

Two kinds of checks run:

* Generic patterns: private IP addresses, global IPv6 addresses, e-mail
  addresses that are not noreply, phone numbers, URLs outside an allowlist,
  home directory paths, MAC addresses, Zigbee and Thread device addresses,
  and geographic coordinates. A line can opt out of one category with a
  `ci-allow: <category>` comment, and paths can be excluded with globs.
* A denylist of terms read from the PRIVACY_DENYLIST environment variable,
  one term per line. It applies everywhere and cannot be opted out of.

What is scanned:

* every tracked file, file path and symbolic link target of the checkout;
* every file written by the commits of the pull request or push, including
  lines and files that a later commit removes, because those commits stay
  reachable;
* the author, committer and message of every commit in the history;
* the pull request title, body and branch name.

Binary files are only checked against the denylist, in their readable
strings. Findings only report where something was found, never the matched
text, so that the log does not repeat the data it is protecting.
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
    Change,
    CheckError,
    Commit,
    PullRequest,
    Reporter,
    allowed_by_pragma,
    blob_contents,
    changes,
    commits,
    decode_text,
    dependency_bot_commits,
    fail,
    history_tip,
    load_event,
    matches_any,
    new_commit_range,
    pull_request,
    read_bytes,
    require_full_history,
    split_lines,
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
# Addresses that only exist inside a home network.
PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(net)
    for net in (
        "10.0.0.0/8",
        "100.64.0.0/10",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "fc00::/7",
        "fe80::/10",
    )
)
GLOBAL_IPV6 = ipaddress.ip_network("2000::/3")
# Addresses that are the same in every network: the start of each range
# above, as in "10.0.0.0/8", and the usual router link-local address.
GENERIC_ADDRESSES = frozenset(
    {network.network_address for network in (*PRIVATE_NETWORKS, GLOBAL_IPV6)}
    | {ipaddress.ip_address("fd00::"), ipaddress.ip_address("fe80::1")}
)
# Public services whose addresses are the same for everyone.
PUBLIC_RESOLVERS = frozenset(
    ipaddress.ip_address(address)
    for address in (
        "1.0.0.1",
        "1.1.1.1",
        "8.8.4.4",
        "8.8.8.8",
        "9.9.9.9",
        "149.112.112.112",
        "2001:4860:4860::8844",
        "2001:4860:4860::8888",
        "2606:4700:4700::1001",
        "2606:4700:4700::1111",
        "2620:fe::9",
        "2620:fe::fe",
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
PLACEHOLDER_COORDINATES = {"32.87336", "-117.22743"}
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
    "shared",
    "ubuntu",
    "user",
    "username",
    "vscode",
    "you",
}
# License texts quote their authors' sites: LICENSE, LICENSE.md,
# LICENSE-APACHE, COPYING.LESSER, NOTICE.txt and the like.
_LICENSE_FILE = re.compile(
    r"^(?i:licen[cs]e|copying|notice)(?:[-.][A-Z0-9][A-Za-z0-9.-]*)?(?:\.(?:md|rst|txt))?$"
)
# Readable strings of binary content: printable ASCII or UTF-8 letters, or
# printable ASCII in UTF-16. Shorter runs are left out, since random bytes
# form them by chance.
MIN_STRING_LENGTH = 8
_STRING_RUN = re.compile(
    rb"(?:[\t\x20-\x7e]|[\xc2-\xdf][\x80-\xbf]|[\xe0-\xef][\x80-\xbf]{2}){%d,}" % MIN_STRING_LENGTH
)
_UTF16_RUN = re.compile(rb"(?:[\t\x20-\x7e]\x00){%d,}" % MIN_STRING_LENGTH)
_NOT_PHRASE = re.compile(r"[^\w .,'/:-]+|_+")
# Letters a term needs to be looked for anywhere in binary content.
MIN_BINARY_TERM = 5

_IPV4 = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?!\w|\.\d)")
_IPV6 = re.compile(r"(?<![\w:.%])([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})(?![\w:])")
_EMAIL = re.compile(
    r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b"
)
_URL = re.compile(r"\b([A-Za-z][A-Za-z0-9+.-]{0,15})://(?:[^\s/@\"'<>]*@)?(\[[\w:.%]*\]|[\w.-]*)")
# The run of digits and separators is bounded, so that a long line of digits
# cannot make the search backtrack; the digit count is checked afterwards.
_PHONE_INTERNATIONAL = re.compile(r"(?<![\w+])\+\d[\d .()-]{6,22}\d(?!\w)")
_PHONE_NATIONAL = re.compile(r"(?<![\w.])(?:0[1-9](?:[ .-]\d{2}){4}|0[67]\d{8})(?![\w.])")
_HOME_PATH = re.compile(
    r"(?<![\w.~%-])"
    r"(?:/home|/Users|/var/home|/run/media|/Volumes|/mnt/[A-Za-z]/Users"
    r"|[A-Za-z]:(?:\\{1,2}|/)Users)"
    r"[/\\]{1,2}([\w.-]+)"
)
_MAC = re.compile(r"(?<![0-9A-Fa-f:-])((?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})(?![0-9A-Fa-f:-])")
_MAC_DOTTED = re.compile(
    r"(?<![0-9A-Fa-f.])([0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4})(?![0-9A-Fa-f.])"
)
# Twelve hex digits are a MAC address only next to a key that says so.
_MAC_BARE = re.compile(
    r"(?<![A-Za-z])(?:mac|bssid|(?:mac|ble|bt|bd)_?addr(?:ess)?)[\"']?\s*[:=]\s*[\"']?"
    r"([0-9A-Fa-f]{12})(?![0-9A-Fa-f])",
    re.IGNORECASE,
)
_EUI64 = re.compile(r"(?<![\w:])(0x[0-9A-Fa-f]{16}|(?:[0-9A-Fa-f]{2}:){7}[0-9A-Fa-f]{2})(?![\w:])")
_COORDINATE = re.compile(
    r"(?<![A-Za-z])(?:lat|latitude|lon|lng|long|longitude)(?![A-Za-z])[\"']?\s*[:=]\s*[\"']?"
    r"(-?\d{1,3}\.\d{3,})",
    re.IGNORECASE,
)
_COORDINATE_PAIR = re.compile(r"[\[(]\s*(-?\d{1,2}\.\d{5,})\s*,\s*(-?\d{1,3}\.\d{5,})\s*[\])]")
_NOREPLY_LOCAL = re.compile(r"^(?:no-?reply|do-?not-?reply)$", re.IGNORECASE)

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


def _domain_allowed(host: str, domains: Iterable[str]) -> bool:
    return any(host == domain or host.endswith("." + domain) for domain in domains)


def is_noreply_email(
    address: str, allowed_domains: Iterable[str] = DEFAULT_ALLOWED_DOMAINS
) -> bool:
    """Return whether an e-mail address cannot reach a person.

    That is a GitHub noreply address, an address at a reserved domain, or a
    plain noreply mailbox at an allowed domain. A noreply mailbox at another
    domain still names that domain, which may be personal.
    """
    local, _, domain = address.strip().lower().rpartition("@")
    if not local:
        return False
    if _domain_allowed(domain, NOREPLY_EMAIL_DOMAINS + RESERVED_DOMAINS):
        return True
    return bool(_NOREPLY_LOCAL.match(local)) and _domain_allowed(domain, allowed_domains)


def _parse_ip(value: str) -> IPAddress | None:
    value = value.strip("[]").partition("%")[0]
    if ":" not in value:
        octets = value.split(".")
        if len(octets) != 4 or not all(octet.isdigit() for octet in octets):
            return None
        value = ".".join(str(int(octet)) for octet in octets)  # Drop leading zeros.
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _is_private(address: IPAddress) -> bool:
    return any(address in network for network in PRIVATE_NETWORKS)


def _is_personal_public(address: IPAddress) -> bool:
    return (
        address.is_global
        and not address.is_multicast
        and address not in PUBLIC_RESOLVERS
        and address not in GENERIC_ADDRESSES
    )


def _is_placeholder_hex(value: str) -> bool:
    digits = re.sub(r"^0x|[:.-]", "", value.lower())
    return len(set(digits)) <= 2 or digits in PLACEHOLDER_HEX


def _private_ip(text: str) -> bool:
    candidates = [m.group(1) for m in _IPV4.finditer(text)]
    candidates += [m.group(1) for m in _IPV6.finditer(text)]
    for candidate in candidates:
        address = _parse_ip(candidate)
        if address is not None and address not in GENERIC_ADDRESSES and _is_private(address):
            return True
    return False


def _public_ip(text: str) -> bool:
    # Public IPv4 addresses look like version numbers, so only IPv6 is checked
    # here; public addresses of both kinds are also caught in URLs.
    for match in _IPV6.finditer(text):
        address = _parse_ip(match.group(1))
        if address is not None and address in GLOBAL_IPV6 and _is_personal_public(address):
            return True
    return False


def _email(text: str, allowed_domains: Iterable[str]) -> bool:
    for match in _EMAIL.finditer(text):
        if text[match.end() : match.end() + 1] == ":":
            continue  # SSH remote such as git@github.com:owner/repo.
        if not is_noreply_email(match.group(0), allowed_domains):
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
        host = match.group(2).lower().rstrip(".")
        if not host:
            continue  # A template such as http://{host}/, or a file:/// URL.
        address = _parse_ip(host)
        if address is not None:
            # Private addresses are reported by their own category.
            if not _is_private(address) and _is_personal_public(address):
                return True
            continue
        if host.startswith("[") or "." not in host:
            continue  # Not an address, or a single label such as http://supervisor/.
        if not _domain_allowed(host, domains):
            return True
    return False


def _home_path(text: str) -> bool:
    return any(
        m.group(1).lower() not in HOME_DIRECTORY_PLACEHOLDERS for m in _HOME_PATH.finditer(text)
    )


def _mac(text: str) -> bool:
    found = [m.group(1) for m in _MAC.finditer(text)]
    found += [m.group(1) for m in _MAC_DOTTED.finditer(text)]
    found += [m.group(1) for m in _MAC_BARE.finditer(text)]
    for mac in found:
        digits = re.sub(r"[:.-]", "", mac.lower())
        if _is_placeholder_hex(digits) or digits.startswith("00005e0053"):
            continue  # Placeholder, or the RFC 7042 documentation range.
        return True
    return False


def _device_id(text: str) -> bool:
    return any(not _is_placeholder_hex(m.group(1)) for m in _EUI64.finditer(text))


def _real_coordinate(value: str) -> bool:
    return value not in PLACEHOLDER_COORDINATES and float(value) != 0


def _coordinates(text: str) -> bool:
    if any(_real_coordinate(m.group(1)) for m in _COORDINATE.finditer(text)):
        return True
    for match in _COORDINATE_PAIR.finditer(text):
        latitude, longitude = match.groups()
        in_range = abs(float(latitude)) <= 90 and abs(float(longitude)) <= 180
        if in_range and (_real_coordinate(latitude) or _real_coordinate(longitude)):
            return True
    return False


def generic_findings(text: str, allowed_domains: Iterable[str]) -> list[str]:
    """Return the categories of personal data found in a piece of text."""
    checks = {
        "private-ip": _private_ip,
        "public-ip": _public_ip,
        "email": lambda value: _email(value, allowed_domains),
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
    if text.isascii():
        return text.lower()
    decomposed = unicodedata.normalize("NFKD", text)
    stripped = "".join(char for char in decomposed if not unicodedata.combining(char))
    return stripped.casefold().translate(_FOLD)


def _alternation(patterns: Iterable[str]) -> re.Pattern[str] | None:
    """Compile word patterns into one that matches any of them as whole words."""
    if not patterns:
        return None
    alternation = "|".join(sorted(patterns, key=len, reverse=True))
    return re.compile(rf"(?<![^\W_])(?:{alternation})(?![^\W_])")


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
        patterns: dict[str, int] = {}
        for term in terms:
            words = [word for word in re.split(r"[\W_]+", normalize(term)) if word]
            if words:
                patterns[r"[\W_]+".join(map(re.escape, words))] = sum(map(len, words))
        self._pattern = _alternation(patterns)
        # Random bytes spell short words by chance, so in binary content short
        # terms only count inside phrases (see matches_binary).
        self._long_pattern = _alternation(
            {pattern: size for pattern, size in patterns.items() if size >= MIN_BINARY_TERM}
        )

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
        lines: list[int] = []
        line = 1
        position = 0
        for match in self._pattern.finditer(folded):
            line += folded.count("\n", position, match.start())
            position = match.start()
            if not lines or lines[-1] != line:
                lines.append(line)
        return lines

    def matches_binary(self, data: bytes) -> bool:
        """Return whether the readable strings of binary content contain a term.

        Terms of at least MIN_BINARY_TERM letters count anywhere in a string.
        Shorter ones count only in a phrase: a part of a string, between
        symbols, with several words and only letters, digits, spaces and
        common punctuation, such as a title or an author in image metadata.
        """
        if not self._pattern:
            return False
        runs = [run.decode("utf-8", errors="replace") for run in _STRING_RUN.findall(data)]
        runs += [run.decode("utf-16-le") for run in _UTF16_RUN.findall(data)]
        for run in runs:
            folded = normalize(run)
            if self._long_pattern and self._long_pattern.search(folded):
                return True
            for part in _NOT_PHRASE.split(folded):
                phrase = part.strip()
                is_phrase = len(phrase) >= MIN_STRING_LENGTH and " " in phrase
                if is_phrase and self._pattern.search(phrase):
                    return True
        return False

    def redact_path(self, path: str) -> str:
        """Return a path with the parts that contain a term replaced."""
        parts = ["[redacted]" if self.matches(part) else part for part in PurePosixPath(path).parts]
        redacted = "/".join(parts)
        return "[redacted path]" if self.matches(redacted) else redacted

    def mask_values(self) -> set[str]:
        """Return the spellings of each term that the runner should mask in logs."""
        values = set()
        for term in self.terms:
            for base in (term, normalize(term)):
                for cased in (base, base.lower(), base.upper(), base.title()):
                    for separator in (" ", "_", "-", "."):
                        values.add(cased.replace(" ", separator))
        return {value for value in values if len(value) >= 3}


def is_license_file(path: str) -> bool:
    """Return whether a path is a license text, which quotes its authors' sites."""
    return bool(_LICENSE_FILE.match(PurePosixPath(path).name))


def _is_utf8(data: bytes) -> bool:
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


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
        self._current: dict[str, list[str]] = {}

    def _generic_applies(self, path: str) -> bool:
        return not matches_any(path, self.exclude) and not is_license_file(path)

    def _location(self, path: str) -> tuple[str, str | None]:
        """Return the path to show and the path to annotate, hiding denylisted parts."""
        if self.denylist.matches(path):
            return self.denylist.redact_path(path), None
        return path, path

    def _personal_data(self, line: str) -> list[str]:
        return [
            category
            for category in generic_findings(line, self.allowed_domains)
            if not allowed_by_pragma(line, category)
        ]

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
            text = decode_text(data)
            if text is None:
                if self.denylist.matches_binary(data):
                    self.reporter.error(
                        f"{shown}: binary content contains a denylisted term.", annotated
                    )
                continue
            for number in self.denylist.matching_lines(text):
                self.reporter.error(f"{shown}:{number}: denylisted term.", annotated, number)
            # Most files have nothing; looking at the whole text first is faster.
            if not self._generic_applies(path) or not generic_findings(text, self.allowed_domains):
                continue
            for number, line in enumerate(split_lines(text), start=1):
                for category in self._personal_data(line):
                    self.reporter.error(
                        f"{shown}:{number}: possible personal data ({category}). Remove it, or "
                        f"add `ci-allow: {category}` to the line if it is not personal.",
                        annotated,
                        number,
                    )

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

    def _current_lines(self, path: str) -> list[str]:
        if path not in self._current:
            data = read_bytes(self.root / path, MAX_SCAN_BYTES)
            text = decode_text(data) if data is not None else None
            self._current[path] = split_lines(text) if text is not None else []
        return self._current[path]

    def check_changes(self, written: Iterable[Change], exempt: set[str]) -> None:
        """Check the files written by new commits, including content removed later.

        Lines that are still in the file at the same place were already
        checked with the files, so they are not reported twice. Commits in
        `exempt` skip the generic patterns but not the denylist.
        """
        written = list(written)
        blobs = (change.blob for change in written if change.blob)
        contents = blob_contents(self.root, blobs, MAX_SCAN_BYTES)
        reported_paths = set()
        for change in written:
            short = change.sha[:12]
            shown, _ = self._location(change.path)
            if self.denylist.matches(change.path) and (short, change.path) not in reported_paths:
                reported_paths.add((short, change.path))
                self.reporter.error(f"Commit {short}: a file path contains a denylisted term.")
            if not change.blob:
                continue
            data = contents.get(change.blob)
            if data is None:
                self.reporter.warning(
                    f"Commit {short}: {shown}: larger than {MAX_SCAN_BYTES} bytes, not scanned."
                )
                continue
            text = decode_text(data)
            if text is None:
                if self.denylist.matches_binary(data):
                    self.reporter.error(
                        f"Commit {short}: {shown}: binary content contains a denylisted term."
                    )
                continue
            added: Iterable[tuple[int, str]] = change.added
            if not _is_utf8(data):
                # A UTF-16 or UTF-32 diff cannot be read line by line.
                added = enumerate(split_lines(text), start=1)
            generic = change.sha not in exempt and self._generic_applies(change.path)
            self._check_added(short, change.path, shown, added, generic)

    def _check_added(
        self, short: str, path: str, shown: str, added: Iterable[tuple[int, str]], generic: bool
    ) -> None:
        current = self._current_lines(path)
        for number, line in added:
            if 0 < number <= len(current) and current[number - 1] == line:
                continue
            where = f"Commit {short}: {shown}:{number}"
            if self.denylist.matches(line):
                self.reporter.error(f"{where}: an added line has a denylisted term.")
            if "gitleaks:allow" in line:
                self.reporter.warning(
                    f"{where}: gitleaks:allow hides the line from the secret scan. "
                    "Reviewers must confirm that it holds no secret."
                )
            if not generic:
                continue
            for category in self._personal_data(line):
                self.reporter.error(
                    f"{where}: an added line may contain personal data ({category}), "
                    "even if a later commit removed it."
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
                if not is_noreply_email(email, self.allowed_domains):
                    self.reporter.error(
                        f"Commit {commit.short}: {role} e-mail is not a noreply address."
                    )
            if self.denylist.matches(commit.message):
                self.reporter.error(f"Commit {commit.short}: message contains a denylisted term.")

    def check_messages(self, new_commits: Iterable[Commit], exempt: set[str]) -> None:
        """Check the messages of new commits with the generic patterns.

        Commits in `exempt` are skipped: dependency bots quote upstream text
        and carry service addresses in their trailers.
        """
        for commit in new_commits:
            if commit.sha in exempt:
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
        if not pr.is_dependency_bot:
            # Dependency bots quote upstream release notes in the body.
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
        help="fail when PRIVACY_DENYLIST is empty",
    )
    parser.add_argument(
        "--mask-only", action="store_true", help="only mask the denylisted terms in the job log"
    )
    args = parser.parse_args(argv)

    denylist = Denylist(os.environ.get("PRIVACY_DENYLIST", ""))
    for command in mask_terms(denylist):
        print(command)
    if args.mask_only:
        return 0

    reporter = Reporter("Privacy")
    event = load_event()
    pr = pull_request(event)
    if not denylist and args.require_denylist == "true":
        if pr is not None and pr.from_fork:
            reporter.error(
                "PRIVACY_DENYLIST is not available to pull requests from forks. A maintainer "
                "must push the branch to this repository so that the denylist runs."
            )
        else:
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
    exempt = dependency_bot_commits(event, new)
    check.check_changes(changes(args.root, new_range), exempt)
    check.check_identities(commits(args.root, [history_tip(event)]))
    check.check_messages(new, exempt)
    if pr is not None:
        check.check_pull_request(pr)
    return reporter.finish()


if __name__ == "__main__":
    sys.exit(main())
