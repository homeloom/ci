"""Look for personal data in files, commit history and pull request text.

Two kinds of checks run:

* Generic patterns: private IP addresses, global IPv6 addresses, e-mail
  addresses that are not noreply, phone numbers, URLs outside an allowlist,
  home directory paths, MAC addresses, Zigbee and Thread device addresses,
  and geographic coordinates. A line can opt out of one category with a
  `ci-allow: <category>` comment, and paths can be excluded with globs.
* A denylist of terms, one per line, merged from every secret whose name
  starts with PRIVACY_DENYLIST (see ci_checks.denylist.denylist_sources).
  It applies everywhere and cannot be opted out of. GitHub prints the names
  of the secrets in the step headers, with their values masked, so the
  denylists are numbered (PRIVACY_DENYLIST_1, PRIVACY_DENYLIST_2...) and
  their names never say what they hold.

What is scanned:

* every tracked file, file path and symbolic link target of the checkout;
* every file written by the commits of the pull request or push, including
  lines and files that a later commit removes, because those commits stay
  reachable;
* the author, committer and message of every commit in the history;
* the pull request title, body and branch name.

Binary files are checked in their metadata (see ci_checks.metadata) and,
for the denylist, in their readable strings. Findings only report where
something was found, never the matched text, so that the log does not
repeat the data it is protecting.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import sys
from bisect import bisect_right
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from itertools import pairwise
from pathlib import Path, PurePosixPath

from ci_checks._common import (
    GITLINK_MODE,
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
    display_path,
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
from ci_checks.denylist import Denylist, denylist_sources, location
from ci_checks.metadata import read_metadata

DEFAULT_ALLOWED_DOMAINS = (
    "astral.sh",
    "conventionalcommits.org",
    "creativecommons.org",
    "github.com",
    "githubusercontent.com",
    "hacs.xyz",
    "home-assistant.io",
    "inkscape.org",
    "json-schema.org",
    "keepachangelog.com",
    "ns.adobe.com",
    "opensource.org",
    "purl.org",
    "pypi.org",
    "python.org",
    "pythonhosted.org",
    "schemastore.org",
    "semver.org",
    "shields.io",
    "sodipodi.sourceforge.net",
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
# Ranges reserved for documentation (RFC 5737, RFC 3849, RFC 9637).
DOCUMENTATION_NETWORKS = tuple(
    ipaddress.ip_network(net)
    for net in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32", "3fff::/20")
)
# Networks that are the same on every installation: the Home Assistant
# Supervisor network, which apps with ingress must allow.
GENERIC_NETWORKS = (ipaddress.ip_network("172.30.32.0/23"),)
# Addresses that are the same in every network: the start of each range
# above, as in "10.0.0.0/8", the usual router link-local address, the
# Docker default bridge and the Tailscale DNS resolver.
GENERIC_ADDRESSES = frozenset(
    {network.network_address for network in (*PRIVATE_NETWORKS, GLOBAL_IPV6)}
    | {
        ipaddress.ip_address(address)
        for address in ("fd00::", "fe80::1", "172.17.0.1", "100.100.100.100")
    }
)
# Public services whose addresses are the same for everyone.
PUBLIC_RESOLVERS = frozenset(
    ipaddress.ip_address(address)
    for address in (
        "1.0.0.1",
        "1.0.0.2",
        "1.0.0.3",
        "1.1.1.1",
        "1.1.1.2",
        "1.1.1.3",
        "8.8.4.4",
        "8.8.8.8",
        "9.9.9.9",
        "94.140.14.14",
        "94.140.15.15",
        "149.112.112.112",
        "208.67.220.220",
        "208.67.222.222",
        "2001:4860:4860::64",
        "2001:4860:4860::6464",
        "2001:4860:4860::8844",
        "2001:4860:4860::8888",
        "2606:4700:4700::1001",
        "2606:4700:4700::1111",
        "2620:119:35::35",
        "2620:119:53::53",
        "2620:fe::9",
        "2620:fe::fe",
        "2a10:50c0::ad1:ff",
        "2a10:50c0::ad2:ff",
    )
)
# Hardware addresses that are obviously placeholders, and the words that
# placeholders spell in hexadecimal.
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
HEX_WORDS = ("babe", "bead", "beef", "c0de", "cafe", "d00d", "dead", "deaf", "f00d", "face", "feed")
# Telephone blocks reserved for fiction and documentation: France (ARCEP, six
# blocks of 10,000 numbers), North America (555-0100 to 555-0199, after the
# area code) and the United Kingdom (Ofcom, 1,000 numbers in each block).
FICTION_NORTH_AMERICA = ("55501",)
FICTION_PHONE_PREFIXES = (
    "3319900",
    "3326191",
    "3335301",
    "3346571",
    "3353649",
    "3363998",
    "441134960",
    "441154960",
    "441174960",
    "441184960",
    "441214960",
    "441314960",
    "441414960",
    "441514960",
    "441614960",
    "441914980",
    "442079460",
    "447700900",
)
# Hardware address ranges reserved for documentation (RFC 7042).
DOCUMENTATION_MAC = ("00005e0053",)
DOCUMENTATION_EUI64 = ("00005eef10",)
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
    "linuxbrew",
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
# The last label of a file name such as icon@2x.png, which looks like an
# e-mail address.
FILE_EXTENSIONS = frozenset(
    {"avif", "bmp", "gif", "heic", "ico", "jpeg", "jpg", "mov", "mp4", "pdf", "png", "svg"}
    | {"tif", "tiff", "webm", "webp"}
)
# Metadata categories: URLs are left out, because metadata formats name
# their schemas with URLs.
METADATA_CATEGORIES = (
    "private-ip",
    "public-ip",
    "email",
    "phone",
    "home-path",
    "mac",
    "device-id",
    "coordinates",
)
DENYLIST = "denylist"
# Lines of context scanned around added lines, so that a term or a pair of
# coordinates spread over several lines is still found.
CONTEXT_LINES = 5
LFS_POINTER = b"version https://git-lfs.github.com/spec/v1\n"
# License texts quote their authors' sites: LICENSE, LICENSE.md,
# LICENSE-APACHE, COPYING.LESSER, NOTICE.txt and the like.
_LICENSE_FILE = re.compile(
    r"^(?i:licen[cs]e|copying|notice)(?:[-.][A-Z0-9][A-Za-z0-9.-]*)?(?:\.(?:md|rst|txt))?$"
)

_IPV4 = re.compile(r"(?<![A-Za-z0-9.])(\d{1,3}(?:\.\d{1,3}){3})(?![A-Za-z0-9]|\.\d)")
_IPV6 = re.compile(
    r"(?<![A-Za-z0-9:.%])([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})(?![A-Za-z0-9:])"
)
_EMAIL = re.compile(
    r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@(?:[^\W_]|-)+(?:\.(?:[^\W_]|-)+)*\.[^\W\d_]{2,}\b"
)
_URL = re.compile(r"\b([A-Za-z][A-Za-z0-9+.-]{0,15})://(?:[^\s/@\"'<>]*@)?(\[[\w:.%]*\]|[\w.-]*)")
# Separators between the digits of a phone number, including the no-break
# spaces that word processors insert.
_SEP = "[ .\\-\N{NO-BREAK SPACE}\N{NARROW NO-BREAK SPACE}\N{THIN SPACE}]"
# The runs of digits and separators are bounded, so that a long line of
# digits cannot make the search backtrack; digit counts are checked after.
_PHONE_INTERNATIONAL = re.compile(
    rf"(?<![\w+])(?:\+[1-9][\d(){_SEP[1:-1]}]{{6,22}}|00[1-9]\d{{0,2}}{_SEP}[\d(){_SEP[1:-1]}]{{5,20}})"
    r"\d(?!\w)"
)
# French numbers, in groups of two digits or written together. A group run
# that goes on, as in a byte dump or a MAC address, is not a number.
_PHONE_NATIONAL = re.compile(
    rf"(?<!\w)(?<!\d\.)(?<![0-9A-Fa-f]{{2}}{_SEP})"
    rf"(?:0[1-9](?:{_SEP}\d{{2}}){{4}}(?!{_SEP}[0-9A-Fa-f]{{2}}(?![0-9A-Za-z]))|0[1-9]\d{{8}})"
    r"(?!\w|\.\d)"
)
_PHONE_NORTH_AMERICA = re.compile(r"(?<![\w)])\(\d{3}\)[ \N{NO-BREAK SPACE}]?\d{3}-\d{4}(?![\w-])")
_HOME_PATH = re.compile(
    r"(?<![\w.~%-])"
    r"(?:/home|/Users|/var/home|/run/media|/mnt/[A-Za-z]/(?i:users)"
    r"|[A-Za-z](?::|%3[Aa])(?:\\{1,2}|/)(?i:users)"
    r"|\\{2,4}wsl(?:\.localhost|\$)\\{1,2}[^\\/\s]+\\{1,2}home)"
    r"[/\\]{1,2}([\w.-]+)"
)
# Groups of two hex digits separated by colons or hyphens, as MAC addresses
# (six groups) and EUI-64 device addresses (eight groups) are written.
_HEX_RUN = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2})+(?![0-9A-Fa-f])")
_MAC_DOTTED = re.compile(
    r"(?<![0-9A-Fa-f.])([0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4})(?![0-9A-Fa-f.])"
)
# A key name starts a word, or a camel case part such as the "Mac" of
# "wifiMac".
_KEY_START = r"(?:(?<![A-Za-z])|(?<=[a-z])(?=[A-Z]))"
_KEY_VALUE = r"[\"']?\s*[:=]\s*[\"']?"
# Hex digits without separators are an address only next to a key that says so.
_MAC_BARE = re.compile(
    _KEY_START
    + r"(?i:mac|bssid|(?:mac|ble|bt|bd)_?addr(?:ess)?)"
    + _KEY_VALUE
    + r"([0-9A-Fa-f]{12})(?![0-9A-Fa-f])"
)
_EUI64 = re.compile(r"(?<![0-9A-Za-z:])0x([0-9A-Fa-f]{16})(?![0-9A-Fa-f:])")
_EUI64_BARE = re.compile(
    _KEY_START
    + r"(?i:ieee(?:_?addr(?:ess)?)?|ext(?:ended)?_?addr(?:ess)?|eui_?64)"
    + _KEY_VALUE
    + r"(?:0x)?([0-9A-Fa-f]{16})(?![0-9A-Fa-f])"
)
_COORDINATE = re.compile(
    _KEY_START
    + r"(?i:lat|latitude|lon|lng|long|longitude)(?![a-z])"
    + _KEY_VALUE
    + r"(-?\d{1,3}\.\d{3,})"
)
_COORDINATE_PAIR = re.compile(r"[\[(]\s*(-?\d{1,3}\.\d{5,})\s*,\s*(-?\d{1,3}\.\d{5,})\s*[\])]")
# A pair written in a sentence, as map applications copy it, but not a
# number in a longer list.
_COORDINATE_TEXT = re.compile(
    r"(?<![\w.,:-])(?<!, )(-?\d{1,3}\.\d{5,}), (-?\d{1,3}\.\d{5,})(?![\w.]|, ?-?\d)"
)
_GEO_URI = re.compile(r"\bgeo:(-?\d{1,2}(?:\.\d+)?),(-?\d{1,3}(?:\.\d+)?)")
_SVG_TRANSFORM = re.compile(r"(?:matrix|rotate|scale|skewX|skewY|translate)\s*\(?\s*$")
_NOREPLY_LOCAL = re.compile(r"^(?:no-?reply|do-?not-?reply)$", re.IGNORECASE)

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
Span = tuple[int, int]


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
        if len(octets) != 4 or not all(octet.isascii() and octet.isdigit() for octet in octets):
            return None
        value = ".".join(str(int(octet)) for octet in octets)  # Drop leading zeros.
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _in_any(
    address: IPAddress, networks: Iterable[ipaddress.IPv4Network | ipaddress.IPv6Network]
) -> bool:
    return any(address in network for network in networks)


def _is_generic(address: IPAddress) -> bool:
    return address in GENERIC_ADDRESSES or _in_any(address, GENERIC_NETWORKS)


def _is_personal_public(address: IPAddress) -> bool:
    return (
        address.is_global
        and not address.is_multicast
        and address not in PUBLIC_RESOLVERS
        and not _is_generic(address)
        and not _in_any(address, DOCUMENTATION_NETWORKS)
    )


def _private_ip(text: str, _allowed: tuple[str, ...]) -> Iterator[Span]:
    for match in (*_IPV4.finditer(text), *_IPV6.finditer(text)):
        address = _parse_ip(match.group(1))
        if address is not None and _in_any(address, PRIVATE_NETWORKS) and not _is_generic(address):
            yield match.span(1)


def _public_ip(text: str, _allowed: tuple[str, ...]) -> Iterator[Span]:
    # Public IPv4 addresses look like version numbers, so only IPv6 is checked
    # here; public addresses of both kinds are also caught in URLs.
    for match in _IPV6.finditer(text):
        address = _parse_ip(match.group(1))
        if address is not None and address in GLOBAL_IPV6 and _is_personal_public(address):
            yield match.span(1)


def _email(text: str, allowed: tuple[str, ...]) -> Iterator[Span]:
    for match in _EMAIL.finditer(text):
        local, _, domain = match.group(0).rpartition("@")
        after = text[match.end() : match.end() + 2]
        if local.lower() == "git" and after[:1] == ":" and after[1:2].strip():
            continue  # SSH remote such as git@github.com:owner/repo.
        if domain.rpartition(".")[2].lower() in FILE_EXTENSIONS:
            continue  # File name such as icon@2x.png.
        if not is_noreply_email(match.group(0), allowed):
            yield match.span()


def _is_placeholder_number(digits: str) -> bool:
    pairs = [int(digits[i : i + 2]) for i in range(len(digits) % 2, len(digits), 2)]
    return (
        len(set(digits)) <= 2
        or any(run in digits for run in ("123456", "234567", "345678", "456789", "567890"))
        or all(second == first + 1 for first, second in pairwise(pairs))
    )


def _is_fiction(international: str) -> bool:
    if international.startswith("1") and len(international) == 11:
        return international[4:].startswith(FICTION_NORTH_AMERICA)
    return international.startswith(FICTION_PHONE_PREFIXES)


def _phone(text: str, _allowed: tuple[str, ...]) -> Iterator[Span]:
    for match in _PHONE_INTERNATIONAL.finditer(text):
        digits = re.sub(r"[^0-9]", "", match.group(0)).removeprefix("00")
        if (
            8 <= len(digits) <= 15
            and not _is_fiction(digits)
            and not _is_placeholder_number(digits)
        ):
            yield match.span()
    for match in _PHONE_NATIONAL.finditer(text):
        digits = re.sub(r"[^0-9]", "", match.group(0))
        if not _is_fiction("33" + digits[1:]) and not _is_placeholder_number(digits):
            yield match.span()
    for match in _PHONE_NORTH_AMERICA.finditer(text):
        digits = re.sub(r"[^0-9]", "", match.group(0))
        if not _is_fiction("1" + digits) and not _is_placeholder_number(digits):
            yield match.span()


def _url(text: str, allowed: tuple[str, ...]) -> Iterator[Span]:
    domains = allowed + RESERVED_DOMAINS
    for match in _URL.finditer(text):
        # Superscript digits are word characters, as in a footnote mark after a host.
        host = match.group(2).lower().rstrip(".")
        while host and host[-1].isdigit() and not host[-1].isdecimal():
            host = host[:-1]
        if not host:
            continue  # A template such as http://{host}/, or a file:/// URL.
        address = _parse_ip(host)
        if address is not None:
            # Private addresses are reported by their own category.
            if not _in_any(address, PRIVATE_NETWORKS) and _is_personal_public(address):
                yield match.span()
            continue
        if host.startswith("[") or "." not in host:
            continue  # Not an address, or a single label such as http://supervisor/.
        if not _domain_allowed(host, domains):
            yield match.span()


def _home_path(text: str, _allowed: tuple[str, ...]) -> Iterator[Span]:
    for match in _HOME_PATH.finditer(text):
        name = match.group(1).lower()
        if name not in HOME_DIRECTORY_PLACEHOLDERS and name.strip("."):
            yield match.span()


def _ascending(sequence: str) -> bool:
    """Return whether a run of five or more hex digits counts up, as in 12345."""
    run = 1
    for first, second in pairwise(sequence):
        run = run + 1 if int(second, 16) == int(first, 16) + 1 else 1
        if run >= 5:
            return True
    return False


def _is_placeholder_hex(digits: str) -> bool:
    """Return whether hex digits look made up, like aa:bb:cc:dd:ee:01 or de:ad:be:ef:ca:fe."""
    digits = digits.lower()
    octets = [digits[i : i + 2] for i in range(0, len(digits) - 1, 2)]
    return (
        len(set(digits)) <= 2
        or digits in PLACEHOLDER_HEX
        or sum(octet[0] == octet[1] for octet in octets) >= 4
        or any(_ascending(part) for part in (digits, digits[0::2], digits[1::2]))
        or sum(word in digits for word in HEX_WORDS) >= 2
        or re.search(r"(.)\1{5}", digits) is not None  # A constant such as a bit mask.
    )


def _is_byte_data(digits: str) -> bool:
    """Return whether most groups are small values, as in protocol frames: 01:03:00:0a."""
    octets = [digits[i : i + 2] for i in range(0, len(digits) - 1, 2)]
    return sum(octet[0] == "0" for octet in octets) * 3 > len(octets) * 2


def _hex_addresses(text: str) -> Iterator[tuple[str, Span, str]]:
    """Yield ("mac" or "device-id", span, digits) for separated hex addresses."""
    for match in _HEX_RUN.finditer(text):
        run, base = match.group(0), match.start()
        separators = run[2::3]
        count = len(run) // 3 + 1
        groups = [run[3 * i : 3 * i + 2] for i in range(count)]
        start = 0
        while start < count - 1:
            end = start
            while end < count - 1 and separators[end] == separators[start]:
                end += 1
            size = end - start + 1
            span = (base + 3 * start, base + 3 * end + 2)
            if size == 6:
                yield "mac", span, "".join(groups[start : end + 1])
            elif size == 8 and separators[start] == ":":
                yield "device-id", span, "".join(groups[start : end + 1])
            start = end


def _real_hex(digits: str) -> bool:
    return not _is_placeholder_hex(digits) and not _is_byte_data(digits)


def _real_hardware(digits: str, documentation: tuple[str, ...]) -> bool:
    return _real_hex(digits) and not digits.lower().startswith(documentation)


def _mac(text: str, _allowed: tuple[str, ...]) -> Iterator[Span]:
    for kind, span, digits in _hex_addresses(text):
        if kind == "mac" and _real_hardware(digits, DOCUMENTATION_MAC):
            yield span
    for pattern in (_MAC_DOTTED, _MAC_BARE):
        for match in pattern.finditer(text):
            if _real_hardware(match.group(1).replace(".", ""), DOCUMENTATION_MAC):
                yield match.span(1)


def _device_id(text: str, _allowed: tuple[str, ...]) -> Iterator[Span]:
    for kind, span, digits in _hex_addresses(text):
        if kind == "device-id" and _real_hardware(digits, DOCUMENTATION_EUI64):
            yield span
    for pattern in (_EUI64, _EUI64_BARE):
        for match in pattern.finditer(text):
            if _real_hardware(match.group(1), DOCUMENTATION_EUI64):
                yield match.span(1)


def _real_coordinate(value: str) -> bool:
    return value not in PLACEHOLDER_COORDINATES and float(value) != 0


def _is_location(first: str, second: str) -> bool:
    x, y = abs(float(first)), abs(float(second))
    if x < 1 and y < 1:
        return False  # Colors, ratios and offsets, not a place near 0, 0.
    in_range = (x <= 90 and y <= 180) or (x <= 180 and y <= 90)  # GeoJSON writes lon, lat.
    return in_range and (_real_coordinate(first) or _real_coordinate(second))


def _coordinates(text: str, _allowed: tuple[str, ...]) -> Iterator[Span]:
    for match in _COORDINATE.finditer(text):
        if _real_coordinate(match.group(1)):
            yield match.span(1)
    for pattern in (_COORDINATE_PAIR, _COORDINATE_TEXT, _GEO_URI):
        for match in pattern.finditer(text):
            if _SVG_TRANSFORM.search(text, max(0, match.start() - 16), match.start()):
                continue  # An SVG transform such as translate(12.34567, 45.67891).
            if _is_location(match.group(1), match.group(2)):
                yield match.span()


_FINDERS: dict[str, Callable[[str, tuple[str, ...]], Iterator[Span]]] = {
    "private-ip": _private_ip,
    "public-ip": _public_ip,
    "email": _email,
    "phone": _phone,
    "url": _url,
    "home-path": _home_path,
    "mac": _mac,
    "device-id": _device_id,
    "coordinates": _coordinates,
}
_ORDER = {name: index for index, name in enumerate((DENYLIST, *_FINDERS))}


def generic_spans(text: str, allowed_domains: Iterable[str]) -> Iterator[tuple[str, Span]]:
    """Yield the category and position of each piece of personal data in a text."""
    allowed = tuple(allowed_domains)
    for name, finder in _FINDERS.items():
        for span in finder(text, allowed):
            yield name, span


def generic_findings(text: str, allowed_domains: Iterable[str]) -> list[str]:
    """Return the categories of personal data found in a piece of text."""
    found = {name for name, _ in generic_spans(text, allowed_domains)}
    return [name for name in _FINDERS if name in found]


@dataclass(frozen=True)
class Finding:
    """Something found in a text: a denylisted term or a generic category."""

    first: int
    last: int
    category: str


def is_license_file(path: str) -> bool:
    """Return whether a path is a license text, which quotes its authors' sites."""
    return bool(_LICENSE_FILE.match(PurePosixPath(path).name))


def is_lfs_pointer(data: bytes) -> bool:
    """Return whether content is a Git LFS pointer, whose real content is stored elsewhere."""
    return len(data) < 1024 and data.startswith(LFS_POINTER)


def _text(data: bytes) -> str | None:
    """Return the text of a file, or None for binary content and documents.

    A PDF file can be plain ASCII, but it writes its text fields with escapes
    that only the metadata reader decodes.
    """
    return None if data.startswith(b"%PDF") else decode_text(data)


def _regions(added: Iterable[int], count: int, context: int) -> list[tuple[int, int]]:
    """Return the line ranges around the added lines, merged when they overlap."""
    regions: list[tuple[int, int]] = []
    for number in sorted(n for n in added if 1 <= n <= count):
        start, end = max(1, number - context), min(count, number + context)
        if regions and start <= regions[-1][1] + 1:
            regions[-1] = (regions[-1][0], end)
        else:
            regions.append((start, end))
    return regions


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
        shown = display_path(path)
        return not matches_any(shown, self.exclude) and not is_license_file(shown)

    def findings(self, text: str, generic: bool) -> list[Finding]:
        """Return what a text holds, by line, after the `ci-allow` comments."""
        found: dict[tuple[int, str], Finding] = {}
        for first, last in self.denylist.spans(text):
            found.setdefault((first, DENYLIST), Finding(first, last, DENYLIST))
        if generic:
            lines = split_lines(text)
            starts = [0, *(match.end() for match in re.finditer("\n", text))]
            for category, (start, end) in generic_spans(text, self.allowed_domains):
                first = bisect_right(starts, start)
                last = bisect_right(starts, max(start, end - 1))
                if any(allowed_by_pragma(line, category) for line in lines[first - 1 : last]):
                    continue
                found.setdefault((first, category), Finding(first, last, category))
        return sorted(found.values(), key=lambda f: (f.first, _ORDER[f.category]))

    def _categories(self, text: str) -> list[str]:
        """Return the generic categories of a message, after its `ci-allow` comments."""
        found = {f.category for f in self.findings(text, generic=True)} - {DENYLIST}
        return sorted(found, key=_ORDER.__getitem__)

    def check_files(self, paths: Iterable[str]) -> None:
        """Check file paths, symbolic link targets and file contents."""
        for path in paths:
            shown, annotated = location(self.denylist, display_path(path))
            if annotated is None:
                self.reporter.error(f"{shown}: the file path contains a denylisted term.")
            full = self.root / path
            if full.is_symlink():
                self._check_symlink(path, str(full.readlink()))
                continue
            if full.is_dir():
                continue  # A submodule, whose URL is checked in .gitmodules.
            data = read_bytes(full, MAX_SCAN_BYTES)
            if data is None:
                if full.exists():
                    self.reporter.warning(
                        f"{shown}: larger than {MAX_SCAN_BYTES} bytes, not scanned."
                    )
                else:
                    self.reporter.error(f"{shown}: tracked but missing from the checkout.")
                continue
            if is_lfs_pointer(data):
                self.reporter.error(
                    f"{shown}: stored with Git LFS, so its content cannot be checked. "
                    "Commit the file to the repository itself.",
                    annotated,
                )
                continue
            text = _text(data)
            generic = self._generic_applies(path)
            if text is None:
                self._check_binary(shown, annotated, data, generic)
                continue
            for finding in self.findings(text, generic):
                number = finding.first
                if finding.category == DENYLIST:
                    self.reporter.error(f"{shown}:{number}: denylisted term.", annotated, number)
                    continue
                self.reporter.error(
                    f"{shown}:{number}: possible personal data ({finding.category}). Remove "
                    f"it, or add `ci-allow: {finding.category}` to the line if it is not "
                    "personal.",
                    annotated,
                    number,
                )

    def _check_binary(self, where: str, annotated: str | None, data: bytes, generic: bool) -> None:
        metadata = read_metadata(data)
        if self.denylist.matches_binary(data) or any(map(self.denylist.matches, metadata.texts)):
            self.reporter.error(f"{where}: binary content contains a denylisted term.", annotated)
        if not generic:
            return
        found = {"coordinates"} if metadata.location else set()
        for text in metadata.texts:
            found.update(generic_findings(text, self.allowed_domains))
        for category in METADATA_CATEGORIES:
            if category in found:
                self.reporter.error(
                    f"{where}: the file metadata may contain personal data ({category}). "
                    "Remove the metadata, for example by exporting the file again without it.",
                    annotated,
                )

    def _check_symlink(self, path: str, target: str) -> None:
        shown, annotated = location(self.denylist, display_path(path))
        target = display_path(target)
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

        Findings that are still in the file at the same place were already
        reported with the files, so they are not reported twice. Commits in
        `exempt` skip the generic patterns but not the denylist.
        """
        written = [change for change in written if change.mode != GITLINK_MODE]
        contents = blob_contents(self.root, (c.blob for c in written if c.blob), MAX_SCAN_BYTES)
        reported_paths = set()
        for change in written:
            if not change.blob:
                continue  # A deletion, which adds nothing.
            short = change.sha[:12]
            shown, _ = location(self.denylist, display_path(change.path))
            if shown != display_path(change.path) and (short, change.path) not in reported_paths:
                reported_paths.add((short, change.path))
                self.reporter.error(f"Commit {short}: a file path contains a denylisted term.")
            where = f"Commit {short}: {shown}"
            if change.blob not in contents:
                self.reporter.error(f"{where}: the content could not be read from the repository.")
                continue
            data = contents[change.blob]
            if data is None:
                self.reporter.warning(f"{where}: larger than {MAX_SCAN_BYTES} bytes, not scanned.")
                continue
            if is_lfs_pointer(data):
                self.reporter.error(
                    f"{where}: stored with Git LFS, so its content cannot be checked."
                )
                continue
            generic = change.sha not in exempt and self._generic_applies(change.path)
            text = _text(data)
            if text is None:
                self._check_binary(where, None, data, generic)
                if b"gitleaks:allow" in data:
                    self.reporter.warning(
                        f"{where}: gitleaks:allow in binary content hides lines from the "
                        "secret scan. Reviewers must confirm that the file holds no secret."
                    )
                continue
            self._check_added(where, change, split_lines(text), generic)

    def _check_added(self, where: str, change: Change, lines: list[str], generic: bool) -> None:
        added = change.added
        current = self._current_lines(change.path)
        context = max(CONTEXT_LINES, self.denylist.longest_term)
        regions = [(1, len(lines))] if added is None else _regions(added, len(lines), context)
        for start, end in regions:
            block = "\n".join(lines[start - 1 : end])
            for finding in self.findings(block, generic):
                span = range(finding.first + start - 1, finding.last + start)
                if added is not None and not any(number in added for number in span):
                    continue
                if all(0 < n <= len(current) and current[n - 1] == lines[n - 1] for n in span):
                    continue
                if finding.category == DENYLIST:
                    self.reporter.error(f"{where}:{span[0]}: an added line has a denylisted term.")
                else:
                    self.reporter.error(
                        f"{where}:{span[0]}: an added line may contain personal data "
                        f"({finding.category}), even if a later commit removed it."
                    )
        for number in range(1, len(lines) + 1) if added is None else sorted(added):
            if 0 < number <= len(lines) and "gitleaks:allow" in lines[number - 1]:
                self.reporter.warning(
                    f"{where}:{number}: gitleaks:allow hides the line from the secret scan. "
                    "Reviewers must confirm that it holds no secret."
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
            for category in self._categories(commit.message):
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
            for category in self._categories(value):
                self.reporter.error(f"Pull request {name} may contain personal data ({category}).")


def mask_terms(denylist: Denylist) -> Iterator[str]:
    """Yield the workflow commands that mask each spelling of each term."""
    for value in sorted(denylist.mask_values()):
        yield f"::add-mask::{value}"


def check_denylist_sources(sources: list[str], pr: PullRequest | None, reporter: Reporter) -> None:
    """Fail when no denylist holds a term, and warn about empty ones.

    Only counts are printed, never a name or a term. GitHub itself prints
    the names of the secrets in the step headers, with their values masked,
    which is why the denylists are numbered rather than named after what
    they hold.
    """
    empty = sum(1 for raw in sources if not Denylist(raw))
    if empty < len(sources):
        if empty:
            reporter.warning(f"{empty} of the {len(sources)} denylist secrets are empty.")
    elif pr is not None and pr.from_fork:
        reporter.error(
            "The denylist secrets are not available to pull requests from forks. Pushing "
            "the branch to this repository runs its workflows with every secret, so a "
            "maintainer first reviews the whole diff: any change under .github/, to the "
            "homeloom/ci pins or to a script that CI runs must be removed or explicitly "
            "approved. Safer: cherry-pick only the reviewed changes outside these paths "
            "onto a fresh branch of this repository."
        )
    else:
        reporter.error(
            "No denylist found. Create at least one organization secret whose name starts "
            "with PRIVACY_DENYLIST, for Actions and for Dependabot, with access to this "
            "repository, and call the workflow with `secrets: inherit`; or set "
            "require-denylist to false."
        )


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
        help="fail when no denylist secret holds a term",
    )
    parser.add_argument(
        "--mask-only", action="store_true", help="only mask the denylisted terms in the job log"
    )
    args = parser.parse_args(argv)

    try:
        sources = denylist_sources(os.environ)
    except CheckError as err:
        return fail(str(err))
    denylist = Denylist("\n".join(sources))
    for command in mask_terms(denylist):
        print(command)
    if args.mask_only:
        return 0

    reporter = Reporter("Privacy")
    print(f"Privacy: {len(sources)} denylist secret(s) read.")
    event = load_event()
    pr = pull_request(event)
    if args.require_denylist == "true":
        check_denylist_sources(sources, pr, reporter)

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
