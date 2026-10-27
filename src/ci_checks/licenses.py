"""Check the repository license and the licenses of runtime dependencies.

The repository must ship a LICENSE file that holds the text of its
license. Runtime dependencies (the `requirements` of Home Assistant
manifests, the requirements.txt of Home Assistant apps, plus any
requirements files given) are installed into a temporary directory with uv, and the license
of every installed distribution, transitive ones included, must be on the
allowed list. A package can be exempted by name when its license has been
reviewed by hand.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from collections.abc import Iterable
from email.parser import HeaderParser
from pathlib import Path

from ci_checks._common import Reporter, fail, split_list

LICENSE_FILES = ("LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING")
# Phrases that the text of each license holds, in lower case with whitespace
# collapsed. The "-or-later" variants share the text of their license.
_GPL2 = ("gnu general public license", "version 2, june 1991")
_GPL3 = ("gnu general public license", "version 3, 29 june 2007")
_LGPL21 = ("gnu lesser general public license", "version 2.1, february 1999")
_LGPL3 = ("gnu lesser general public license", "version 3, 29 june 2007")
_AGPL3 = ("gnu affero general public license", "version 3, 19 november 2007")
LICENSE_FINGERPRINTS = {
    "0BSD": ("permission to use, copy, modify, and/or distribute this software",),
    "AGPL-3.0-only": _AGPL3,
    "AGPL-3.0-or-later": _AGPL3,
    "Apache-2.0": ("apache license", "version 2.0"),
    "BSD-2-Clause": ("redistribution and use in source and binary forms",),
    "BSD-3-Clause": ("redistribution and use in source and binary forms", "neither the name of"),
    "BSL-1.0": ("boost software license - version 1.0",),
    "CC0-1.0": ("cc0 1.0 universal",),
    "GPL-2.0-only": _GPL2,
    "GPL-2.0-or-later": _GPL2,
    "GPL-3.0-only": _GPL3,
    "GPL-3.0-or-later": _GPL3,
    "ISC": ("permission to use, copy, modify, and",),
    "LGPL-2.1-only": _LGPL21,
    "LGPL-2.1-or-later": _LGPL21,
    "LGPL-3.0-only": _LGPL3,
    "LGPL-3.0-or-later": _LGPL3,
    "MIT": ("permission is hereby granted, free of charge",),
    "MIT-0": ("permission is hereby granted, free of charge",),
    "MPL-2.0": ("mozilla public license version 2.0",),
    "Unlicense": ("this is free and unencumbered software released into the public domain",),
    "Zlib": ("altered source versions must be plainly marked as such",),
}
DEFAULT_ALLOWED = frozenset(
    """
    0BSD Apache-2.0 BlueOak-1.0.0 BSD BSD-2-Clause BSD-3-Clause BSL-1.0
    CC0-1.0 CNRI-Python HPND ISC LGPL-2.1-only LGPL-2.1-or-later LGPL-3.0-only
    LGPL-3.0-or-later MIT MIT-0 MIT-CMU MPL-2.0 PSF-2.0 Python-2.0 Unlicense
    Zlib
    """.split()
)
# SPDX license exceptions (license list 3.29.0). Each one only adds
# permissions to the license it follows.
SPDX_EXCEPTIONS = frozenset(
    """
    389-exception Asterisk-exception Asterisk-linking-protocols-exception
    Autoconf-exception-2.0 Autoconf-exception-3.0 Autoconf-exception-generic
    Autoconf-exception-generic-3.0 Autoconf-exception-macro Bison-exception-1.24
    Bison-exception-2.2 Bootloader-exception CGAL-linking-exception Classpath-exception-2.0
    Classpath-exception-2.0-short CLISP-exception-2.0 cryptsetup-OpenSSL-exception
    Digia-Qt-LGPL-exception-1.1 DigiRule-FOSS-exception eCos-exception-2.0
    erlang-otp-linking-exception Fawkes-Runtime-exception FLTK-exception fmt-exception
    Font-exception-2.0 freertos-exception-2.0 GCC-exception-2.0 GCC-exception-2.0-note
    GCC-exception-3.1 Gmsh-exception GNAT-exception GNOME-examples-exception
    GNU-compiler-exception gnu-javamail-exception Google-Patent-WebM
    GPL-3.0-389-ds-base-exception GPL-3.0-interface-exception GPL-3.0-linking-exception
    GPL-3.0-linking-source-exception GPL-CC-1.0 GStreamer-exception-2005
    GStreamer-exception-2008 harbour-exception i2p-gpl-java-exception
    Independent-modules-exception KiCad-libraries-exception kvirc-openssl-exception
    LGPL-3.0-linking-exception libpri-OpenH323-exception Libtool-exception
    Linux-syscall-note LLGPL LLVM-exception LZMA-exception mif-exception mxml-exception
    OCaml-LGPL-linking-exception OCCT-exception-1.0 OpenJDK-assembly-exception-1.0
    openvpn-openssl-exception PCRE2-exception polyparse-exception
    PS-or-PDF-font-exception-20170817 QPL-1.0-INRIA-2004-exception Qt-GPL-exception-1.0
    Qt-LGPL-exception-1.1 Qwt-exception-1.0 romic-exception RRDtool-FLOSS-exception-2.0
    rsync-linking-exception SANE-exception SHL-2.0 SHL-2.1 Simple-Library-Usage-exception
    Spelling-Provider-LGPL-exception sqlitestudio-OpenSSL-exception stunnel-exception
    SWI-exception Swift-exception Texinfo-exception u-boot-exception-2.0 UBDL-exception
    Universal-FOSS-exception-1.0 vsftpd-openssl-exception WxWindows-exception-3.1
    x11vnc-openssl-exception
    """.split()
)
PROPRIETARY = "LicenseRef-Proprietary"
CLASSIFIERS = {
    "Apache Software License": "Apache-2.0",
    "BSD License": "BSD",
    "Blue Oak Model License (BlueOak-1.0.0)": "BlueOak-1.0.0",
    "Boost Software License 1.0 (BSL-1.0)": "BSL-1.0",
    "CC0 1.0 Universal (CC0 1.0) Public Domain Dedication": "CC0-1.0",
    "CMU License (MIT-CMU)": "MIT-CMU",
    "GNU Affero General Public License v3": "AGPL-3.0-only",
    "GNU Affero General Public License v3 or later (AGPLv3+)": "AGPL-3.0-or-later",
    # Without a version, the GNU licenses let the licensee pick any version.
    "GNU General Public License (GPL)": "GPL-1.0-or-later",
    "GNU General Public License v2 (GPLv2)": "GPL-2.0-only",
    "GNU General Public License v2 or later (GPLv2+)": "GPL-2.0-or-later",
    "GNU General Public License v3 (GPLv3)": "GPL-3.0-only",
    "GNU General Public License v3 or later (GPLv3+)": "GPL-3.0-or-later",
    "GNU Lesser General Public License v2 (LGPLv2)": "LGPL-2.1-only",
    "GNU Lesser General Public License v2 or later (LGPLv2+)": "LGPL-2.1-or-later",
    "GNU Lesser General Public License v3 (LGPLv3)": "LGPL-3.0-only",
    "GNU Lesser General Public License v3 or later (LGPLv3+)": "LGPL-3.0-or-later",
    "GNU Library or Lesser General Public License (LGPL)": "LGPL-2.0-or-later",
    "Historical Permission Notice and Disclaimer (HPND)": "HPND",
    "ISC License (ISCL)": "ISC",
    "MIT License": "MIT",
    "MIT No Attribution License (MIT-0)": "MIT-0",
    "Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "Other/Proprietary License": PROPRIETARY,
    "Python License (CNRI Python License)": "CNRI-Python",
    "Python Software Foundation License": "PSF-2.0",
    "The Unlicense (Unlicense)": "Unlicense",
    "Universal Permissive License (UPL)": "UPL-1.0",
    "Zero-Clause BSD (0BSD)": "0BSD",
    "zlib/libpng License": "Zlib",
}
# License classifiers that add no condition to the licenses they come with.
NEUTRAL_CLASSIFIERS = frozenset({"OSI Approved", "DFSG approved", "Public Domain"})
# Unambiguous names of permissive licenses, as normalized by `_name_key`.
FREE_TEXT = {
    "apache": "Apache-2.0",
    "apache 2": "Apache-2.0",
    "apache-2": "Apache-2.0",
    "apache 2.0": "Apache-2.0",
    "apache software": "Apache-2.0",
    "apache software 2.0": "Apache-2.0",
    "bsd": "BSD",
    "2-clause bsd": "BSD-2-Clause",
    "bsd 2-clause": "BSD-2-Clause",
    "simplified bsd": "BSD-2-Clause",
    "3-clause bsd": "BSD-3-Clause",
    "bsd 3-clause": "BSD-3-Clause",
    "modified bsd": "BSD-3-Clause",
    "new bsd": "BSD-3-Clause",
    "revised bsd": "BSD-3-Clause",
    "expat": "MIT",
    "isc": "ISC",
    "mit": "MIT",
    "mpl 2.0": "MPL-2.0",
    "mozilla public 2.0": "MPL-2.0",
    "psf": "PSF-2.0",
    "psfl": "PSF-2.0",
    "python software foundation": "PSF-2.0",
    "unlicense": "Unlicense",
    "universal permissive": "UPL-1.0",
    "universal permissive 1.0": "UPL-1.0",
    "zlib/libpng": "Zlib",
}
# Short names of GNU and Mozilla licenses, as packages write them without a
# classifier. They are translated only when the whole field is one of them.
SHORT_NAMES = {
    "agplv3": "AGPL-3.0-only",
    "agplv3+": "AGPL-3.0-or-later",
    "gplv2": "GPL-2.0-only",
    "gplv2+": "GPL-2.0-or-later",
    "gplv3": "GPL-3.0-only",
    "gplv3+": "GPL-3.0-or-later",
    "lgplv2": "LGPL-2.1-only",
    "lgplv2+": "LGPL-2.1-or-later",
    "lgplv2.1": "LGPL-2.1-only",
    "lgplv2.1+": "LGPL-2.1-or-later",
    "lgplv3": "LGPL-3.0-only",
    "lgplv3+": "LGPL-3.0-or-later",
    "mpl2": "MPL-2.0",
    "mpl 2": "MPL-2.0",
    "mplv2": "MPL-2.0",
    "mozilla public 2": "MPL-2.0",
}
# Phrases of full license texts, compared with whitespace collapsed. A
# single line is never read as a full text, since it is more likely a
# notice about one bundled component.
TEXT_FINGERPRINTS = (
    ("permission is hereby granted, free of charge", "MIT"),
    ("terms and conditions for use, reproduction, and distribution", "Apache-2.0"),
    ("licensed under the apache license, version 2.0", "Apache-2.0"),
    ("redistribution and use in source and binary forms", "BSD"),
)
# Restrictions that some packages add to a permissive license, in free text.
RESTRICTION = re.compile(r"commons[\s_-]*clause|proprietary|non[\s_-]*commercial", re.IGNORECASE)
# GNU licenses, as named in free text and as SPDX license families.
GNU_LICENSE = re.compile(r"gpl|general public", re.IGNORECASE)
GNU_FAMILIES = frozenset({"AGPL", "GPL", "LGPL"})
# Free text naming a restriction or a GNU license is never translated into
# a permissive license, even when it also names one.
RESTRICTIVE_TEXT = re.compile(rf"{RESTRICTION.pattern}|{GNU_LICENSE.pattern}", re.IGNORECASE)
# A PEP 508 requirement starts with a distribution name; anything else may
# be read by uv as an option, a path or a URL. uv also drops a byte order
# mark at the start of the file, which str.strip() keeps.
REQUIREMENT_NAME = re.compile(
    r"\s*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)(?=[\s\[(<>=!~;@]|\Z)"
)
# Home Assistant still accepts "<url>#<requirement>" from custom
# integrations, as in "git+https://example.com/lib.git#lib>=1". The part
# after "#" must then start with a distribution name.
LEGACY_URL_REQUIREMENT = re.compile(r"\s*[A-Za-z][A-Za-z0-9+.-]*://[^\s#]+#(\S+)\s*")
# Names that uv reads as the path of an archive.
ARCHIVE_NAME = re.compile(r"\.(?:whl|zip|tgz|tar(?:\.\w+)?)\Z", re.IGNORECASE)
_OPERATOR = re.compile(r"\s+(AND|OR)\s+", re.IGNORECASE)
_IDENTIFIER = re.compile(r"[A-Za-z0-9.+-]+")
_LICENSE_WORD = re.compile(r"\blicen[cs]e\b", re.IGNORECASE)
_VERSIONED = re.compile(r"(.+)-(\d+(?:\.\d+)*)(-only|-or-later)?")
_OPERATORS = frozenset({"AND", "OR", "WITH", "(", ")"})
_EXCEPTIONS = frozenset(item.lower() for item in SPDX_EXCEPTIONS)
PLATFORM = "x86_64-manylinux_2_28"


def find_license_file(root: Path) -> Path | None:
    """Return the license file at the root of the repository, if any."""
    for name in LICENSE_FILES:
        if (root / name).is_file():
            return root / name
    return None


def normalize_name(name: str) -> str:
    """Normalize a distribution name as described in PEP 503."""
    return re.sub(r"[-_.]+", "-", name).lower()


class _Expression:
    """Evaluate an SPDX license expression against an allowed set."""

    _TOKEN = re.compile(r"\(|\)|[^\s()]+")

    def __init__(self, text: str, allowed: frozenset[str]) -> None:
        self.tokens = self._TOKEN.findall(text)
        self.position = 0
        self.allowed = {item.lower() for item in allowed}
        # The allowed licenses that name a version, as (license, version).
        self.versions = [
            (match[1], _version(match[2]))
            for item in self.allowed
            if (match := _VERSIONED.fullmatch(item))
        ]
        self.identifiers: list[str] = []

    def evaluate(self) -> bool:
        result = self._or()
        if self.position != len(self.tokens):
            raise ValueError("unexpected token")
        return result

    def _peek(self) -> str | None:
        return self.tokens[self.position] if self.position < len(self.tokens) else None

    def _take(self) -> str:
        token = self._peek()
        if token is None:
            raise ValueError("unexpected end")
        self.position += 1
        return token

    def _or(self) -> bool:
        result = self._and()
        while (self._peek() or "").upper() == "OR":
            self._take()
            right = self._and()
            result = result or right
        return result

    def _and(self) -> bool:
        result = self._atom()
        while (self._peek() or "").upper() == "AND":
            self._take()
            right = self._atom()
            result = result and right
        return result

    def _atom(self) -> bool:
        item = self._take()
        if item == "(":
            result = self._or()
            if self._take() != ")":
                raise ValueError("missing parenthesis")
            return result
        if item.upper() in _OPERATORS:
            raise ValueError("unexpected operator")
        self.identifiers.append(item)
        allowed = self._allows(item.lower())
        if (self._peek() or "").upper() == "WITH":
            self._take()
            exception = self._take()
            if exception.upper() in _OPERATORS:
                raise ValueError("missing exception")
            # An SPDX exception only adds permissions. Anything else, such as
            # a LicenseRef, may take some away.
            allowed = allowed and exception.lower() in _EXCEPTIONS
        return allowed

    def _allows(self, name: str) -> bool:
        """Return whether a license identifier, in lower case, is allowed."""
        # Deprecated SPDX forms: "X+" means "X-or-later" and a bare "X" means "X-only".
        candidates = {name, name + "-only"}
        if name.endswith("+"):
            name = name[:-1] + "-or-later"
            candidates.add(name)
        if not candidates.isdisjoint(self.allowed):
            return True
        # "X-2.0-or-later" can be used under version 2.0 or any later version.
        match = _VERSIONED.fullmatch(name)
        if not match or match[3] != "-or-later":
            return False
        minimum = _version(match[2])
        return any(family == match[1] and version >= minimum for family, version in self.versions)


def _version(text: str) -> tuple[int, ...]:
    """Return a version such as "2.1" as numbers, so that versions compare."""
    return tuple(int(part) for part in text.split("."))


def expression_allowed(expression: str, allowed: frozenset[str]) -> bool | None:
    """Return whether an SPDX expression is allowed, or None if it does not parse."""
    try:
        return _Expression(expression, allowed).evaluate()
    except ValueError:
        return None


def license_of(metadata: str) -> str | None:
    """Return the license of a distribution as an SPDX expression, if known.

    License-Expression is authoritative. Otherwise the License field decides
    together with the classifiers it does not account for (see `_refine`).
    When it accounts for none of them, the classifiers decide, unless the
    field names something that they cannot express.
    """
    headers = HeaderParser().parsestr(metadata)
    expression = headers.get("License-Expression")
    if expression:
        return expression.strip()
    text = (headers.get("License") or "").strip()
    declared = _text_license(text)
    classified = {
        spdx
        for classifier in headers.get_all("Classifier") or []
        if (spdx := _classifier_license(classifier.strip()))
    }
    if not classified:
        return declared
    refined = _refine(declared, classified) if declared else None
    if refined:
        return refined
    if "\n" not in text and _unexplained(text, classified):
        # Reported as written: the classifiers cannot express it.
        return text
    identifiers = _license_ids(declared) if declared else []
    if identifiers and all(map(_is_license_id, identifiers)):
        # The field names licenses that the classifiers contradict, so both
        # must be allowed.
        field = f"({declared})" if len(identifiers) > 1 else declared
        return " AND ".join([field, *sorted(classified)])
    # Several classifiers may mean a choice or a combination; assume the
    # stricter combination. Reviewed packages go in the exceptions.
    return " AND ".join(sorted(classified))


def _is_license_id(identifier: str) -> bool:
    """Return whether an identifier of the License field names a license, not loose words.

    It is a known license, a versioned identifier such as BUSL-1.1, or a
    LicenseRef. Words such as "Custom" or "BSD-like" are not.
    """
    known = {*DEFAULT_ALLOWED, *CLASSIFIERS.values(), *FREE_TEXT.values()}
    return (
        identifier.removesuffix("+") in known
        or _VERSIONED.fullmatch(identifier.removesuffix("+")) is not None
        or identifier.startswith("LicenseRef-")
    )


def _classifier_license(classifier: str) -> str | None:
    """Return the SPDX identifier of a classifier, or None if it adds no license condition.

    A license classifier without an SPDX identifier becomes a LicenseRef, so
    that it still counts in the combination instead of being dropped.
    """
    if not classifier.startswith("License :: "):
        return None
    name = classifier.removeprefix("License :: OSI Approved :: ").removeprefix("License :: ")
    if name in NEUTRAL_CLASSIFIERS:
        return None
    return CLASSIFIERS.get(name) or "LicenseRef-" + re.sub(r"[^A-Za-z0-9.]+", "-", name).strip("-")


def _refine(declared: str, classified: set[str]) -> str | None:
    """Combine the License field with the classifiers, if it accounts for any of them.

    The core metadata specification lets the License field name the version
    or the variant of a license that a classifier names, so the field is more
    precise than the classifiers it accounts for, and can state a choice that
    classifiers cannot. The classifiers it does not account for are added to
    it. A field that accounts for none of them gives None: it is then either
    unrelated text or contradicts the classifiers.
    """
    identifiers = _license_ids(declared)
    others = sorted(
        spdx
        for spdx in classified
        if not any(_accounts_for(identifier, spdx) for identifier in identifiers)
    )
    if len(others) == len(classified):
        return None
    if not others:
        return declared
    return " AND ".join([f"({declared})" if len(identifiers) > 1 else declared, *others])


def _license_ids(expression: str) -> list[str]:
    """Return the license identifiers of an SPDX expression, or none if it does not parse."""
    parser = _Expression(expression, frozenset())
    try:
        parser.evaluate()
    except ValueError:
        return []
    return parser.identifiers


def _accounts_for(identifier: str, classified: str) -> bool:
    """Return whether a license of the License field accounts for a classifier license.

    It does when it is the same license, or a version of it, such as
    BSD-3-Clause for the BSD License classifier or LGPL-2.1-or-later for the
    versionless LGPL one. Poetry adds Other/Proprietary License to every
    license it has no classifier for, so any license accounts for that one.
    """
    if classified == PROPRIETARY or identifier.lower() == classified.lower():
        return True
    family = classified.split("-")[0]
    versioned = re.match(rf"{re.escape(family)}-\d", identifier, re.IGNORECASE)
    return family != "LicenseRef" and versioned is not None


def _unexplained(text: str, classified: set[str]) -> bool:
    """Return whether a License field names a restriction, or a GNU license no classifier names."""
    if RESTRICTION.search(text):
        return True
    gnu_classified = any(spdx.split("-")[0] in GNU_FAMILIES for spdx in classified)
    return not gnu_classified and GNU_LICENSE.search(text) is not None


def _text_license(text: str) -> str | None:
    """Return the license of a free-text License field as an SPDX expression.

    A single line is a license name or expression. It is translated when every
    license it names is known and it names no restriction or GNU license, and
    is returned as written otherwise, so that it fails to parse or is not
    allowed and is reported as written. Several lines are a full license text.
    """
    if not text or text.upper() == "UNKNOWN":
        return None
    if "\n" in text:
        return _full_text_license(text)
    # The name of a classifier, or a short name, says exactly which GNU
    # license the field means.
    named = CLASSIFIERS.get(text) or SHORT_NAMES.get(_name_key(text))
    if named:
        return named
    if not RESTRICTIVE_TEXT.search(text):
        translated = _translate_names(text)
        if translated:
            return translated
    return text


def _full_text_license(text: str) -> str | None:
    """Return the licenses that a full license text quotes, or None if it is not recognized.

    The text must quote a known license and name no restriction or GNU
    license. When its first line names a license, as in "BSD 3-Clause
    License", that name must be known too: it is more precise than the
    phrases, and a text that names another license, such as "Eclipse Public
    License 2.0", may only quote a known one for a bundled component.
    """
    if RESTRICTIVE_TEXT.search(text):
        return None
    found = _fingerprints(text)
    title = text.split("\n", 1)[0].strip()
    if found and _LICENSE_WORD.search(title) and not _fingerprints(title):
        named = _license_name(title)
        if not named:
            return None
        found = {named, *(spdx for spdx in found if not _accounts_for(named, spdx))}
    # A text that quotes several licenses gets all of them.
    return " AND ".join(sorted(found)) or None


def _fingerprints(text: str) -> set[str]:
    """Return the licenses whose phrases a text quotes."""
    words = " ".join(text.lower().split())
    return {spdx for phrase, spdx in TEXT_FINGERPRINTS if phrase in words}


def _translate_names(text: str) -> str | None:
    """Translate license names joined by AND or OR into SPDX identifiers, if all are known.

    The operators may be in any case, as in "MIT or Apache 2.0", as they are
    for the evaluator.
    """
    named = _license_name(text)
    if named:
        # Some names contain an operator, as in "Historical Permission
        # Notice and Disclaimer (HPND)".
        return named
    parts = _OPERATOR.split(text)
    for index, part in enumerate(parts):
        if index % 2:
            parts[index] = part.upper()
            continue
        # Parentheses inside a name are part of it, as in "ISC License
        # (ISCL)"; grouping parentheses would be lost by the translation.
        if part.count("(") != part.count(")"):
            return None
        spdx = _license_name(part) or (part if _IDENTIFIER.fullmatch(part) else None)
        if spdx is None:
            return None
        parts[index] = spdx
    return " ".join(parts)


def _license_name(name: str) -> str | None:
    """Return the SPDX identifier of an unambiguous license name, if known."""
    return CLASSIFIERS.get(name) or FREE_TEXT.get(_name_key(name))


def _name_key(name: str) -> str:
    """Normalize a license name, so that "The MIT License (MIT)" gives "mit"."""
    key = re.sub(r"[,()]", " ", name.lower().replace("licence", "license"))
    key = re.sub(r"\b(?:the|license|version)\b|\bv(?=\d)", " ", key)
    return " ".join(dict.fromkeys(key.split()))


def check_license_file(path: Path, expected: str, reporter: Reporter) -> None:
    """Report a license file that does not hold the text of the expected license."""
    fingerprints = {name.lower(): phrases for name, phrases in LICENSE_FINGERPRINTS.items()}
    phrases = fingerprints.get(expected.lower())
    if phrases is None:
        reporter.warning(
            f"{path.name} is not compared with the {expected} license, whose text this "
            "check does not know."
        )
        return
    text = " ".join(path.read_text(encoding="utf-8", errors="replace").lower().split())
    if not all(phrase in text for phrase in phrases):
        reporter.error(f"{path.name} does not look like the {expected} license.")


def app_requirements(root: Path) -> list[Path]:
    """Return the requirements files of the Home Assistant apps of a repository.

    An app is a folder at the root or one level down that holds a Dockerfile
    and a config.yaml, config.yml or config.json. Its runtime dependencies
    are the requirements.txt next to them.
    """
    found = []
    for dockerfile in sorted([*root.glob("Dockerfile"), *root.glob("*/Dockerfile")]):
        folder = dockerfile.parent
        configs = ("config.yaml", "config.yml", "config.json")
        if any((folder / name).is_file() for name in configs):
            requirements = folder / "requirements.txt"
            if requirements.is_file():
                found.append(requirements)
    return found


def manifest_requirements(root: Path) -> list[str]:
    """Return the requirements declared by Home Assistant integration manifests."""
    requirements: list[str] = []
    for manifest in sorted(root.glob("custom_components/*/manifest.json")):
        data = json.loads(manifest.read_text(encoding="utf-8"))
        requirements.extend(data.get("requirements", []))
    return requirements


def install(
    requirements: list[str],
    files: list[Path],
    target: Path,
    python_version: str,
) -> None:
    """Install requirements into a directory without running a Python interpreter on them.

    Requirements go through a file so that none can be read as an option, and
    the uv configuration of the checked out repository is ignored.
    """
    for requirement in requirements:
        if not _valid_requirement(requirement):
            raise ValueError(f"Invalid manifest requirement: {requirement!r}")
    listing = target.parent / "manifest-requirements.txt"
    listing.write_text("".join(f"{line}\n" for line in requirements), encoding="utf-8")
    command = [
        "uv",
        "pip",
        "install",
        "--quiet",
        "--no-progress",
        "--no-config",
        "--target",
        str(target),
        "--python-version",
        python_version,
        "--python-platform",
        PLATFORM,
        "--requirement",
        str(listing),
    ]
    for path in files:
        command += ["--requirement", str(path)]
    subprocess.run(command, check=True)


def _valid_requirement(requirement: str) -> bool:
    """Return whether a manifest requirement is a single requirement that Home Assistant accepts.

    That is a PEP 508 requirement, which starts with a distribution name, or
    the legacy form "<url>#<requirement>".
    """
    if requirement.splitlines() != [requirement]:
        return False
    legacy = LEGACY_URL_REQUIREMENT.fullmatch(requirement)
    name = REQUIREMENT_NAME.match(legacy[1] if legacy else requirement)
    return name is not None and not ARCHIVE_NAME.search(name[1])


def installed(target: Path) -> Iterable[tuple[str, str, str | None]]:
    """Yield (name, version, license) for every distribution in a directory."""
    for metadata in sorted(target.glob("*.dist-info/METADATA")):
        text = metadata.read_text(encoding="utf-8", errors="replace")
        headers = HeaderParser().parsestr(text)
        yield (
            headers.get("Name", metadata.parent.name),
            headers.get("Version", "?"),
            license_of(text),
        )


def check_dependencies(
    distributions: Iterable[tuple[str, str, str | None]],
    allowed: frozenset[str],
    exceptions: Iterable[str],
    reporter: Reporter,
) -> None:
    """Report distributions whose license is unknown or not allowed."""
    exempt = {normalize_name(name) for name in exceptions}
    for name, version, spdx in distributions:
        if normalize_name(name) in exempt:
            print(f"{name} {version}: exempted by configuration.")
            continue
        if spdx is None:
            reporter.error(f"{name} {version}: license is unknown.")
            continue
        verdict = expression_allowed(spdx, allowed)
        if verdict is None:
            reporter.error(f"{name} {version}: license '{spdx}' could not be parsed.")
        elif not verdict:
            unmapped = (
                " A LicenseRef stands for a license classifier that has no SPDX identifier:"
                " review the license, then exempt the package."
                if "LicenseRef-" in spdx
                else ""
            )
            reporter.error(f"{name} {version}: license '{spdx}' is not allowed.{unmapped}")
        else:
            print(f"{name} {version}: {spdx}")


def main(argv: list[str] | None = None) -> int:
    """Run the license check from the command line."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--license", default="MIT", help="expected SPDX id of the repository")
    parser.add_argument("--requirements", default="", help="extra requirements files")
    parser.add_argument("--allowed", default="", help="replace the allowed SPDX ids")
    parser.add_argument("--exceptions", default="", help="package names exempted from the check")
    parser.add_argument("--python-version", default="3.14")
    args = parser.parse_args(argv)

    reporter = Reporter("Licenses")
    license_file = find_license_file(args.root)
    if license_file is None:
        reporter.error("The repository has no LICENSE file.")
    else:
        check_license_file(license_file, args.license, reporter)

    requirements = manifest_requirements(args.root)
    files = [args.root / path for path in split_list(args.requirements)]
    files += [path for path in app_requirements(args.root) if path not in files]
    for path in files:
        if not path.is_file():
            reporter.error(f"Requirements file not found: {path.relative_to(args.root)}")
    files = [path for path in files if path.is_file()]
    if requirements or files:
        allowed = frozenset(split_list(args.allowed)) or DEFAULT_ALLOWED
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "site"
            try:
                install(requirements, files, target, args.python_version)
            except (ValueError, subprocess.CalledProcessError) as err:
                return fail(f"Could not resolve the runtime dependencies: {err}")
            check_dependencies(installed(target), allowed, split_list(args.exceptions), reporter)
    else:
        print("No runtime dependency declared.")
    return reporter.finish()


if __name__ == "__main__":
    sys.exit(main())
