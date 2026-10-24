"""Check the repository license and the licenses of runtime dependencies.

The repository must ship a LICENSE file. Runtime dependencies (the
`requirements` of Home Assistant manifests, plus any requirements files
given) are installed into a temporary directory with uv, and the license
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
LICENSE_FINGERPRINTS = {
    "MIT": "permission is hereby granted, free of charge",
    "Apache-2.0": "apache license",
}
DEFAULT_ALLOWED = frozenset(
    """
    0BSD Apache-2.0 BlueOak-1.0.0 BSD BSD-2-Clause BSD-3-Clause BSL-1.0
    CC0-1.0 CNRI-Python HPND ISC LGPL-2.1-only LGPL-2.1-or-later LGPL-3.0-only
    LGPL-3.0-or-later MIT MIT-0 MIT-CMU MPL-2.0 PSF-2.0 Python-2.0 Unlicense
    Zlib
    """.split()
)
CLASSIFIERS = {
    "Apache Software License": "Apache-2.0",
    "BSD License": "BSD",
    "Boost Software License 1.0 (BSL-1.0)": "BSL-1.0",
    "CC0 1.0 Universal (CC0 1.0) Public Domain Dedication": "CC0-1.0",
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
    "Other/Proprietary License": "LicenseRef-Proprietary",
    "Python License (CNRI Python License)": "CNRI-Python",
    "Python Software Foundation License": "PSF-2.0",
    "The Unlicense (Unlicense)": "Unlicense",
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
    "zlib/libpng": "Zlib",
}
# Phrases of full license texts, compared with whitespace collapsed.
TEXT_FINGERPRINTS = (
    ("permission is hereby granted, free of charge", "MIT"),
    ("terms and conditions for use, reproduction, and distribution", "Apache-2.0"),
    ("licensed under the apache license, version 2.0", "Apache-2.0"),
    ("redistribution and use in source and binary forms", "BSD"),
)
# Restrictions that some packages add to a permissive license. No SPDX
# exception is named like this, since exceptions only ever widen a license.
RESTRICTION = re.compile(r"commons[\s_-]*clause|proprietary|non[\s_-]*commercial", re.IGNORECASE)
# Free text naming a restriction or a copyleft license is never translated
# into a permissive license, even when it also names one.
RESTRICTIVE_TEXT = re.compile(rf"{RESTRICTION.pattern}|gpl|general public", re.IGNORECASE)
# A manifest requirement must start with a distribution name (PEP 508), or
# uv may read it as an option, a path or a URL. uv also drops a byte order
# mark at the start of the file, which str.strip() keeps.
REQUIREMENT_NAME = re.compile(
    r"\s*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)(?=[\s\[(<>=!~;@]|\Z)"
)
# Names that uv reads as the path of an archive.
ARCHIVE_NAME = re.compile(r"\.(?:whl|zip|tgz|tar(?:\.\w+)?)\Z", re.IGNORECASE)
_OPERATOR = re.compile(r"\s+(AND|OR)\s+")
_IDENTIFIER = re.compile(r"[A-Za-z0-9.+-]+")
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
        if item.upper() in {"AND", "OR", "WITH", ")"}:
            raise ValueError("unexpected operator")
        if (self._peek() or "").upper() == "WITH":
            self._take()
            # Exceptions only widen what a license allows, unless the
            # "exception" is in fact a restriction.
            if RESTRICTION.search(self._take()):
                return False
        name = item.lower()
        # Deprecated SPDX forms: "X+" means "X-or-later" and a bare "X" means "X-only".
        candidates = {name, name + "-only"}
        if name.endswith("+"):
            candidates.add(name[:-1] + "-or-later")
        return not candidates.isdisjoint(self.allowed)


def expression_allowed(expression: str, allowed: frozenset[str]) -> bool | None:
    """Return whether an SPDX expression is allowed, or None if it does not parse."""
    try:
        return _Expression(expression, allowed).evaluate()
    except ValueError:
        return None


def license_of(metadata: str) -> str | None:
    """Return the license of a distribution as an SPDX expression, if known."""
    headers = HeaderParser().parsestr(metadata)
    expression = headers.get("License-Expression")
    if expression:
        return expression.strip()
    found = {
        spdx
        for classifier in headers.get_all("Classifier") or []
        if (spdx := _classifier_license(classifier.strip()))
    }
    if found:
        # Several classifiers may mean a choice or a combination; assume the
        # stricter combination. Reviewed packages go in the exceptions.
        return " AND ".join(sorted(found))
    return _text_license((headers.get("License") or "").strip())


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


def _text_license(text: str) -> str | None:
    """Return the license of a free-text License field as an SPDX expression.

    Text that cannot be translated unambiguously is returned unchanged when it
    is a single line, so that it fails to parse or is not allowed and is
    reported as written; a full license text that is not recognized is
    unknown.
    """
    if not text or text.upper() == "UNKNOWN":
        return None
    restrictive = RESTRICTIVE_TEXT.search(text) is not None
    single_line = "\n" not in text
    if single_line and not restrictive:
        translated = _translate_names(text)
        if translated:
            return translated
    words = " ".join(text.lower().split())
    found = sorted({spdx for phrase, spdx in TEXT_FINGERPRINTS if phrase in words})
    if found and not restrictive:
        # A text that quotes several licenses gets all of them.
        return " AND ".join(found)
    return text if single_line else None


def _translate_names(text: str) -> str | None:
    """Translate license names joined by AND or OR into SPDX identifiers, if all are known."""
    parts = _OPERATOR.split(text)
    for index in range(0, len(parts), 2):
        term = parts[index]
        # Parentheses inside a name are part of it, as in "ISC License
        # (ISCL)"; grouping parentheses would be lost by the translation.
        if term.count("(") != term.count(")"):
            return None
        spdx = _license_name(term) or (term if _IDENTIFIER.fullmatch(term) else None)
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
        name = REQUIREMENT_NAME.match(requirement)
        if not name or ARCHIVE_NAME.search(name[1]) or requirement.splitlines() != [requirement]:
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
            reporter.error(f"{name} {version}: license '{spdx}' is not allowed.")
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
        fingerprint = LICENSE_FINGERPRINTS.get(args.license)
        text = license_file.read_text(encoding="utf-8", errors="replace").lower()
        if fingerprint and fingerprint not in text:
            reporter.error(f"{license_file.name} does not look like the {args.license} license.")

    requirements = manifest_requirements(args.root)
    files = [args.root / path for path in split_list(args.requirements)]
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
