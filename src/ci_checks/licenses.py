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
    CC0-1.0 HPND ISC LGPL-2.1-only LGPL-2.1-or-later LGPL-3.0-only
    LGPL-3.0-or-later MIT MIT-0 MPL-2.0 PSF-2.0 Python-2.0 Unlicense Zlib
    """.split()
)
CLASSIFIERS = {
    "Apache Software License": "Apache-2.0",
    "BSD License": "BSD",
    "Boost Software License 1.0 (BSL-1.0)": "BSL-1.0",
    "CC0 1.0 Universal (CC0 1.0) Public Domain Dedication": "CC0-1.0",
    "GNU Affero General Public License v3": "AGPL-3.0-only",
    "GNU General Public License v2 (GPLv2)": "GPL-2.0-only",
    "GNU General Public License v3 (GPLv3)": "GPL-3.0-only",
    "GNU Lesser General Public License v2 (LGPLv2)": "LGPL-2.1-only",
    "GNU Lesser General Public License v2 or later (LGPLv2+)": "LGPL-2.1-or-later",
    "GNU Lesser General Public License v3 (LGPLv3)": "LGPL-3.0-only",
    "GNU Lesser General Public License v3 or later (LGPLv3+)": "LGPL-3.0-or-later",
    "Historical Permission Notice and Disclaimer (HPND)": "HPND",
    "ISC License (ISCL)": "ISC",
    "MIT License": "MIT",
    "MIT No Attribution License (MIT-0)": "MIT-0",
    "Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "Python Software Foundation License": "PSF-2.0",
    "The Unlicense (Unlicense)": "Unlicense",
    "zlib/libpng License": "Zlib",
}
FREE_TEXT = {
    "apache": "Apache-2.0",
    "apache 2": "Apache-2.0",
    "apache 2.0": "Apache-2.0",
    "apache software": "Apache-2.0",
    "apache software 2.0": "Apache-2.0",
    "apache version 2.0": "Apache-2.0",
    "bsd": "BSD",
    "bsd 3-clause": "BSD-3-Clause",
    "new bsd": "BSD-3-Clause",
    "isc": "ISC",
    "mit": "MIT",
    "mpl 2.0": "MPL-2.0",
    "mozilla public 2.0": "MPL-2.0",
    "psf": "PSF-2.0",
    "psfl": "PSF-2.0",
    "python software foundation": "PSF-2.0",
}
TEXT_FINGERPRINTS = (
    ("permission is hereby granted, free of charge", "MIT"),
    ("apache license", "Apache-2.0"),
    ("redistribution and use in source and binary forms", "BSD"),
)
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
            self._take()  # Exceptions only widen what a license allows.
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
    prefix = "License :: OSI Approved :: "
    found = []
    for classifier in headers.get_all("Classifier") or []:
        name = classifier.strip()
        name = name.removeprefix(prefix).removeprefix("License :: ")
        if name in CLASSIFIERS:
            found.append(CLASSIFIERS[name])
    if found:
        # Several classifiers may mean a choice or a combination; assume the
        # stricter combination. Reviewed packages go in the exceptions.
        return " AND ".join(sorted(set(found)))
    text = (headers.get("License") or "").strip()
    if not text or text.upper() == "UNKNOWN":
        return None
    lowered = text.lower()
    for fingerprint, spdx in TEXT_FINGERPRINTS:
        if fingerprint in lowered:
            return spdx
    key = re.sub(r"[,()]", " ", lowered)
    key = re.sub(r"\b(the|license|licence|version)\b", " ", key)
    key = " ".join(key.split())
    return FREE_TEXT.get(key, text if "\n" not in text else None)


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
        if requirement.lstrip().startswith("-") or any(c in requirement for c in "\r\n"):
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
