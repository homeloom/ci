"""Tests for the license check."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ci_checks import licenses
from ci_checks._common import Reporter

ALLOWED = licenses.DEFAULT_ALLOWED
Capture = pytest.CaptureFixture[str]
MIT_TEXT = "MIT License\n\nPermission is hereby granted, free of charge, to any person\n"


def folded(*lines: str) -> str:
    """Return a header value spread over several lines, as METADATA folds it."""
    return "\n        ".join(lines)


def metadata(name: str = "demo", version: str = "1.0", **headers: str | list[str]) -> str:
    lines = ["Metadata-Version: 2.4", f"Name: {name}", f"Version: {version}"]
    for key, value in headers.items():
        values = value if isinstance(value, list) else [value]
        lines += [f"{key.replace('_', '-')}: {item}" for item in values]
    return "\n".join(lines) + "\n\nLong description.\n"


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        ("MIT", True),
        ("mit", True),
        ("Apache-2.0 OR GPL-3.0-only", True),
        ("GPL-3.0-only OR MIT", True),
        ("MIT AND BSD-3-Clause", True),
        ("MIT AND GPL-3.0-only", False),
        ("(MIT OR GPL-2.0-only) AND Apache-2.0", True),
        ("Apache-2.0 WITH LLVM-exception", True),
        ("Apache-2.0 WITH Commons-Clause", False),
        ("MIT WITH LicenseRef-Non-Commercial OR BSD-3-Clause", True),
        ("MIT-CMU", True),
        ("Apache-2.0 AND CNRI-Python", True),
        ("GPL-2.0+", False),
        ("LGPL-2.1+", True),
        ("LGPL-3.0", True),
        ("LGPL-2.1-or-later", True),
        ("GPL-3.0-only", False),
        ("MIT OR", None),
        ("(MIT", None),
        ("MIT)", None),
        ("AND MIT", None),
        ("MIT Apache-2.0", None),
    ],
)
def test_expression_allowed(expression: str, expected: bool | None) -> None:
    assert licenses.expression_allowed(expression, ALLOWED) is expected


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        ({"License_Expression": "Apache-2.0 OR MIT", "License": "ignored"}, "Apache-2.0 OR MIT"),
        ({"Classifier": ["License :: OSI Approved :: MIT License"]}, "MIT"),
        (
            {
                "Classifier": [
                    "License :: OSI Approved :: Apache Software License",
                    "License :: OSI Approved :: BSD License",
                    "Programming Language :: Python",
                ]
            },
            "Apache-2.0 AND BSD",
        ),
        (
            {"Classifier": ["License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication"]},
            "CC0-1.0",
        ),
        ({"License": "MIT License"}, "MIT"),
        ({"License": "Apache License, Version 2.0"}, "Apache-2.0"),
        ({"License": "BSD 3-Clause License"}, "BSD-3-Clause"),
        ({"License": "Permission is hereby granted, free of charge, to any person"}, "MIT"),
        ({"License": "GPL-3.0-only"}, "GPL-3.0-only"),
        ({"License": "UNKNOWN"}, None),
        ({}, None),
        ({"License": "3-Clause BSD License"}, "BSD-3-Clause"),
        ({"License": "BSD 3-Clause OR Apache-2.0"}, "BSD-3-Clause OR Apache-2.0"),
        ({"License": "Apache 2.0"}, "Apache-2.0"),
        ({"License": "ISC License (ISCL)"}, "ISC"),
        ({"License": "The MIT License (MIT)"}, "MIT"),
        ({"License": "Apache Licence v2.0 AND Simplified BSD"}, "Apache-2.0 AND BSD-2-Clause"),
        # Unknown names and grouping parentheses are left as written.
        ({"License": "MIT OR Bluefinch Public License"}, "MIT OR Bluefinch Public License"),
        ({"License": "(BSD 3-Clause OR MIT) AND ISC"}, "(BSD 3-Clause OR MIT) AND ISC"),
        ({"License": "MIT and Apache License"}, "MIT and Apache License"),
        # Text naming a restriction or a copyleft license is never translated.
        (
            {"License": "Apache License 2.0 with Commons Clause v1.0"},
            "Apache License 2.0 with Commons Clause v1.0",
        ),
        (
            {"License": "GPL-3.0-only; bundled parser under the Apache License"},
            "GPL-3.0-only; bundled parser under the Apache License",
        ),
        ({"License": "Apache 2.0, non-commercial use"}, "Apache 2.0, non-commercial use"),
        ({"License": "BSD 3-Clause OR LGPLv3"}, "BSD 3-Clause OR LGPLv3"),
        # Full license texts.
        ({"License": folded("Permission is hereby granted,", "free of charge, to")}, "MIT"),
        (
            {
                "License": folded(
                    "Apache License",
                    "TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION",
                )
            },
            "Apache-2.0",
        ),
        (
            {
                "License": folded(
                    "Licensed under the Apache License, Version 2.0 (the",
                    '"License"); you may not use this file except in compliance',
                )
            },
            "Apache-2.0",
        ),
        (
            {
                "License": folded(
                    "Permission is hereby granted, free of charge, to any person",
                    "Redistribution and use in source and binary forms, with or without",
                )
            },
            "BSD AND MIT",
        ),
        (
            {
                "License": folded(
                    "Permission is hereby granted, free of charge, to any person",
                    "The parser is covered by the GNU General Public License.",
                )
            },
            None,
        ),
        ({"License": folded("Copyright 2024 Bluefinch", "All rights reserved.")}, None),
    ],
)
def test_license_of(headers: dict, expected: str | None) -> None:
    assert licenses.license_of(metadata(**headers)) == expected


OSI = "License :: OSI Approved :: "


@pytest.mark.parametrize(
    ("classifiers", "expected"),
    [
        (
            [f"{OSI}MIT License", f"{OSI}GNU General Public License v3 (GPLv3)"],
            "GPL-3.0-only AND MIT",
        ),
        (
            [f"{OSI}MIT License", f"{OSI}GNU General Public License v3 or later (GPLv3+)"],
            "GPL-3.0-or-later AND MIT",
        ),
        ([f"{OSI}GNU General Public License v2 or later (GPLv2+)"], "GPL-2.0-or-later"),
        ([f"{OSI}GNU General Public License (GPL)"], "GPL-1.0-or-later"),
        ([f"{OSI}GNU Library or Lesser General Public License (LGPL)"], "LGPL-2.0-or-later"),
        (
            [f"{OSI}GNU Affero General Public License v3 or later (AGPLv3+)"],
            "AGPL-3.0-or-later",
        ),
        (
            [f"{OSI}MIT License", "License :: Other/Proprietary License"],
            "LicenseRef-Proprietary AND MIT",
        ),
        ([f"{OSI}Python License (CNRI Python License)"], "CNRI-Python"),
        # A classifier without an SPDX identifier still counts.
        (
            [f"{OSI}MIT License", f"{OSI}Eclipse Public License 2.0 (EPL-2.0)"],
            "LicenseRef-Eclipse-Public-License-2.0-EPL-2.0 AND MIT",
        ),
        # Classifiers that add no condition are ignored.
        (["License :: DFSG approved", f"{OSI}MIT License"], "MIT"),
        ([f"{OSI}BSD License", "License :: Public Domain"], "BSD"),
    ],
)
def test_license_of_classifiers(classifiers: list[str], expected: str) -> None:
    assert licenses.license_of(metadata(Classifier=classifiers)) == expected


def test_license_of_neutral_classifier_keeps_license_field() -> None:
    text = metadata(Classifier=["License :: OSI Approved"], License="LGPL-2.1-or-later")
    assert licenses.license_of(text) == "LGPL-2.1-or-later"


@pytest.mark.parametrize(
    ("only", "or_later"),
    [
        (
            "GNU General Public License v2 (GPLv2)",
            "GNU General Public License v2 or later (GPLv2+)",
        ),
        (
            "GNU General Public License v3 (GPLv3)",
            "GNU General Public License v3 or later (GPLv3+)",
        ),
        (
            "GNU Lesser General Public License v2 (LGPLv2)",
            "GNU Lesser General Public License v2 or later (LGPLv2+)",
        ),
        (
            "GNU Lesser General Public License v3 (LGPLv3)",
            "GNU Lesser General Public License v3 or later (LGPLv3+)",
        ),
        (
            "GNU Affero General Public License v3",
            "GNU Affero General Public License v3 or later (AGPLv3+)",
        ),
    ],
)
def test_or_later_classifiers_get_the_same_verdict(only: str, or_later: str) -> None:
    verdicts = {
        licenses.expression_allowed(
            licenses.license_of(metadata(Classifier=[f"{OSI}MIT License", f"{OSI}{name}"])) or "",
            ALLOWED,
        )
        for name in (only, or_later)
    }
    assert len(verdicts) == 1


def make_site(target: Path, packages: dict[str, str]) -> None:
    for name, text in packages.items():
        directory = target / f"{name}-1.0.dist-info"
        directory.mkdir(parents=True)
        (directory / "METADATA").write_text(text, encoding="utf-8")


def test_check_dependencies(tmp_path: Path, capsys: Capture) -> None:
    make_site(
        tmp_path,
        {
            "good": metadata("good", License_Expression="MIT"),
            "copyleft": metadata("copyleft", License_Expression="GPL-3.0-only"),
            "mystery": metadata("mystery"),
            "broken": metadata("broken", License_Expression="MIT OR"),
            "Reviewed_Pkg": metadata("Reviewed_Pkg", License_Expression="GPL-3.0-only"),
        },
    )
    reporter = Reporter("Licenses")
    licenses.check_dependencies(licenses.installed(tmp_path), ALLOWED, ["reviewed-pkg"], reporter)
    out = capsys.readouterr().out
    assert reporter.count == 3
    assert "good 1.0: MIT" in out
    assert "copyleft 1.0: license 'GPL-3.0-only' is not allowed." in out
    assert "mystery 1.0: license is unknown." in out
    assert "broken 1.0: license 'MIT OR' could not be parsed." in out
    assert "Reviewed_Pkg 1.0: exempted by configuration." in out


def test_manifest_requirements(tmp_path: Path) -> None:
    for domain, requirements in (("a", ["lib-a==1.0"]), ("b", [])):
        manifest = tmp_path / "custom_components" / domain / "manifest.json"
        manifest.parent.mkdir(parents=True)
        manifest.write_text(json.dumps({"domain": domain, "requirements": requirements}))
    assert licenses.manifest_requirements(tmp_path) == ["lib-a==1.0"]


def test_install_command(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr(licenses.subprocess, "run", lambda command, check: calls.append(command))
    licenses.install(["lib==1.0"], [tmp_path / "req.txt"], tmp_path / "site", "3.14")
    command = calls[0]
    assert command[:3] == ["uv", "pip", "install"]
    assert "--target" in command
    assert command[command.index("--python-version") + 1] == "3.14"
    assert "--no-config" in command
    assert command[-2:] == ["--requirement", str(tmp_path / "req.txt")]
    assert "lib==1.0" not in command
    listing = Path(command[command.index("--requirement") + 1])
    assert listing.read_text(encoding="utf-8") == "lib==1.0\n"


def test_install_accepts_requirements(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr(licenses.subprocess, "run", lambda command, check: calls.append(command))
    requirements = [
        "lib",
        "  Lib.Name_two~=1.0",
        "lib[extra]>=1.0",
        "lib (>=1.0)",
        "lib==1.0 ; python_version >= '3.12'",
        "lib @ https://example.com/lib-1.0-py3-none-any.whl",
    ]
    licenses.install(requirements, [], tmp_path / "site", "3.14")
    listing = Path(calls[0][calls[0].index("--requirement") + 1])
    assert listing.read_text(encoding="utf-8").splitlines() == requirements


@pytest.mark.parametrize(
    "requirement",
    [
        "--index-url=https://pkgs.example.com",
        "lib\n--index-url https://pkgs.example.com",
        "\ufeff--index-url https://pkgs.example.com",
        " \ufeff-r other.txt",
        "\ufefflib==1.0",
        "lib==1.0\u2028--index-url https://pkgs.example.com",
        "./vendor/lib",
        "/srv/lib",
        "~/lib",
        "https://example.com/lib-1.0.tar.gz",
        "file:lib",
        "lib-1.0-py3-none-any.whl",
        "lib.tar.gz",
        "lib.ZIP",
        "",
    ],
)
def test_install_rejects_options_in_requirements(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, requirement: str
) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr(licenses.subprocess, "run", lambda command, check: calls.append(command))
    with pytest.raises(ValueError, match="Invalid manifest requirement"):
        licenses.install([requirement], [], tmp_path / "site", "3.14")
    assert calls == []


def test_main_license_file(tmp_path: Path, capsys: Capture) -> None:
    assert licenses.main(["--root", str(tmp_path)]) == 1
    assert "has no LICENSE file" in capsys.readouterr().out

    (tmp_path / "LICENSE").write_text("All rights reserved.\n", encoding="utf-8")
    assert licenses.main(["--root", str(tmp_path)]) == 1
    assert "does not look like the MIT license" in capsys.readouterr().out

    (tmp_path / "LICENSE").write_text(MIT_TEXT, encoding="utf-8")
    assert licenses.main(["--root", str(tmp_path)]) == 0
    assert "No runtime dependency declared." in capsys.readouterr().out

    assert licenses.main(["--root", str(tmp_path), "--license", "LicenseRef-Custom"]) == 0


def test_main_rejects_byte_order_mark_in_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Capture
) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr(licenses.subprocess, "run", lambda command, check: calls.append(command))
    (tmp_path / "LICENSE").write_text(MIT_TEXT, encoding="utf-8")
    manifest = tmp_path / "custom_components" / "demo" / "manifest.json"
    manifest.parent.mkdir(parents=True)
    requirements = ["\ufeff--index-url https://pkgs.example.com/simple", "lib==1.0"]
    data = {"domain": "demo", "requirements": requirements}
    manifest.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    assert licenses.main(["--root", str(tmp_path)]) == 1
    assert "Invalid manifest requirement" in capsys.readouterr().err
    assert calls == []


def test_main_dependencies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Capture
) -> None:
    (tmp_path / "LICENSE").write_text(MIT_TEXT, encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("lib==1.0\n", encoding="utf-8")

    def fake_install(
        requirements: list[str], files: list[Path], target: Path, python_version: str
    ) -> None:
        assert files == [tmp_path / "requirements.txt"]
        make_site(target, {"lib": metadata("lib", License_Expression="GPL-3.0-only")})

    monkeypatch.setattr(licenses, "install", fake_install)
    args = ["--root", str(tmp_path), "--requirements", "requirements.txt missing.txt"]
    assert licenses.main(args) == 1
    out = capsys.readouterr().out
    assert "Requirements file not found: missing.txt" in out
    assert "license 'GPL-3.0-only' is not allowed" in out

    assert licenses.main([*args[:3], "requirements.txt", "--allowed", "GPL-3.0-only"]) == 0
