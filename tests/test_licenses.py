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
        ("lgpl-3.0-only with lgpl-3.0-linking-exception", True),
        # Only SPDX exceptions are read as added permissions.
        ("Apache-2.0 WITH Commons-Clause", False),
        ("Apache-2.0 WITH LicenseRef-Bluefinch-Field-Of-Use", False),
        ("MIT WITH Bluefinch-No-Resale", False),
        ("Apache-2.0 WITH Elastic-2.0", False),
        ("GPL-2.0-only WITH Classpath-exception-2.0", False),
        ("MIT WITH LicenseRef-Non-Commercial OR BSD-3-Clause", True),
        ("MIT-CMU", True),
        ("Apache-2.0 AND CNRI-Python", True),
        ("GPL-2.0+", False),
        ("LGPL-2.1+", True),
        ("LGPL-3.0", True),
        ("LGPL-2.1-or-later", True),
        # LGPL-2.0-or-later can be used under LGPL-2.1, which is allowed.
        ("LGPL-2.0-or-later", True),
        ("LGPL-2.0+", True),
        ("LGPL-2.0-only", False),
        ("LGPL-2.0", False),
        ("GPL-3.0-only", False),
        ("MIT OR", None),
        ("(MIT", None),
        ("MIT)", None),
        ("AND MIT", None),
        ("MIT Apache-2.0", None),
        ("MIT WITH", None),
        ("MIT WITH AND BSD", None),
        ("MIT WITH (BSD)", None),
    ],
)
def test_expression_allowed(expression: str, expected: bool | None) -> None:
    assert licenses.expression_allowed(expression, ALLOWED) is expected


@pytest.mark.parametrize(
    ("expression", "allowed", "expected"),
    [
        ("GPL-2.0-or-later", "GPL-3.0-only", True),
        ("GPL-3.0-or-later", "GPL-3.0-only", True),
        ("GPL-2.0+", "GPL-3.0-or-later", True),
        ("GPL-2.0-only", "GPL-3.0-only", False),
        ("LGPL-2.1-or-later", "LGPL-2.0-only", False),
        ("AGPL-3.0-or-later", "GPL-3.0-only", False),
        ("GPL-2.0-or-later WITH Classpath-exception-2.0", "GPL-2.0-or-later", True),
        ("Apache-2.0 WITH LicenseRef-Bluefinch-Field-Of-Use", "Apache-2.0", False),
    ],
)
def test_expression_allowed_custom_list(expression: str, allowed: str, expected: bool) -> None:
    assert licenses.expression_allowed(expression, frozenset({allowed})) is expected


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
        ({"License": "GPL-3.0-only"}, "GPL-3.0-only"),
        ({"License": "UNKNOWN"}, None),
        ({}, None),
        ({"License": "3-Clause BSD License"}, "BSD-3-Clause"),
        ({"License": "BSD 3-Clause OR Apache-2.0"}, "BSD-3-Clause OR Apache-2.0"),
        ({"License": "Apache 2.0"}, "Apache-2.0"),
        ({"License": "ISC License (ISCL)"}, "ISC"),
        ({"License": "The MIT License (MIT)"}, "MIT"),
        ({"License": "Apache Licence v2.0 AND Simplified BSD"}, "Apache-2.0 AND BSD-2-Clause"),
        # Operators in prose are operators too, as they are for the evaluator.
        ({"License": "MIT or Apache 2.0"}, "MIT OR Apache-2.0"),
        ({"License": "MIT and Apache License"}, "MIT AND Apache-2.0"),
        ({"License": "Historical Permission Notice and Disclaimer (HPND)"}, "HPND"),
        # Unknown names and grouping parentheses are left as written.
        ({"License": "MIT OR Bluefinch Public License"}, "MIT OR Bluefinch Public License"),
        ({"License": "(BSD 3-Clause OR MIT) AND ISC"}, "(BSD 3-Clause OR MIT) AND ISC"),
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
        # A single line is never read as a full license text.
        (
            {"License": "Permission is hereby granted, free of charge, to any person"},
            "Permission is hereby granted, free of charge, to any person",
        ),
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
        # A title that names a license gives the precise license, if known.
        (
            {
                "License": folded(
                    "BSD 3-Clause License",
                    "Redistribution and use in source and binary forms, with or without",
                )
            },
            "BSD-3-Clause",
        ),
        (
            {
                "License": folded(
                    "MIT License",
                    "Redistribution and use in source and binary forms, with or without",
                )
            },
            "BSD AND MIT",
        ),
        (
            {
                "License": folded(
                    "Eclipse Public License 2.0",
                    "Redistribution and use in source and binary forms, with or without",
                )
            },
            None,
        ),
        ({"License": folded("MIT License", "Copyright 2024 Bluefinch")}, None),
    ],
)
def test_license_of(headers: dict, expected: str | None) -> None:
    assert licenses.license_of(metadata(**headers)) == expected


@pytest.mark.parametrize(
    "text",
    [
        "BUSL-1.1; client library licensed under the Apache License, Version 2.0",
        "EUPL-1.2; bundled parser licensed under the Apache License, Version 2.0",
        "CDDL-1.0, with helpers licensed under the Apache License, Version 2.0",
        "CC-BY-NC-4.0 for the models; code: Permission is hereby granted, free of charge",
        "MIT WITH Bluefinch-No-Resale",
    ],
)
def test_license_of_single_line_notice_is_reported_as_written(text: str) -> None:
    spdx = licenses.license_of(metadata(License=text))
    assert spdx == text
    assert not licenses.expression_allowed(spdx, ALLOWED)


OSI = "License :: OSI Approved :: "
PROPRIETARY = "License :: Other/Proprietary License"
LGPL = f"{OSI}GNU Library or Lesser General Public License (LGPL)"


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
        ([LGPL], "LGPL-2.0-or-later"),
        (
            [f"{OSI}GNU Affero General Public License v3 or later (AGPLv3+)"],
            "AGPL-3.0-or-later",
        ),
        (
            [f"{OSI}MIT License", PROPRIETARY],
            "LicenseRef-Proprietary AND MIT",
        ),
        ([f"{OSI}Python License (CNRI Python License)"], "CNRI-Python"),
        ([f"{OSI}Zero-Clause BSD (0BSD)"], "0BSD"),
        ([f"{OSI}Blue Oak Model License (BlueOak-1.0.0)"], "BlueOak-1.0.0"),
        ([f"{OSI}CMU License (MIT-CMU)"], "MIT-CMU"),
        ([f"{OSI}Universal Permissive License (UPL)"], "UPL-1.0"),
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


def test_versionless_lgpl_classifier_is_allowed() -> None:
    text = metadata(Classifier=[LGPL])
    assert licenses.expression_allowed(licenses.license_of(text) or "", ALLOWED) is True


@pytest.mark.parametrize(
    ("license_field", "classifiers", "expected"),
    [
        # The License field names the version or variant of a classifier...
        ("LGPL-2.1-or-later", [LGPL], "LGPL-2.1-or-later"),
        ("BSD 3-Clause", [f"{OSI}BSD License"], "BSD-3-Clause"),
        ("0BSD", [f"{OSI}Zero-Clause BSD (0BSD)"], "0BSD"),
        ("MIT-CMU", [f"{OSI}CMU License (MIT-CMU)"], "MIT-CMU"),
        # ... or states a choice that classifiers cannot.
        (
            "Apache-2.0 OR BSD-3-Clause",
            [f"{OSI}Apache Software License", f"{OSI}BSD License"],
            "Apache-2.0 OR BSD-3-Clause",
        ),
        (
            "Universal Permissive License 1.0 or Apache License 2.0",
            [f"{OSI}Apache Software License", f"{OSI}Universal Permissive License (UPL)"],
            "UPL-1.0 OR Apache-2.0",
        ),
        # Poetry adds Other/Proprietary License to licenses it has no classifier for.
        ("Apache-2.0 OR BSD-3-Clause", [PROPRIETARY], "Apache-2.0 OR BSD-3-Clause"),
        ("BSD", [f"{OSI}BSD License", PROPRIETARY], "BSD"),
        # Classifiers the field does not account for still count.
        (
            "MIT",
            [f"{OSI}MIT License", f"{OSI}GNU General Public License v3 or later (GPLv3+)"],
            "MIT AND GPL-3.0-or-later",
        ),
        (
            "MIT OR Apache-2.0",
            [f"{OSI}MIT License", f"{OSI}GNU General Public License v3 (GPLv3)"],
            "(MIT OR Apache-2.0) AND GPL-3.0-only",
        ),
        (
            "MIT License",
            [f"{OSI}MIT License", f"{OSI}Academic Free License (AFL)"],
            "MIT AND LicenseRef-Academic-Free-License-AFL",
        ),
        # A field unrelated to the classifiers leaves them to decide...
        ("BSD-like", [f"{OSI}BSD License"], "BSD"),
        ("Dual License", [f"{OSI}MIT License"], "MIT"),
        (
            "LGPLv3+",
            [f"{OSI}GNU Lesser General Public License v3 or later (LGPLv3+)"],
            "LGPL-3.0-or-later",
        ),
        ("Copyright 2024 Bluefinch", [PROPRIETARY], "LicenseRef-Proprietary"),
        # ... unless it names what they cannot express.
        (
            "Apache License 2.0 with Commons Clause v1.0",
            [f"{OSI}Apache Software License"],
            "Apache License 2.0 with Commons Clause v1.0",
        ),
        ("MIT, non-commercial use only", [f"{OSI}MIT License"], "MIT, non-commercial use only"),
        ("Proprietary", [f"{OSI}BSD License"], "Proprietary"),
        ("GPL-3.0-only", [f"{OSI}MIT License"], "GPL-3.0-only"),
        (
            "GPL-3.0-only; bundled parser under the Apache License",
            [f"{OSI}Apache Software License"],
            "GPL-3.0-only; bundled parser under the Apache License",
        ),
    ],
)
def test_license_of_field_and_classifiers(
    license_field: str, classifiers: list[str], expected: str
) -> None:
    assert licenses.license_of(metadata(License=license_field, Classifier=classifiers)) == expected


@pytest.mark.parametrize(
    ("license_field", "classifiers", "expected"),
    [
        ("LGPL-2.1-or-later", [LGPL], True),
        ("Apache-2.0 OR BSD-3-Clause", [PROPRIETARY], True),
        ("BSD", [f"{OSI}BSD License", PROPRIETARY], True),
        ("Apache License 2.0 with Commons Clause v1.0", [f"{OSI}Apache Software License"], None),
        ("MIT, non-commercial use only", [f"{OSI}MIT License"], None),
        ("Proprietary", [f"{OSI}BSD License"], False),
        ("MIT WITH Bluefinch-No-Resale", [f"{OSI}MIT License"], False),
        (
            "MIT OR Apache-2.0",
            [f"{OSI}MIT License", f"{OSI}GNU General Public License v3 (GPLv3)"],
            False,
        ),
    ],
)
def test_field_and_classifiers_verdict(
    license_field: str, classifiers: list[str], expected: bool | None
) -> None:
    spdx = licenses.license_of(metadata(License=license_field, Classifier=classifiers)) or ""
    assert licenses.expression_allowed(spdx, ALLOWED) is expected


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
        # The legacy "<url>#<requirement>" form of custom integrations.
        "git+https://example.com/lib.git#lib>=1",
        "git+https://example.com/lib.git#egg=lib",
        "https://example.com/lib-1.0.zip#lib==1.0",
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
        "git+https://example.com/lib.git",
        "git+https://example.com/lib.git#--index-url=https://pkgs.example.com",
        "git+https://example.com/lib.git#lib --index-url https://pkgs.example.com",
        "git+https://example.com/lib.git#lib\n--index-url https://pkgs.example.com",
        "\ufeffgit+https://example.com/lib.git#lib",
        "./vendor/lib#lib",
        "https://example.com/lib.tar.gz#lib.tar.gz",
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


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("GNU Lesser General Public License v3 or later (LGPLv3+)", "LGPL-3.0-or-later"),
        ("GNU General Public License v2 (GPLv2)", "GPL-2.0-only"),
        ("LGPLv3+", "LGPL-3.0-or-later"),
        ("LGPLv2.1", "LGPL-2.1-only"),
        ("GPLv3", "GPL-3.0-only"),
        ("MPL2", "MPL-2.0"),
        ("MPL 2", "MPL-2.0"),
        ("Mozilla Public License 2", "MPL-2.0"),
    ],
)
def test_license_of_gnu_and_mozilla_names_without_classifiers(text: str, expected: str) -> None:
    assert licenses.license_of(metadata(License=text)) == expected


@pytest.mark.parametrize(
    ("license_field", "classifiers", "expected", "verdict"),
    [
        ("BUSL-1.1", [f"{OSI}MIT License"], "BUSL-1.1 AND MIT", False),
        ("Apache-2.0", [f"{OSI}MIT License"], "Apache-2.0 AND MIT", True),
        (
            "EPL-2.0 OR Zlib",
            [f"{OSI}MIT License"],
            "(EPL-2.0 OR Zlib) AND MIT",
            True,
        ),
        ("LicenseRef-Bluefinch", [f"{OSI}MIT License"], "LicenseRef-Bluefinch AND MIT", False),
        # Loose words leave the classifiers to decide.
        ("Custom", [f"{OSI}MIT License"], "MIT", True),
    ],
)
def test_license_field_that_contradicts_the_classifiers(
    license_field: str, classifiers: list[str], expected: str, verdict: bool
) -> None:
    spdx = licenses.license_of(metadata(License=license_field, Classifier=classifiers))
    assert spdx == expected
    assert licenses.expression_allowed(spdx, ALLOWED) is verdict


def test_unmapped_classifier_is_explained(capsys: Capture) -> None:
    reporter = Reporter("Licenses")
    spdx = licenses.license_of(metadata(Classifier=["License :: Freely Distributable"]))
    licenses.check_dependencies([("lib", "1.0", spdx)], ALLOWED, [], reporter)
    out = capsys.readouterr().out
    assert "license 'LicenseRef-Freely-Distributable' is not allowed. A LicenseRef stands" in out
    licenses.check_dependencies([("lib", "1.0", "GPL-3.0-only")], ALLOWED, [], reporter)
    assert "LicenseRef" not in capsys.readouterr().out


TEXTS = {
    "0BSD": "Permission to use, copy, modify, and/or distribute this software for any purpose",
    "Apache-2.0": "Apache License\n  Version 2.0, January 2004",
    "BSD-2-Clause": "Redistribution and use in source and binary\nforms, with or without",
    "BSD-3-Clause": (
        "Redistribution and use in source and binary forms\n3. Neither the name of the copyright"
    ),
    "BSL-1.0": "Boost Software License - Version 1.0 - August 17th, 2003",
    "CC0-1.0": "Creative Commons Legal Code\n\nCC0 1.0 Universal",
    "GPL-2.0-or-later": "GNU GENERAL PUBLIC LICENSE\n  Version 2, June 1991",
    "GPL-3.0-only": "GNU GENERAL PUBLIC LICENSE\n  Version 3, 29 June 2007",
    "AGPL-3.0-only": "GNU AFFERO GENERAL PUBLIC LICENSE\n  Version 3, 19 November 2007",
    "LGPL-2.1-only": "GNU LESSER GENERAL PUBLIC LICENSE\n  Version 2.1, February 1999",
    "LGPL-3.0-or-later": "GNU LESSER GENERAL PUBLIC LICENSE\n  Version 3, 29 June 2007",
    "ISC": "Permission to use, copy, modify, and distribute this software",
    "MIT": MIT_TEXT,
    "MPL-2.0": "Mozilla Public License Version 2.0\n==================================",
    "Unlicense": "This is free and unencumbered software released into the public domain.",
    "Zlib": "2. Altered source versions must be plainly marked as such, and must not be",
}


@pytest.mark.parametrize("spdx", sorted(TEXTS))
def test_license_file_fingerprints(tmp_path: Path, capsys: Capture, spdx: str) -> None:
    path = tmp_path / "LICENSE"
    path.write_text(TEXTS[spdx], encoding="utf-8")
    reporter = Reporter("Licenses")
    licenses.check_license_file(path, spdx.lower(), reporter)
    assert reporter.count == 0, capsys.readouterr().out
    path.write_text(TEXTS["MIT" if spdx != "MIT" else "ISC"], encoding="utf-8")
    licenses.check_license_file(path, spdx, reporter)
    assert reporter.count == 1
    assert f"LICENSE does not look like the {spdx} license." in capsys.readouterr().out


def test_every_fingerprint_is_tested() -> None:
    # A license that shares the phrases of a tested one is tested with it.
    tested = {licenses.LICENSE_FINGERPRINTS[name] for name in TEXTS}
    assert set(licenses.LICENSE_FINGERPRINTS.values()) <= tested


def test_license_file_with_an_unknown_identifier_warns(tmp_path: Path, capsys: Capture) -> None:
    path = tmp_path / "LICENSE"
    path.write_text("Bluefinch terms\n", encoding="utf-8")
    reporter = Reporter("Licenses")
    licenses.check_license_file(path, "EUPL-1.2", reporter)
    assert reporter.count == 0
    assert "LICENSE is not compared with the EUPL-1.2 license" in capsys.readouterr().out


def test_app_requirements(tmp_path: Path) -> None:
    for folder in ("zorble", "quillmore", "docs", ".github/ISSUE_TEMPLATE"):
        (tmp_path / folder).mkdir(parents=True)
    for path in ("zorble/Dockerfile", "zorble/config.yaml", "zorble/requirements.txt"):
        (tmp_path / path).write_text("x\n", encoding="utf-8")
    # A Dockerfile without an app configuration is not an app, nor is a
    # configuration without a Dockerfile.
    for path in ("quillmore/Dockerfile", "quillmore/requirements.txt"):
        (tmp_path / path).write_text("x\n", encoding="utf-8")
    for path in (".github/ISSUE_TEMPLATE/config.yml", "docs/config.json"):
        (tmp_path / path).write_text("x\n", encoding="utf-8")
    (tmp_path / "Dockerfile").write_text("x\n", encoding="utf-8")
    (tmp_path / "config.json").write_text("{}\n", encoding="utf-8")
    assert licenses.app_requirements(tmp_path) == [tmp_path / "zorble" / "requirements.txt"]
    (tmp_path / "requirements.txt").write_text("x\n", encoding="utf-8")
    assert licenses.app_requirements(tmp_path) == [
        tmp_path / "requirements.txt",
        tmp_path / "zorble" / "requirements.txt",
    ]


def test_main_checks_app_requirements_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "LICENSE").write_text(MIT_TEXT, encoding="utf-8")
    app = tmp_path / "zorble"
    app.mkdir()
    for name in ("Dockerfile", "config.yaml", "requirements.txt"):
        (app / name).write_text("x\n", encoding="utf-8")
    seen: list[list[Path]] = []

    def fake_install(
        requirements: list[str], files: list[Path], target: Path, python_version: str
    ) -> None:
        seen.append(files)
        assert python_version == "3.13"
        target.mkdir(parents=True)

    monkeypatch.setattr(licenses, "install", fake_install)
    args = ["--root", str(tmp_path), "--python-version", "3.13"]
    assert licenses.main([*args, "--requirements", "zorble/requirements.txt"]) == 0
    assert seen == [[app / "requirements.txt"]]
