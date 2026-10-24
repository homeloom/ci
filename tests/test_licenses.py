"""Tests for the license check."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ci_checks import licenses
from ci_checks._common import Reporter

ALLOWED = licenses.DEFAULT_ALLOWED
MIT_TEXT = "MIT License\n\nPermission is hereby granted, free of charge, to any person\n"


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
    ],
)
def test_license_of(headers: dict, expected: str | None) -> None:
    assert licenses.license_of(metadata(**headers)) == expected


def make_site(target: Path, packages: dict[str, str]) -> None:
    for name, text in packages.items():
        directory = target / f"{name}-1.0.dist-info"
        directory.mkdir(parents=True)
        (directory / "METADATA").write_text(text, encoding="utf-8")


def test_check_dependencies(tmp_path: Path, capsys) -> None:
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


def test_install_command(tmp_path: Path, monkeypatch) -> None:
    calls = []
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


def test_install_rejects_options_in_requirements(tmp_path: Path, monkeypatch) -> None:
    calls = []
    monkeypatch.setattr(licenses.subprocess, "run", lambda command, check: calls.append(command))
    with pytest.raises(ValueError, match="Invalid manifest requirement"):
        licenses.install(["--index-url=https://pkgs.example.com"], [], tmp_path / "site", "3.14")
    assert calls == []


def test_main_license_file(tmp_path: Path, capsys) -> None:
    assert licenses.main(["--root", str(tmp_path)]) == 1
    assert "has no LICENSE file" in capsys.readouterr().out

    (tmp_path / "LICENSE").write_text("All rights reserved.\n", encoding="utf-8")
    assert licenses.main(["--root", str(tmp_path)]) == 1
    assert "does not look like the MIT license" in capsys.readouterr().out

    (tmp_path / "LICENSE").write_text(MIT_TEXT, encoding="utf-8")
    assert licenses.main(["--root", str(tmp_path)]) == 0
    assert "No runtime dependency declared." in capsys.readouterr().out

    assert licenses.main(["--root", str(tmp_path), "--license", "LicenseRef-Custom"]) == 0


def test_main_dependencies(tmp_path: Path, monkeypatch, capsys) -> None:
    (tmp_path / "LICENSE").write_text(MIT_TEXT, encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("lib==1.0\n", encoding="utf-8")

    def fake_install(requirements, files, target, python_version):
        assert files == [tmp_path / "requirements.txt"]
        make_site(target, {"lib": metadata("lib", License_Expression="GPL-3.0-only")})

    monkeypatch.setattr(licenses, "install", fake_install)
    args = ["--root", str(tmp_path), "--requirements", "requirements.txt missing.txt"]
    assert licenses.main(args) == 1
    out = capsys.readouterr().out
    assert "Requirements file not found: missing.txt" in out
    assert "license 'GPL-3.0-only' is not allowed" in out

    assert licenses.main([*args[:3], "requirements.txt", "--allowed", "GPL-3.0-only"]) == 0
