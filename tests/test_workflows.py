"""Run the coverage steps of ha-tests.yml on small integrations."""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from helpers import Repo

WORKFLOW = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "ha-tests.yml"
TESTED = "def double(value: int) -> int:\n    return value * 2\n"
NBSP = "\u00a0"
TEST = "from {package} import double\n\n\ndef test_double() -> None:\n    assert double(2) == 4\n"


def step_script(name: str) -> str:
    """Return the run script of a step of the workflow."""
    lines = WORKFLOW.read_text(encoding="utf-8").splitlines()
    start = lines.index(f"      - name: {name}")
    run = lines.index("        run: |", start)
    body = []
    for line in lines[run + 1 :]:
        if line.strip() and not line.startswith(" " * 10):
            break
        body.append(line)
    return textwrap.dedent("\n".join(body))


def run_step(
    repo: Repo, tmp_path: Path, name: str, source: str = "custom_components"
) -> subprocess.CompletedProcess[str]:
    # Without the variables of the pytest-cov run of this test suite, which
    # would measure the inner run too.
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("COV_CORE_", "COVERAGE_", "PYTEST_"))
    }
    env |= {
        "PATH": f"{Path(sys.executable).parent}{os.pathsep}{env['PATH']}",
        "RUNNER_TEMP": str(tmp_path / "runner"),
        "COVERAGE_SOURCE": source,
        "COVERAGE_MINIMUM": "95",
    }
    return subprocess.run(
        ["bash", "-e", "-o", "pipefail", "-c", step_script(name)],
        cwd=repo.root,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def integration(repo: Repo, code: str) -> None:
    repo.write("custom_components/__init__.py", "")
    repo.write("custom_components/bluefinch/__init__.py", TESTED + code)
    repo.write("tests/test_bluefinch.py", TEST.format(package="custom_components.bluefinch"))
    repo.write("pytest.ini", "[pytest]\naddopts = -p no:cacheprovider\n")
    repo.git("add", "--all")


def test_code_that_never_runs_is_excluded(repo: Repo, tmp_path: Path) -> None:
    integration(
        repo,
        "from typing import TYPE_CHECKING, Protocol\n\n"
        "if TYPE_CHECKING:\n    from collections.abc import Callable\n\n\n"
        "class Source(Protocol):\n    def read(self) -> int:\n        ...\n",
    )
    result = run_step(repo, tmp_path, "Run tests")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "100.00%" in result.stdout


@pytest.mark.parametrize("layout", ["directory", "src"])
def test_coverage_source_forms(repo: Repo, tmp_path: Path, layout: str) -> None:
    if layout == "directory":
        integration(repo, "")
        source = "./custom_components"
    else:
        repo.write("src/bluefinch/__init__.py", TESTED)
        repo.write("tests/test_bluefinch.py", TEST.format(package="bluefinch"))
        repo.write("pytest.ini", "[pytest]\naddopts = -p no:cacheprovider\npythonpath = src\n")
        repo.git("add", "--all")
        source = "bluefinch"
    result = run_step(repo, tmp_path, "Run tests", source)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "100.00%" in result.stdout


@pytest.mark.parametrize(
    ("pragma", "reported"),
    [
        ("# pragma: no cover", True),
        ("# pragma: no cover - ", True),
        # Non-breaking spaces, which the shell does not take for spaces.
        (f"#{NBSP}pragma:{NBSP}no{NBSP}cover", False),
        (f"# pragma: no cover{NBSP}- unused", True),
    ],
)
def test_pragma_without_reason_excludes_nothing(
    repo: Repo, tmp_path: Path, pragma: str, reported: bool
) -> None:
    integration(repo, f"\n\ndef unused() -> int:  {pragma}\n    return 1\n")
    result = run_step(repo, tmp_path, "Run tests")
    assert result.returncode != 0
    assert "Coverage failure" in result.stdout
    check = run_step(repo, tmp_path, "Check coverage pragmas")
    assert ("give the reason after the pragma" in check.stdout) is reported
    assert (check.returncode != 0) is reported


def test_pragma_with_reason_excludes_code(repo: Repo, tmp_path: Path) -> None:
    pragma = "# pragma: no cover - kept for scripts"
    integration(repo, f"\n\ndef unused() -> int:  {pragma}\n    return 1\n")
    result = run_step(repo, tmp_path, "Run tests")
    assert result.returncode == 0, result.stdout + result.stderr
    assert run_step(repo, tmp_path, "Check coverage pragmas").returncode == 0
