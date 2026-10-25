"""Run workflow steps: version selection, coverage on small integrations, HACS gate."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from datetime import UTC, datetime
from pathlib import Path

import pytest

from helpers import Repo

WORKFLOWS = Path(__file__).resolve().parent.parent / ".github" / "workflows"
WORKFLOW = WORKFLOWS / "ha-tests.yml"
TESTED = "def double(value: int) -> int:\n    return value * 2\n"
NBSP = "\u00a0"
TEST = "from {package} import double\n\n\ndef test_double() -> None:\n    assert double(2) == 4\n"


def step_script(name: str, workflow: Path = WORKFLOW) -> str:
    """Return the run script of a step of a workflow."""
    lines = workflow.read_text(encoding="utf-8").splitlines()
    start = lines.index(f"      - name: {name}")
    run = lines.index("        run: |", start)
    body = []
    for line in lines[run + 1 :]:
        if line.strip() and not line.startswith(" " * 10):
            break
        body.append(line)
    return textwrap.dedent("\n".join(body))


def workflow_env(name: str) -> str:
    """Return a variable of the env section of the workflow."""
    lines = WORKFLOW.read_text(encoding="utf-8").splitlines()
    [value] = [line.split(":", 1)[1].strip() for line in lines if line.startswith(f"  {name}:")]
    return value


def run_step(
    repo: Repo,
    tmp_path: Path,
    name: str,
    source: str = "custom_components",
    extra: dict[str, str] | None = None,
    bin_dir: Path | None = None,
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
    env |= extra or {}
    if bin_dir:
        env["PATH"] = f"{bin_dir}{os.pathsep}{env['PATH']}"
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


def select(repo: Repo, tmp_path: Path, leg: str, requires: str) -> tuple[int, str, str]:
    """Run the version selection step with a fake PyPI answer.

    Return the exit status, the output and the step outputs.
    """
    fake = tmp_path / "bin"
    fake.mkdir()
    release = {
        "info": {"requires_python": requires},
        "urls": [{"upload_time_iso_8601": "2026-03-04T12:00:00.000000Z"}],
    }
    curl = fake / "curl"
    curl.write_text(f"#!/bin/sh\ncat <<'EOF'\n{json.dumps(release)}\nEOF\n", encoding="utf-8")
    curl.chmod(0o755)
    outputs = tmp_path / "outputs"
    result = run_step(
        repo,
        tmp_path,
        "Select Home Assistant version",
        bin_dir=fake,
        extra={
            "LEG": leg,
            "MINIMUM": "2026.3.0",
            "GITHUB_OUTPUT": str(outputs),
            "PLUGIN": workflow_env("PLUGIN"),
        },
    )
    written = outputs.read_text(encoding="utf-8") if outputs.exists() else ""
    return result.returncode, result.stdout + result.stderr, written


def test_minimum_leg_selects_the_release_and_a_cutoff(repo: Repo, tmp_path: Path) -> None:
    major, minor = sys.version_info[:2]
    status, output, written = select(
        repo, tmp_path, "minimum", f">={major}.{minor}.0,<{major}.{minor + 1},!={major}.0.1"
    )
    assert status == 0, output
    assert "spec=homeassistant==2026.3.0\n" in written
    assert "cutoff=2026-03-11T12:00:00Z\n" in written


@pytest.mark.parametrize("bound", [">={major}.{next}", ">={major}.{minor}.99", "<{major}.{minor}"])
def test_minimum_leg_fails_when_the_release_excludes_the_python(
    repo: Repo, tmp_path: Path, bound: str
) -> None:
    major, minor = sys.version_info[:2]
    requires = bound.format(major=major, minor=minor, next=minor + 1)
    status, output, written = select(repo, tmp_path, "minimum", requires)
    assert status == 1
    assert f"::error::Home Assistant 2026.3.0 requires Python {requires}, and this leg" in output
    assert "Set python-minimum" in output
    assert "spec=" not in written


def test_latest_leg_bounds_the_plugin(repo: Repo, tmp_path: Path) -> None:
    assert workflow_env("PLUGIN") == "pytest-homeassistant-custom-component>=0.13"
    status, output, written = select(repo, tmp_path, "latest", "")
    assert status == 0, output
    assert "spec=pytest-homeassistant-custom-component>=0.13\n" in written


@pytest.mark.parametrize(
    ("answer", "status", "written"),
    [
        ("echo false", 0, "private=false\n"),
        ("echo true", 0, "private=true\n"),
        ("echo 'HTTP 403: Resource not accessible' >&2; exit 1", 1, ""),
        ("echo null", 1, ""),
    ],
)
def test_hacs_gate_reads_the_visibility(
    tmp_path: Path, answer: str, status: int, written: str
) -> None:
    fake = tmp_path / "bin"
    fake.mkdir()
    gh = fake / "gh"
    gh.write_text(f"#!/bin/sh\n{answer}\n", encoding="utf-8")
    gh.chmod(0o755)
    outputs = tmp_path / "outputs"
    outputs.touch()
    result = subprocess.run(
        [
            "bash",
            "-e",
            "-o",
            "pipefail",
            "-c",
            step_script("Read visibility", WORKFLOWS / "ha-integration.yml"),
        ],
        env={
            "PATH": f"{fake}{os.pathsep}{os.environ['PATH']}",
            "GITHUB_REPOSITORY": "example/zorble",
            "GITHUB_OUTPUT": str(outputs),
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == status, result.stdout + result.stderr
    assert outputs.read_text(encoding="utf-8") == written


def test_hacs_runs_only_when_the_repository_is_public() -> None:
    lines = (WORKFLOWS / "ha-integration.yml").read_text(encoding="utf-8").splitlines()
    condition = lines[lines.index("      - name: HACS") + 1]
    assert condition == (
        "        if: ${{ !cancelled() && steps.visibility.outputs.private == 'false' }}"
    )


def test_minimum_leg_installs_the_bounded_plugin(repo: Repo, tmp_path: Path) -> None:
    fake = tmp_path / "bin"
    fake.mkdir()
    calls = tmp_path / "calls"
    uv = fake / "uv"
    uv.write_text(
        f'#!/bin/sh\necho "$@" >> {calls}\n'
        'if [ "$2" = show ]; then printf "Name: x\\nVersion: 1\\n"; fi\n',
        encoding="utf-8",
    )
    uv.chmod(0o755)
    repo.write("custom_components/zorble/manifest.json", '{"requirements": ["zorblelib==1.0"]}')
    repo.write("requirements_test.txt", "pytest-zorble==2.0\n")
    (tmp_path / "runner").mkdir()
    started = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    result = run_step(
        repo,
        tmp_path,
        "Install dependencies",
        bin_dir=fake,
        extra={
            "SPEC": "homeassistant==2026.3.0",
            "CUTOFF": "2026-03-11T12:00:00Z",
            "REQUIREMENTS": "requirements_test.txt",
            "PLUGIN": "zorbleplugin>=9",
        },
    )
    assert result.returncode == 0, result.stdout + result.stderr
    install = calls.read_text(encoding="utf-8").splitlines()[0].split()
    assert install[:5] == [
        "pip",
        "install",
        "--system",
        "homeassistant==2026.3.0",
        "zorbleplugin>=9",
    ]
    assert install[install.index("--requirement", 6) + 1] == "requirements_test.txt"
    assert install[install.index("--exclude-newer") + 1] == "2026-03-11T12:00:00Z"
    # The integration's own requirements are resolved as of now.
    name, cutoff = install[install.index("--exclude-newer-package") + 1].split("=")
    assert name == "zorblelib"
    assert cutoff >= started
