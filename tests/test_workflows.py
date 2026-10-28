"""Run workflow steps: version selection, coverage on small integrations, HACS gate."""

from __future__ import annotations

import json
import os
import shutil
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
# Split so that the pragma check of this repository does not report this file.
PRAGMA = "# pragma: no " + "cover"
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
        # The environment of this test suite stands for the one of the job.
        "VIRTUAL_ENV": str(Path(sys.executable).parent.parent),
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
        (PRAGMA, True),
        (f"{PRAGMA} - ", True),
        # Non-breaking spaces, which the shell does not take for spaces.
        (f"#{NBSP}pragma:{NBSP}no{NBSP}cover", False),
        (f"{PRAGMA}{NBSP}- unused", True),
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


PLUGIN_NAME = "pytest-homeassistant-custom-component"
RELEASED = "2026-03-04T12:00:00.000000Z"


def fake_pypi(root: Path, requires: str, plugins: dict[str, tuple[str, str]]) -> Path:
    """Write the PyPI answers for Home Assistant 2026.3.0 and plugin releases.

    plugins maps each plugin version to the Home Assistant version it pins
    and its upload time.
    """

    def answer(path: str, data: dict) -> None:
        target = root / path / "json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(data), encoding="utf-8")

    answer(
        "homeassistant/2026.3.0",
        {"info": {"requires_python": requires}, "urls": [{"upload_time_iso_8601": RELEASED}]},
    )
    files = {number: [{"upload_time_iso_8601": when}] for number, (_, when) in plugins.items()}
    answer(PLUGIN_NAME, {"releases": {**files, "0.1.0": []}})
    for number, (pinned, _) in plugins.items():
        answer(
            f"{PLUGIN_NAME}/{number}",
            {"info": {"requires_dist": ["pytest==9.0.0", f"homeassistant=={pinned}"]}},
        )
    return root


PINNED = {
    "0.13.300": ("2026.2.3", "2026-02-20T08:00:00Z"),
    "0.13.301": ("2026.3.0b4", "2026-03-03T08:00:00Z"),
    "0.13.302": ("2026.3.0", "2026-03-05T08:00:00Z"),
    "0.13.303": ("2026.3.1", "2026-03-12T08:00:00Z"),
}


def select(
    repo: Repo,
    tmp_path: Path,
    leg: str,
    requires: str = ">=3.13.2",
    python: str = "",
    plugins: dict[str, tuple[str, str]] = PINNED,
) -> tuple[int, str, str]:
    """Run the version selection step with fake PyPI answers.

    Return the exit status, the output and the step outputs.
    """
    pypi = fake_pypi(tmp_path / "pypi", requires, plugins)
    outputs = tmp_path / "outputs"
    result = run_step(
        repo,
        tmp_path,
        "Select versions",
        extra={
            "LEG": leg,
            "MINIMUM": "2026.3.0",
            "PYTHON_MINIMUM": python,
            "PYTHON_LATEST": "3.14",
            "PYPI_URL": pypi.as_uri(),
            "GITHUB_OUTPUT": str(outputs),
            "PLUGIN": workflow_env("PLUGIN"),
        },
    )
    written = outputs.read_text(encoding="utf-8") if outputs.exists() else ""
    return result.returncode, result.stdout + result.stderr, written


def test_minimum_leg_selects_the_release_its_plugin_and_python(repo: Repo, tmp_path: Path) -> None:
    status, output, written = select(repo, tmp_path, "minimum")
    assert status == 0, output
    assert "spec=homeassistant==2026.3.0\n" in written
    assert f"plugin={PLUGIN_NAME}==0.13.302\n" in written
    # The oldest Python that the release supports, at its newest patch.
    assert "python=3.13\n" in written
    assert "cutoff=2026-03-11T12:00:00Z\n" in written


def test_minimum_leg_waits_for_a_late_plugin_release(repo: Repo, tmp_path: Path) -> None:
    late = {"0.13.302": ("2026.3.0", "2026-03-15T08:00:00Z")}
    status, output, written = select(repo, tmp_path, "minimum", plugins=late)
    assert status == 0, output
    assert "cutoff=2026-03-16T08:00:00Z\n" in written


@pytest.mark.parametrize(
    ("requires", "python"),
    [(">=3.12", "3.12"), (">=3.14.0", "3.14"), (">=3.13.2,<3.15", "3.13"), ("", "3.12")],
)
def test_minimum_leg_derives_the_python(
    repo: Repo, tmp_path: Path, requires: str, python: str
) -> None:
    status, output, written = select(repo, tmp_path, "minimum", requires)
    assert status == 0, output
    assert f"python={python}\n" in written


def test_minimum_leg_keeps_a_python_that_fits(repo: Repo, tmp_path: Path) -> None:
    status, output, written = select(repo, tmp_path, "minimum", ">=3.13.2", "3.14")
    assert status == 0, output
    assert "python=3.14\n" in written


@pytest.mark.parametrize(
    ("requires", "python"), [(">=3.14", "3.13"), (">=3.13.2", "3.13.1"), ("<3.13", "3.13")]
)
def test_minimum_leg_fails_when_the_release_excludes_the_python(
    repo: Repo, tmp_path: Path, requires: str, python: str
) -> None:
    status, output, written = select(repo, tmp_path, "minimum", requires, python)
    assert status == 1
    assert (
        f"::error::Home Assistant 2026.3.0 requires Python {requires}, and python-minimum" in output
    )
    assert "spec=" not in written


def test_minimum_leg_fails_when_no_python_fits(repo: Repo, tmp_path: Path) -> None:
    status, output, written = select(repo, tmp_path, "minimum", ">=3.15")
    assert status == 1
    assert "which no version from 3.12 to python-latest satisfies" in output
    assert "spec=" not in written


def test_minimum_leg_names_the_releases_that_a_plugin_pins(repo: Repo, tmp_path: Path) -> None:
    others = {number: pin for number, pin in PINNED.items() if number != "0.13.302"}
    status, output, written = select(repo, tmp_path, "minimum", plugins=others)
    assert status == 1
    assert (
        f"::error::No {PLUGIN_NAME} release pins Home Assistant 2026.3.0. The releases near it "
        "pin 2026.2.3, 2026.3.1: set homeassistant-minimum to one of them." in output
    )
    assert "spec=" not in written
    status, output, _ = select(repo, tmp_path / "none", "minimum", plugins={})
    assert "Set homeassistant-minimum to a release that it supports." in output


def test_latest_leg_bounds_the_plugin(repo: Repo, tmp_path: Path) -> None:
    assert workflow_env("PLUGIN") == f"{PLUGIN_NAME}>=0.13"
    status, output, written = select(repo, tmp_path, "latest")
    assert status == 0, output
    assert f"spec={PLUGIN_NAME}>=0.13\n" in written
    assert "python=3.14\n" in written
    assert "plugin=" not in written


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
            "PLUGIN_SPEC": "zorbleplugin==9.1",
            "VIRTUAL_ENV": "/venv",
        },
    )
    finished = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert result.returncode == 0, result.stdout + result.stderr
    install = calls.read_text(encoding="utf-8").splitlines()[0].split()
    assert install[:6] == [
        "pip",
        "install",
        "--python",
        "/venv/bin/python",
        "homeassistant==2026.3.0",
        "zorbleplugin==9.1",
    ]
    assert install[install.index("--requirement", 7) + 1] == "requirements_test.txt"
    assert install[install.index("--exclude-newer") + 1] == "2026-03-11T12:00:00Z"
    # The integration's own requirements are resolved as of now.
    name, cutoff = install[install.index("--exclude-newer-package") + 1].split("=")
    assert name == "zorblelib"
    assert started <= cutoff <= finished


def test_tests_install_into_a_virtual_environment(repo: Repo, tmp_path: Path) -> None:
    # A self-hosted runner keeps the Python of the tool cache between jobs, so
    # no step may install into it.
    fake = tmp_path / "bin"
    fake.mkdir()
    calls = tmp_path / "calls"
    uv = fake / "uv"
    uv.write_text(f'#!/bin/sh\necho "$UV_CACHE_DIR" "$@" >> {calls}\n', encoding="utf-8")
    uv.chmod(0o755)
    (tmp_path / "runner").mkdir()
    github_path = tmp_path / "github_path"
    github_env = tmp_path / "github_env"
    result = run_step(
        repo,
        tmp_path,
        "Create a virtual environment",
        bin_dir=fake,
        extra={"GITHUB_PATH": str(github_path), "GITHUB_ENV": str(github_env)},
    )
    assert result.returncode == 0, result.stdout + result.stderr
    venv = tmp_path / "runner" / "ha-tests-venv"
    cache = tmp_path / "runner" / "uv-cache"
    python = shutil.which("python", path=str(Path(sys.executable).parent))
    assert calls.read_text(encoding="utf-8").split() == [
        str(cache),
        "venv",
        "--quiet",
        "--python",
        str(python),
        str(venv),
    ]
    assert github_env.read_text(encoding="utf-8") == f"VIRTUAL_ENV={venv}\nUV_CACHE_DIR={cache}\n"
    # Home Assistant installs an older uv into the environment, which would
    # run instead of the pinned one from the next step on.
    assert not github_path.exists()
    for workflow in WORKFLOWS.glob("*.yml"):
        assert "--system" not in workflow.read_text(encoding="utf-8"), workflow.name


def test_only_the_test_step_runs_from_the_virtual_environment(repo: Repo, tmp_path: Path) -> None:
    venv = tmp_path / "venv"
    (venv / "bin").mkdir(parents=True)
    calls = tmp_path / "calls"
    for name in ("python", "uv"):
        tool = venv / "bin" / name
        tool.write_text(f'#!/bin/sh\necho {name} "$@" >> {calls}\n', encoding="utf-8")
        tool.chmod(0o755)
    (tmp_path / "runner").mkdir()
    extra = {"VIRTUAL_ENV": str(venv)}
    assert run_step(repo, tmp_path, "Run tests", extra=extra).returncode == 0
    assert [line.split()[:3] for line in calls.read_text(encoding="utf-8").splitlines()] == [
        ["python", "-m", "pytest"],
        ["python", "-m", "coverage"],
    ]
    calls.unlink()
    fake = tmp_path / "bin"
    fake.mkdir()
    pinned = fake / "uv"
    pinned.write_text(f'#!/bin/sh\necho pinned "$@" >> {calls}\n', encoding="utf-8")
    pinned.chmod(0o755)
    result = run_step(repo, tmp_path, "Prune uv cache", extra=extra, bin_dir=fake)
    assert result.returncode == 0, result.stdout + result.stderr
    assert calls.read_text(encoding="utf-8").split() == ["pinned", "cache", "prune", "--ci"]


def build_app(
    repo: Repo, tmp_path: Path, build: object | None, config: object | None = None
) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    """Run the build step of ha-app.yml on an app whose files hold the given data.

    The stand-in yq prints the JSON written next to each file, as yq -o=json
    would print the YAML.
    """
    fake = tmp_path / "bin"
    fake.mkdir(exist_ok=True)
    calls = tmp_path / "docker.log"
    (fake / "yq").write_text('#!/bin/sh\ncat "$3.json"\n', encoding="utf-8")
    (fake / "docker").write_text(
        f'#!/bin/sh\nfor arg in "$@"; do echo "$arg"; done > {calls}\n', encoding="utf-8"
    )
    for name in ("yq", "docker"):
        (fake / name).chmod(0o755)
    for name, data in (("build.yaml", build), ("config.yaml", config)):
        if data is not None:
            repo.write(f"zorble/{name}", "unused: true\n")
            repo.write(f"zorble/{name}.json", json.dumps(data))
    result = subprocess.run(
        [
            "bash",
            "-e",
            "-o",
            "pipefail",
            "-c",
            step_script("Build image", WORKFLOWS / "ha-app.yml"),
        ],
        cwd=repo.root,
        env={**os.environ, "PATH": f"{fake}{os.pathsep}{os.environ['PATH']}", "APP_PATH": "zorble"},
        capture_output=True,
        text=True,
        check=False,
    )
    args = calls.read_text(encoding="utf-8").splitlines() if calls.exists() else []
    return result, args


def build_args(args: list[str]) -> list[str]:
    return [args[index + 1] for index, arg in enumerate(args) if arg == "--build-arg"]


DEFAULT_BASE = "BUILD_FROM=ghcr.io/home-assistant/amd64-base:latest"


@pytest.mark.parametrize(
    ("build", "base"),
    [
        (
            {"build_from": {"amd64": "ghcr.io/zorble/amd64:1", "aarch64": "x"}},
            "ghcr.io/zorble/amd64:1",
        ),
        ({"build_from": "ghcr.io/zorble/base:2"}, "ghcr.io/zorble/base:2"),
        ({"build_from": {"aarch64": "x"}}, DEFAULT_BASE.split("=", 1)[1]),
        ({"args": {}}, DEFAULT_BASE.split("=", 1)[1]),
        (None, DEFAULT_BASE.split("=", 1)[1]),
    ],
)
def test_app_build_from(repo: Repo, tmp_path: Path, build: object, base: str) -> None:
    result, args = build_app(repo, tmp_path, build)
    assert result.returncode == 0, result.stdout + result.stderr
    assert build_args(args) == ["BUILD_ARCH=amd64", f"BUILD_FROM={base}"]
    assert args[-1] == "zorble"


def test_app_build_arguments(repo: Repo, tmp_path: Path) -> None:
    build = {"args": {"ZORBLE_VERSION": "1.2", "WORKERS": 4, "BUILD_ARCH": "custom"}}
    result, args = build_app(repo, tmp_path, build, {"version": "0.3.0", "slug": "zorble"})
    assert result.returncode == 0, result.stdout + result.stderr
    assert build_args(args) == [
        "BUILD_ARCH=amd64",
        DEFAULT_BASE,
        "BUILD_VERSION=0.3.0",
        "ZORBLE_VERSION=1.2",
        "WORKERS=4",
        # The build file's own arguments come last, so they win.
        "BUILD_ARCH=custom",
    ]


def test_app_build_rejects_other_build_from(repo: Repo, tmp_path: Path) -> None:
    result, args = build_app(repo, tmp_path, {"build_from": ["ghcr.io/zorble/base:2"]})
    assert result.returncode == 1
    assert "::error::zorble: build_from must be an image or a map" in result.stdout
    assert args == []
