"""Download retries of actions/setup-tools/install.sh."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

INSTALL = Path(__file__).resolve().parent.parent / "actions" / "setup-tools" / "install.sh"
# A curl stand-in that fails as many times as FAKE_CURL_FAILURES says, then
# writes an archive whose digest matches nothing, and a sleep stand-in; both
# record their calls.
FAKE_CURL = """\
#!/usr/bin/env bash
calls="${FAKE_CALLS}/curl"
echo call >> "$calls"
if (( $(wc -l < "$calls") <= FAKE_CURL_FAILURES )); then
  echo "curl: (22) The requested URL returned error: 403" >&2
  exit 22
fi
while (( $# )); do
  if [[ "$1" == --output ]]; then
    echo "not the pinned archive" > "$2"
  fi
  shift
done
"""
FAKE_SLEEP = """\
#!/usr/bin/env bash
echo "$1" >> "${FAKE_CALLS}/sleep"
"""


def install(tmp_path: Path, failures: int) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, script in (("curl", FAKE_CURL), ("sleep", FAKE_SLEEP)):
        (bin_dir / name).write_text(script, encoding="utf-8")
        (bin_dir / name).chmod(0o755)
    calls = tmp_path / "calls"
    calls.mkdir()
    (tmp_path / "temp").mkdir()
    env = {
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "FAKE_CALLS": str(calls),
        "FAKE_CURL_FAILURES": str(failures),
        "RUNNER_OS": "Linux",
        "RUNNER_ARCH": "X64",
        "RUNNER_TEMP": str(tmp_path / "temp"),
        "GITHUB_PATH": str(tmp_path / "github_path"),
        "TOOLS": "actionlint",
    }
    result = subprocess.run(
        ["bash", str(INSTALL)], env=env, capture_output=True, text=True, check=False
    )
    curl_calls = (calls / "curl").read_text(encoding="utf-8").splitlines()
    sleeps = (calls / "sleep").read_text().split() if (calls / "sleep").exists() else []
    return result, [str(len(curl_calls)), *sleeps]


def test_a_download_that_fails_is_tried_again_and_still_checked(tmp_path: Path) -> None:
    result, calls = install(tmp_path, failures=2)
    # Two failures, two growing waits, then a download whose digest is wrong.
    assert calls == ["3", "5", "15"]
    assert result.returncode != 0
    assert "FAILED" in result.stdout
    assert result.stdout.count("::warning::Download of actionlint") == 2
    assert not (tmp_path / "temp" / "ci-tools" / "bin" / "actionlint").exists()


def test_a_download_stops_after_three_attempts(tmp_path: Path) -> None:
    result, calls = install(tmp_path, failures=3)
    assert calls == ["3", "5", "15"]
    assert result.returncode == 1
    assert "::error::Could not download actionlint " in result.stdout
    assert "after 3 attempts." in result.stdout
    assert "FAILED" not in result.stdout


def test_a_first_download_is_not_delayed(tmp_path: Path) -> None:
    result, calls = install(tmp_path, failures=0)
    assert calls == ["1"]
    assert result.returncode != 0
    assert "FAILED" in result.stdout
