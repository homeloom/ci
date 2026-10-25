"""Keep the files of this repository in sync with the templates it ships."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
COMMON = ROOT / "templates" / "common"
# dependabot.yml differs on purpose: its header points to the tools that
# Dependabot cannot update in this repository.
SHARED = sorted(
    path.relative_to(COMMON)
    for path in COMMON.rglob("*")
    if path.is_file() and path.name != "dependabot.yml"
)


@pytest.mark.parametrize("relative", SHARED, ids=str)
def test_root_matches_template(relative: Path) -> None:
    assert (ROOT / relative).read_bytes() == (COMMON / relative).read_bytes()


def test_workflow_templates_use_placeholder_pins() -> None:
    for workflow in (ROOT / "templates").glob("*/.github/workflows/*.yml"):
        for line in workflow.read_text(encoding="utf-8").splitlines():
            if "homeloom/ci/" in line:
                assert "@REPLACE_WITH_RELEASE_SHA # vX.Y.Z" in line, workflow


CALLERS = [
    ROOT / ".github" / "workflows" / "ci.yml",
    *sorted(ROOT.glob("templates/*/.github/workflows/ci.yml")),
]


@pytest.mark.parametrize("workflow", CALLERS, ids=lambda path: str(path.relative_to(ROOT)))
def test_no_job_runs_on_drafts(workflow: Path) -> None:
    # Skipped jobs cost no runner minutes, and GitHub never merges a draft.
    jobs = workflow.read_text(encoding="utf-8").split("\njobs:\n", 1)[1]
    blocks = re.split(r"\n(?=  [\w-]+:\n)", "\n" + jobs)
    conditions = {
        block.split(":", 1)[0].strip(): re.findall(r"^    if: (.+)$", block, re.MULTILINE)
        for block in blocks
        if block.strip() and not block.lstrip().startswith("#")
    }
    assert "report" in conditions
    for job, found in conditions.items():
        assert found, job
        assert "github.event.pull_request.draft != true" in found[0], job
    assert conditions["report"] == ["${{ always() && github.event.pull_request.draft != true }}"]
