"""Keep the files of this repository in sync with the templates it ships."""

from __future__ import annotations

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
