"""Tests for the pull request title check."""

from __future__ import annotations

import pytest

from ci_checks import pr_title
from helpers import EventWriter, pr_event

TYPES = pr_title.DEFAULT_TYPES.split()


@pytest.mark.parametrize(
    "title",
    [
        "feat: add a sensor",
        "fix(api): handle timeouts",
        "feat!: drop the legacy option",
        "refactor(core/io)!: split the client",
        "docs: update README",
        "chore(deps): bump pytest-homeassistant-custom-component from 0.13.300 to 0.13.301",
    ],
)
def test_valid_titles(title: str) -> None:
    assert pr_title.title_problem(title, TYPES) is None


@pytest.mark.parametrize(
    ("title", "reason"),
    [
        ("Add a sensor", "type(scope): subject"),
        ("feature: add a sensor", "type(scope): subject"),
        ("feat:add a sensor", "type(scope): subject"),
        ("feat(API): add", "type(scope): subject"),
        ("feat: add a sensor.", "period"),
        ("feat: Add a sensor", "lowercase"),
        ("feat: " + "x" * 120, "at most"),
    ],
)
def test_invalid_titles(title: str, reason: str) -> None:
    problem = pr_title.title_problem(title, TYPES)
    assert problem is not None
    assert reason in problem


def test_main(event: EventWriter, capsys: pytest.CaptureFixture[str]) -> None:
    event({})
    assert pr_title.main([]) == 0
    assert "Not a pull request event" in capsys.readouterr().out

    event(pr_event("a", "b", title="feat: add a sensor"))
    assert pr_title.main([]) == 0

    event(pr_event("a", "b", title="Add a sensor"))
    assert pr_title.main([]) == 1
    assert pr_title.main(["--types", "add", "--max-length", "200"]) == 1
