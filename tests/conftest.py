"""Fixtures shared by the tests."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from helpers import Repo


@pytest.fixture
def repo(tmp_path: Path) -> Repo:
    return Repo(tmp_path / "repo")


@pytest.fixture
def event(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Callable[[dict], None]:
    """Write an event payload and point GITHUB_EVENT_PATH at it."""

    def write(payload: dict) -> None:
        path = tmp_path / "event.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        monkeypatch.setenv("GITHUB_EVENT_PATH", str(path))

    monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)
    monkeypatch.delenv("CI_EVENT_PATH", raising=False)
    return write
