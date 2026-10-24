"""Helpers shared by the tests."""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from pathlib import Path

NOREPLY = "1+octocat@users.noreply.github.com"
DEPENDABOT = "49699333+dependabot[bot]@users.noreply.github.com"
# The `event` fixture: writes an event payload for the checks to read.
EventWriter = Callable[[dict], None]


class Repo:
    """A throwaway git repository."""

    def __init__(self, root: Path) -> None:
        self.root = root
        root.mkdir(parents=True)
        self.git("init", "--quiet", "--initial-branch=main")

    def git(self, *args: str, env: dict[str, str] | None = None) -> str:
        return subprocess.run(
            ["git", *args],
            cwd=self.root,
            check=True,
            capture_output=True,
            text=True,
            env=env,
        ).stdout

    def write(self, path: str, content: str | bytes) -> None:
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            target.write_bytes(content)
        else:
            target.write_text(content, encoding="utf-8")

    def commit(
        self,
        message: str = "chore: update",
        name: str = "octocat",
        email: str = NOREPLY,
    ) -> str:
        identity = [
            "-c",
            f"user.name={name}",
            "-c",
            f"user.email={email}",
            "-c",
            "commit.gpgsign=false",
        ]
        self.git("add", "--all")
        self.git(*identity, "commit", "--quiet", "--allow-empty", "--message", message)
        return self.git("rev-parse", "HEAD").strip()


def pr_event(
    base: str,
    head: str,
    title: str = "feat: add a thing",
    body: str = "",
    login: str = "octocat",
    fork: bool = False,
) -> dict:
    """Return a minimal pull_request event payload."""
    return {
        "pull_request": {
            "title": title,
            "body": body,
            "user": {"login": login, "type": "Bot" if login.endswith("[bot]") else "User"},
            "base": {"sha": base, "repo": {"full_name": "owner/repo"}},
            "head": {
                "sha": head,
                "ref": "feature",
                "repo": {"full_name": "someone/repo" if fork else "owner/repo"},
            },
        }
    }
