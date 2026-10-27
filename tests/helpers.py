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
        # Merges check the committer identity too, and runners have none.
        # Options given later, as in commit(), take precedence.
        identity = ["-c", "user.name=octocat", "-c", f"user.email={NOREPLY}"]
        return subprocess.run(
            ["git", *identity, *args],
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
    before: str = "",
) -> dict:
    """Return a minimal pull_request event payload.

    With `before`, it is the synchronize event of a push whose previous
    head was `before`.
    """
    event: dict = {
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
    if before:
        event.update(action="synchronize", before=before, after=head)
    return event


def merge_resolving_a_submodule(repo: Repo) -> tuple[str, str]:
    """Commit a merge that points a submodule to a commit neither parent had.

    Returns the first commit and the merge. The submodule commits are absent
    from the repository, as they usually are, and its folder stays empty.
    """
    (repo.root / "vendor" / "lib").mkdir(parents=True)
    pointers = iter(str(digit) * 40 for digit in range(1, 5))

    def point(message: str) -> str:
        repo.git("update-index", "--add", "--cacheinfo", f"160000,{next(pointers)},vendor/lib")
        return repo.commit(message)

    base = point("chore: add the library")
    repo.git("checkout", "--quiet", "-b", "side")
    side = point("chore: update the library")
    repo.git("checkout", "--quiet", "main")
    point("chore: update the library again")
    repo.git("update-index", "--cacheinfo", f"160000,{next(pointers)},vendor/lib")
    tree = repo.git("write-tree").strip()
    identity = ["-c", "user.name=octocat", "-c", f"user.email={NOREPLY}"]
    merge = repo.git(*identity, "commit-tree", tree, "-p", "HEAD", "-p", side, "-m", "Merge side")
    repo.git("update-ref", "HEAD", merge.strip())
    return base, merge.strip()
