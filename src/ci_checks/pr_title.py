"""Check that the pull request title follows Conventional Commits.

Squash merging turns the title into the commit subject on the default
branch, so the title is what the history and the changelog are built from.
"""

from __future__ import annotations

import argparse
import re
import sys

from ci_checks._common import Reporter, load_event, pull_request, split_list

DEFAULT_TYPES = "build chore ci docs feat fix perf refactor revert style test"
MAX_LENGTH = 100
# The title GitHub gives to the pull request of its Revert button.
_REVERT = re.compile(r'Revert "(?P<title>.+)"')


def title_problem(title: str, types: list[str], max_length: int = MAX_LENGTH) -> str | None:
    """Return why a title is not a valid Conventional Commits subject, or None.

    A revert title from GitHub, `Revert "<title>"`, is valid when the title
    it reverts is.
    """
    reverted = title
    while revert := _REVERT.fullmatch(reverted):
        reverted = revert.group("title")
    problem = _subject_problem(reverted, types)
    if problem is None and len(title) > max_length:
        problem = f"Title must be at most {max_length} characters long (it has {len(title)})."
    return problem


def _subject_problem(title: str, types: list[str]) -> str | None:
    """Return why a title breaks the format rules, whatever its length, or None."""
    scope = r"[a-z0-9][a-z0-9._/-]*"
    pattern = re.compile(
        rf"^(?P<type>{'|'.join(map(re.escape, types))})"
        rf"(?:\((?P<scope>{scope}(?:, ?{scope})*)\))?"
        r"(?P<breaking>!)?: (?P<subject>\S.*)$"
    )
    match = pattern.match(title)
    if not match:
        return (
            "Title must look like `type(scope): subject` with a type among: "
            + ", ".join(types)
            + "."
        )
    subject = match.group("subject")
    if subject.endswith("."):
        return "Subject must not end with a period."
    # Proper nouns and acronyms with other capitals (GitHub, MQTT) keep their case.
    first = subject.split()[0]
    if first[0].isupper() and not any(char.isupper() for char in first[1:]):
        return "Subject must start with a lowercase letter."
    return None


def main(argv: list[str] | None = None) -> int:
    """Run the title check from the command line."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--types", default=DEFAULT_TYPES)
    parser.add_argument("--max-length", type=int, default=MAX_LENGTH)
    args = parser.parse_args(argv)

    reporter = Reporter("Pull request title")
    pr = pull_request(load_event())
    if pr is None:
        print("Not a pull request event; nothing to check.")
        return 0
    problem = title_problem(pr.title, split_list(args.types), args.max_length)
    if problem:
        reporter.error(problem)
    return reporter.finish()


if __name__ == "__main__":
    sys.exit(main())
