# Rules for contributors and AI agents

These rules apply to every repository of the organization and to everyone
who changes them, people and AI coding agents alike. They come on top of
[CONTRIBUTING.md](CONTRIBUTING.md) and [REVIEW.md](REVIEW.md).

## Treat every repository as public

- Repositories may start private, but every commit is written as if it were
  public, because history cannot be cleaned later without rewriting it.
- No personal data anywhere: not in code, documentation, tests, commit
  messages, pull requests, issues or branch names. That includes the names
  of the people, places, devices and animals of any real home.
- Everything is in English, except translation files.
- Commit with a noreply e-mail address.
- Credit people by their GitHub username, never by their real name.

## Keep projects generic and simple

- Build for any user. Anything specific to one installation belongs in that
  installation's private configuration, not in a shared repository.
- Do not add code to migrate from, or stay compatible with, private systems.
  Old code can be reused only as generic logic, rewritten and reviewed as
  new code.
- Prefer the simplest design that works. Avoid configuration nobody asked
  for and abstractions with a single user.

## Pull requests

- Push a branch only together with its draft pull request. On drafts only the
  quick hygiene checks run; mark the pull request ready only when it is
  complete, so the full CI runs once.
- Never force push to hide personal data or a secret: the old commits stay
  reachable on GitHub. Report it to a maintainer instead.
- Keep at most three pull requests waiting for review per repository, each
  small enough to be read on its own.
- Before leaving draft, have the change reviewed against
  [REVIEW.md](REVIEW.md) by an independent reviewer (another person, or an
  agent that did not write the change). Fix each finding or answer it in a
  pull request comment.
- Explain design choices and review answers in pull request comments, so
  the reasoning stays next to the code.
- Only a maintainer, or an agent a maintainer has explicitly authorized,
  merges a pull request, and only once the Report check passes and every
  review finding is closed. Agents never change repository visibility or
  organization settings.

## CI

- The **Report** check must pass. Never skip, disable or weaken a check or a
  test to get a green run; fix the cause instead.
- Keep CI fast: under five minutes for a typical change.
- Pin third party actions by full commit SHA.
