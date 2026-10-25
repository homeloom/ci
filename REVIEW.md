# Review checklist

Every pull request in the organization is reviewed against this list before
it leaves draft. The reviewer is strict: a point that is not met is either
fixed or explained in a pull request comment, and the explanation must
convince someone who will maintain the code in two years. "It works" is not
an explanation.

Record the review as pull request comments, one per finding, each with its
severity:

- **Blocking**: must be fixed before merging.
- **Should fix**: fixed in this pull request unless a reply justifies it.
- **Nit**: optional; a one line reply is enough.

## 1. Security

- [ ] No secret, token, password or private key, in the code or in the
      history. Tokens in examples are obvious placeholders.
- [ ] Untrusted input (user configuration, API responses, files, event
      payloads) is validated before use. No `eval`, `exec`, `pickle` or
      shell built from strings.
- [ ] Network calls use HTTPS, verify certificates, set timeouts and handle
      errors and rate limits.
- [ ] Credentials are stored with Home Assistant config entries, never
      logged, never shown in diagnostics (use `async_redact_data`), never
      put in URLs that end up in logs.
- [ ] Files written to disk stay inside the expected directory (no path
      traversal), and downloads are verified before use.
- [ ] Workflows: actions pinned by full SHA; `permissions` minimal and set
      per job; no `pull_request_target` with a checkout of the pull request;
      no `${{ }}` expression of untrusted text inside `run:` (pass it through
      `env:`); `persist-credentials: false` unless pushing is needed.
- [ ] New dependencies are maintained, widely used and have an allowed
      license.

## 2. Privacy

- [ ] Nothing identifies a person, a home or a network: names, addresses,
      coordinates, IP or MAC addresses, serial numbers, device names, room
      names, pets, schedules, screenshots.
- [ ] Examples and tests use `example.com`, documentation IP ranges and
      neutral placeholders.
- [ ] Commit authors use noreply addresses; commit messages and the pull
      request text follow the same rules as the code.
- [ ] Every `ci-allow:` comment is justified, and every `gitleaks:allow` is
      questioned.
- [ ] No commit was force pushed away to hide data: a pushed commit stays
      reachable on GitHub, so a leak is reported to a maintainer instead.

## 3. Open and generic design

- [ ] The feature solves a general problem. Nothing is hard coded for one
      installation: options are configurable from the Home Assistant UI,
      with sensible defaults.
- [ ] No code for migrating from, or staying compatible with, a private
      setup that is not part of the project.
- [ ] Everything is in English. User facing text is in translation files.
- [ ] The README explains what the project does, how to install it, how to
      configure it and its limits, for someone who has never seen it.

## 4. Home Assistant practices

- [ ] Configuration through config flows (and options flows); YAML only as
      an optional extra.
- [ ] Async all the way: no blocking I/O in the event loop; the shared
      `aiohttp` session is used.
- [ ] Polling goes through a `DataUpdateCoordinator`; entities have unique
      IDs, `has_entity_name`, translation keys and device info.
- [ ] Unavailable devices or services raise the right exceptions
      (`ConfigEntryNotReady`, `ConfigEntryAuthFailed`, `UpdateFailed`) and
      recover on their own.
- [ ] Unloading a config entry releases everything it set up.
- [ ] The manifest is complete and passes hassfest; the minimum Home
      Assistant version is right in `hacs.json`.
- [ ] Apps: minimal image, no root unless required, options validated by
      the schema, data only in `/data`.

## 5. Maintainability

- [ ] Small, focused pull request with a Conventional Commits title and a
      template that is filled in.
- [ ] Clear names, small functions, no dead code, no commented out code, no
      duplicated logic.
- [ ] Comments explain why, not what. Public functions have docstrings.
- [ ] Type hints on all functions.
- [ ] Tests exercise real behavior, including errors and edge cases, not
      just the happy path; they are not written to chase coverage. Total
      coverage stays at or above 95 %.
- [ ] Every `# pragma: no cover` gives its reason
      (`# pragma: no cover - <reason>`), and reviewers question it as they
      question a skipped test.
- [ ] Lowering the coverage threshold (`coverage-minimum`) is justified in
      writing in the pull request.
- [ ] `CHANGELOG.md` and the documentation are updated.
- [ ] CI is green, and it stays fast.
