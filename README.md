# homeloom CI

Shared GitHub Actions workflows and checks for the Home Assistant
repositories of the homeloom organization: integrations, apps and the tools
around them. Every repository is treated as public from its first commit, so
the checks focus on code quality, licensing and keeping personal data out of
the code and the history.

## Contents

| Path | What it is |
| --- | --- |
| `.github/workflows/hygiene.yml` | Pull request title, secrets and personal data, English and workflow lint in one job; licenses in a second job. |
| `.github/workflows/python-lint.yml` | Ruff lint and format check. |
| `.github/workflows/ha-tests.yml` | pytest on the oldest supported and the latest Home Assistant, with a coverage threshold. |
| `.github/workflows/ha-integration.yml` | hassfest, plus HACS validation once the repository is public. |
| `.github/workflows/ha-app.yml` | Home Assistant app lint and an amd64 image build. |
| `.github/workflows/release.yml` | Publish `v<version>` with notes from `CHANGELOG.md` when the tag is missing. |
| `actions/` | Composite actions used by the workflows. Each can also be used on its own. |
| `src/ci_checks/` | The Python checks behind the actions (standard library only). |
| `templates/` | Files to copy into each repository, including the calling workflows. |
| `REVIEW.md` | The review checklist every change must pass. |
| `AGENTS.md` | Rules for anyone, human or AI agent, who contributes. |

## Using the workflows

Copy the workflows from `templates/integration/` or `templates/app/` and pin
`homeloom/ci` to the commit SHA of a release, as the organization policy
requires. See [templates/README.md](templates/README.md).

A typical integration CI calls four workflows and ends with a **Report** job
that needs all of them. Branch protection requires Report only, so adding or
removing a job never requires a settings change.

- Draft pull requests only run the hygiene job, which takes seconds and
  finds personal data as soon as it is pushed. Report then fails with
  "Draft pull request: only the hygiene checks ran". A skipped required check
  would count as passed, so Report always runs and only passes when every
  job it needs succeeded.
- Marking the pull request ready for review starts one full run.
- Editing the title or body starts a new run, because the title becomes the
  squash commit message and both are checked for personal data.
- Runs of the same pull request cancel each other. Runs on `main` never do,
  so that every commit is checked.

Push a branch only together with its draft pull request: a branch without
one is not checked. A force push does not remove anything from GitHub, where
the old commits stay reachable; if personal data or a secret was pushed,
tell a maintainer instead.

The composite actions in `actions/` can also be used on their own. The
privacy and English actions read the history, so they need a checkout with
`fetch-depth: 0`; on a shallow checkout they stop with an error instead of
silently checking less.

### hygiene.yml

| Input | Default | Description |
| --- | --- | --- |
| `allowed-domains` | | Extra domains allowed in URLs and noreply addresses. |
| `privacy-exclude` | | Globs skipped by the generic personal data patterns. |
| `require-denylist` | `true` | Fail when no `PRIVACY_DENYLIST*` secret holds a term, including on fork pull requests. |
| `english-exclude` | | Globs skipped by the language check. |
| `english-allowed-words` | | Words the language check accepts, such as accented brand names. |
| `license` | `MIT` | SPDX identifier the LICENSE file must match. |
| `license-requirements` | | Extra runtime requirements files whose licenses are checked. |
| `license-allowed` | | SPDX identifiers that replace the default allowed list. |
| `license-exceptions` | | Packages exempted after a manual license review. |

Secrets: every secret whose name starts with `PRIVACY_DENYLIST`, such as
`PRIVACY_DENYLIST` and `PRIVACY_DENYLIST_STREETS`, holds a denylist, one term
per line (lines starting with `#` are comments). The check merges them all.
A secret cannot be read back, so separate lists let each one be replaced
whole without retyping the others. Callers pass them with
`secrets: inherit` (see the design notes). The log shows how many lists were
read and how many are empty, never their names or their terms.

Matching ignores case, accents and invisible characters such as soft
hyphens, respects word boundaries and accepts any punctuation, underscore,
line break or nothing at all between the words of a term, so `First Last`
also matches `first_last`, `First-Last`, `FirstLast` and a `First` that ends
one line followed by a `Last` that starts the next. Terms of five letters or
more also match as a part of a camel case name, such as `getFirstLast`. Text
that writes characters as escapes (`\u00e9`, `\x41`, `\n`, `%20`, `&eacute;`)
is also matched decoded. List only terms that never belong in a repository:
not the GitHub usernames of maintainers, which appear in noreply addresses
and attributions, and not common words, which also match inside names such
as `max_value`, since the denylist has no exceptions.

The first step of the job masks the common spellings of each term (as
written, in lower, upper and title case, without accents, with spaces,
underscores, hyphens, dots or nothing between words) for the rest of the job
log, before the checkout prints the branch names. Masking is a safety net
that cannot cover every spelling: the checks never print a term, and they
redact the file paths they print.

The **Hygiene** job checks:

- **Pull request title**: Conventional Commits, at most 100 characters.
- **Secrets**: gitleaks over the whole history of the pull request head,
  with the default rules. The action passes its own configuration and runs
  outside the checkout, so a `.gitleaks.toml` or `.gitleaksignore` in the
  repository has no effect.
- **Personal data** with generic patterns: private and link-local IP
  addresses, global IPv6 addresses, e-mail addresses that are not noreply,
  phone numbers, URLs of any scheme whose host is outside an allowlist or is
  a public IP address, home directory paths, MAC addresses, Zigbee and
  Thread device addresses (EUI-64) and coordinates. They apply to:
  - every tracked text file and symbolic link target;
  - every file written by the commits of the pull request or push,
    including lines and files that a later commit removes, because those
    commits stay reachable after the merge (merge commits count with the
    lines they add themselves);
  - the messages of those commits;
  - the pull request title and body.
- **Commit identities**: authors and committers of the whole history must
  use GitHub noreply addresses, or a `noreply` mailbox at an allowed domain.
- **Binary files**: the metadata of images and documents (PNG text chunks,
  JPEG comments, EXIF with its GPS position, IPTC, XMP and the information
  fields of PDF files) goes through the generic patterns except URLs, and a
  GPS position counts as coordinates.
- **Denylist**: everything above, plus the readable strings of binary files,
  file paths, the commit authors, committers and messages of the whole
  history, and the branch name.
- **Unreadable content**: a file stored with Git LFS fails the check, because
  only its pointer is in the repository while its content is published
  unchecked. So does a tracked file missing from the checkout.
- **English**: French text outside translation files, in files, new commit
  messages and the pull request title and body.
- **Workflows**: actionlint with shellcheck.

The first push of a branch, a force push and a manual run check every commit
of the history as new.

The **Licenses** job checks that the LICENSE file matches the expected
license and that every runtime dependency (manifest `requirements` and
extra requirements files, transitive dependencies included) has an allowed
license. Installing packages may run their build code, so this job runs
separately and never receives the denylist secret.

Findings report where something was found, never what, so logs do not
repeat the data. When a file path contains a denylisted term, the matching
path segments are shown as `[redacted]`.

A line that is not personal data despite matching a pattern can opt out of
one category with a comment such as `# ci-allow: private-ip`. The categories
are `private-ip`, `public-ip`, `email`, `phone`, `url`, `home-path`, `mac`,
`device-id`, `coordinates` and `french`. The denylist and gitleaks cannot be
opted out of. gitleaks has its own `gitleaks:allow` comment; the privacy
check warns about every added line that uses it, and reviewers must
question it.

Exemptions, kept narrow on purpose:

- License files (`LICENSE`, `LICENCE`, `COPYING` and `NOTICE`, with an
  optional suffix such as `-APACHE` or `.md`) skip the generic patterns,
  because license texts quote their authors' sites.
- Dependabot commits skip the generic patterns for their added lines and
  messages, and its pull request body skips them too, because these quote
  upstream release notes and carry service addresses in trailers. In a pull
  request this only applies when Dependabot opened it, since anyone can
  write a bot address into a commit. The denylist still applies.
- Fork pull requests do not receive secrets, so the denylist cannot run on
  them: the check fails, and a maintainer pushes the branch to the
  repository to run it.

Limits:

- The generic patterns cannot recognize names, street addresses or public
  IPv4 addresses outside URLs (they look like version numbers), nor text in
  images, archives or encoded data. The denylist and the review cover what
  the patterns cannot.
- In binary files, terms of three or four letters only count inside phrases
  of several words (such as a title in image metadata), and shorter terms not
  at all, because random bytes spell short words by chance. Single byte
  (Latin-1) strings are only searched for the longer terms. PDF files are
  always read as binary files.
- Files larger than 20 MB are skipped with a warning.

### python-lint.yml

| Input | Default | Description |
| --- | --- | --- |
| `path` | `.` | Directory to lint. |

### ha-tests.yml

| Input | Default | Description |
| --- | --- | --- |
| `homeassistant-minimum` | `homeassistant` in `hacs.json` | Oldest supported Home Assistant version. |
| `python-minimum` | `3.13` | Python used with the oldest version. |
| `python-latest` | `3.14` | Python used with the latest version. |
| `requirements` | `requirements_test.txt` | Test requirements, installed when the file exists. |
| `coverage-source` | `custom_components` | What coverage measures. |
| `coverage-minimum` | `90` | Minimum total coverage in percent. |

The workflow picks the versions of `homeassistant` and
`pytest-homeassistant-custom-component`, so the test requirements must not
pin them. Runtime requirements from the manifests are installed too.

### ha-integration.yml

| Input | Default | Description |
| --- | --- | --- |
| `hacs-ignore` | | HACS checks to skip. |

HACS validation only runs on public repositories, because HACS cannot read
private ones.

### ha-app.yml

| Input | Default | Description |
| --- | --- | --- |
| `paths` | required | JSON array of app directories. |

The image base comes from `build_from.amd64` in `build.yaml` or `build.json`
when present.

### release.yml

| Input | Default | Description |
| --- | --- | --- |
| `sha` | required | Commit to release. |
| `version-file` | the only integration manifest | `manifest.json`, `config.yaml`, `pyproject.toml` or a plain text file. |
| `changelog` | `CHANGELOG.md` | Changelog with a `## [<version>]` section per release. |

Call it from a workflow triggered by `workflow_run` after CI succeeds on a
push to `main` (see the templates). Versions with a pre-release suffix are
published as pre-releases.

## Organization settings

- **Visibility**: GitHub only lets private repositories use workflows and
  actions from a private repository. This repository must be made public
  before the first repository that calls it becomes public.
- **Actions access**: while private, this repository is accessible from
  repositories in the organization (Settings, Actions, General, Access).
- **Secrets**: each denylist secret (a name starting with `PRIVACY_DENYLIST`)
  exists as an organization Actions secret and as an organization Dependabot
  secret of the same name, both available to every repository that calls
  `hygiene.yml`.
- **Dependabot**: allowed to read this private repository, so it can update
  the pins in other repositories.
- **Rulesets**: `main` requires a pull request, squash merging and the
  **Report** check.

## Design notes

- Composite actions are referenced with the `$/` self repository syntax.
  It resolves to this repository at the commit of the running workflow, so a
  caller pinned to one SHA gets workflows and scripts from that same SHA,
  with no extra pin to maintain.
- Third party actions are pinned by SHA. Tools that are not actions
  (actionlint, gitleaks, Ruff, uv) are downloaded from their releases and
  checked against SHA-256 digests in `actions/setup-tools/install.sh`.
- The checks use the Python standard library only and run on the system
  Python of the runner, so the hygiene job installs nothing but its tools.
- Cheap checks share one job, because GitHub bills each job by the started
  minute. The license check is the exception: it installs third party
  packages, so it runs in a job without secrets.
- The denylist secrets are passed with `secrets: inherit`, because GitHub
  cannot pass secrets by a name pattern. The reusable workflow hands the
  secrets context, as JSON, only to the steps that run this repository's own
  Python code (masking, privacy and English). That code keeps the
  `PRIVACY_DENYLIST*` values and removes the variable before it starts git;
  gitleaks, actionlint and the license job never receive it. As a
  consequence, a change to this repository could read every secret of the
  repositories that call it once they move their pin, so changes here go
  through the same review and ruleset as everywhere else. One environment
  variable holds at most 128 KiB on Linux, which bounds the total size of the
  secrets available to a repository.
- The hassfest and HACS actions are pinned by SHA, but they run container
  images that their maintainers publish under moving tags. This is an
  accepted risk: they are the official validators, and they run in a job
  with a read-only token and no secrets.

## Maintenance

- Dependabot updates the action pins and the test dependencies.
- Dependabot does not see the tools in `actions/setup-tools/install.sh`
  (actionlint, gitleaks, Ruff, uv). Check their releases when releasing
  this repository; to update one, change its version and digest together,
  using the checksums published with the upstream release.
- To release this repository, bump `version` in `pyproject.toml` and add the
  matching `CHANGELOG.md` section. Releases are tagged automatically once CI
  passes on `main`.

## Development

```sh
uv venv --python 3.12
uv pip install --require-hashes --requirement requirements-dev.txt
.venv/bin/python -m pytest
```

## License

[MIT](LICENSE)
