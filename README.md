# homeloom CI

Shared GitHub Actions workflows and checks for the Home Assistant
repositories of the homeloom organization: integrations, apps and the tools
around them. Every repository is treated as public from its first commit, so
the checks focus on code quality, licensing and keeping personal data out of
the code and the history.

## Contents

| Path | What it is |
| --- | --- |
| `.github/workflows/hygiene.yml` | Pull request title, secrets and personal data, English, licenses, workflow lint. One job. |
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
removing a job never requires a settings change. Draft pull requests skip
every job, Report included; marking the pull request ready for review starts
one full run. Runs of the same pull request cancel each other.

### hygiene.yml

| Input | Default | Description |
| --- | --- | --- |
| `allowed-domains` | | Extra domains allowed in URLs. |
| `privacy-exclude` | | Globs skipped by the generic personal data patterns. |
| `require-denylist` | `true` | Fail when the `PRIVACY_DENYLIST` secret is empty. Fork pull requests only warn. |
| `english-exclude` | | Globs skipped by the language check. |
| `license` | `MIT` | SPDX identifier the LICENSE file must match. |
| `license-requirements` | | Extra runtime requirements files whose licenses are checked. |
| `license-allowed` | | SPDX identifiers that replace the default allowed list. |
| `license-exceptions` | | Packages exempted after a manual license review. |

Secret: `PRIVACY_DENYLIST`, one term per line (lines starting with `#` are
comments). Matching ignores case and accents and respects word boundaries.

What it checks:

- **Pull request title**: Conventional Commits, at most 100 characters.
- **Secrets**: gitleaks over the whole history.
- **Personal data**: private IP addresses, e-mail addresses that are not
  noreply, phone numbers, URLs outside an allowlist, home directory paths,
  MAC addresses and coordinates, in files, commit messages and the pull
  request title and body. Commit authors and committers must use noreply
  addresses. The denylist applies to all of that plus file paths and the
  branch name. Findings report where, never what, so logs do not repeat the
  data.
- **English**: French text outside translation files, in files, new commit
  messages and the pull request title and body.
- **Licenses**: a LICENSE file, and allowed licenses for every runtime
  dependency (manifest `requirements` and extra requirements files,
  transitive dependencies included).
- **Workflows**: actionlint with shellcheck.

A line that is not personal data despite matching a pattern can opt out of
one category with a comment such as `# ci-allow: private-ip`. The categories
are `private-ip`, `email`, `phone`, `url`, `home-path`, `mac`, `coordinates`
and `french`. The denylist and gitleaks cannot be opted out of
(gitleaks has its own `gitleaks:allow` comment, which reviewers must
question).

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

- **Actions access**: this repository is accessible from repositories in
  the organization (Settings, Actions, General, Access).
- **Secrets**: `PRIVACY_DENYLIST` exists as an organization Actions secret
  and as an organization Dependabot secret, both available to every
  repository that calls `hygiene.yml`.
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
  minute.

## Maintenance

- Dependabot updates the action pins and the test dependencies.
- To update a tool, change its version and digest together in
  `actions/setup-tools/install.sh`, using the checksums published with the
  upstream release.
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
