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
| `.github/workflows/release.yml` | Publish `v<version>` with notes from `CHANGELOG.md` when the tag is missing, optionally with a zip built from the repository. |
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

- Draft pull requests run no job at all, so that work in progress costs no
  runner minutes. GitHub never merges a draft, so the skipped Report, which
  branch protection counts as passed, lets nothing through.
- Marking the pull request ready for review starts one full run. Report runs
  after failed or cancelled jobs too, and only passes when every job it
  needs succeeded.
- Editing the title or body starts a new run, because the title becomes the
  squash commit message and both are checked for personal data.
- Runs of the same pull request cancel each other. Runs on `main` never do,
  so that every commit is checked.

Nothing is checked before the pull request is ready for review, so run the
checks locally on a draft, and never push personal data or a secret: a force
push does not remove anything from GitHub, where the old commits stay
reachable. If personal data or a secret was pushed, tell a maintainer
instead.

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
| `english-allowed-words` | | Words the language check accepts, such as brand names with accents or made of French words (hyphenated ones included). |
| `secrets-ignore` | | Fingerprints (`commit:path:rule:line`) of known gitleaks false positives already on the base branch, one per line; each is reported as a warning. |
| `license` | `MIT` | SPDX identifier the LICENSE file must match. |
| `license-requirements` | | Extra runtime requirements files whose licenses are checked. |
| `license-allowed` | | SPDX identifiers that replace the default allowed list. |
| `license-exceptions` | | Packages exempted after a manual license review. |
| `license-python-version` | `3.14` | Python version used to resolve the runtime dependencies. |

The calling job grants `contents: read` and `pull-requests: read`. The
second lets the checks read the current pull request title and body: a run
that is started again keeps the event of its first attempt, whose text may
have been edited since.

Secrets: every secret whose name starts with `PRIVACY_DENYLIST`, such as
`PRIVACY_DENYLIST` and `PRIVACY_DENYLIST_2`, holds a denylist, one term per
line (lines starting with `#` are comments). The check merges them all.
A secret cannot be read back, so separate lists let each one be replaced
whole without retyping the others. Callers pass them with
`secrets: inherit` (see the design notes). The checks print how many lists
were read and how many are empty, never a term. GitHub itself shows the
secrets context in the step headers of the Hygiene job with every value
masked, so the name of every secret the repository can see appears in the
logs: give all of them neutral names, and the denylists numbered names that
say nothing about their content. GitHub also masks
each line of a secret everywhere in the log, so a line made only of `#`
signs hides those signs in the whole log; start comments with `# ` and a
word.

Matching ignores case, accents and invisible characters such as soft hyphens,
respects word boundaries and accepts any punctuation, underscore, line break
or nothing at all between the words of a term, so `First Last` also matches
`first_last`, `First-Last`, `FirstLast` and a `First` that ends one line
followed by a `Last` that starts the next. A camel case term such as
`FirstLast` matches the same spellings, except that where one of its parts
has three letters or less, as in `LeBlanc`, only nothing or one punctuation
character may separate them, unless the text writes the next part with a
capital after white space, as names are written: `LeBlanc` matches
`Le Blanc` and `LE BLANC`, but not the words `le blanc` of a sentence. A
term that glues digits after letters, such as `Name5G`, also matches
`Name 5G`. Terms of five letters and digits or more also match as a part of
a camel case name, such as `getFirstLast`, and, unless they are spelled only
with hexadecimal digits, next to digits, such as `FirstLast2`. Numbers
follow stricter rules: a number never touches another digit or a dot
followed by a digit, nor a letter, except a `v` that starts a word before a
number the text writes with a dot, as in `v12.3.0`; two numbers are
separated by exactly one space, dot, dash or underscore; a word and the
number after it by anything but a comma or a colon, unless the comma or
colon comes right after the word and before a space or a tab, as in
`Quillmore Lane, 12`, which unquoted lists such as `[bus, 917]` also match;
and a number and the word after it by anything but a colon. A term that
starts or ends with two numbers is not found inside a longer run of
numbers, such as the coordinates of an SVG path, though a number that ends
or starts a word, as in `eth0` or `2nd`, does not count. Terms of eight
digits or more, such as phone numbers, also match with their numbers glued
or separated by any run of spaces, any dash with or without spaces around
it, or a line break, and two numbers that a term separates with a comma may
have any white space around it or none. So `12.3.0` matches `12 3 0`,
`12_3_0` and `v12.3.0`, but not `2026-12-30`, `12:30`, `1230`, `[12, 3, 0]`,
`v1.12.3.0`, `M12.3 0` or `matrix(12 3 0 1 5 5)`, `06 39 98 12 34` also
matches `0639981234`, `06–39–98–12–34` and `06 - 39 98 12 34`, and `step 12`
matches `step: 12` but not `"step": 12`, `["step", 12]` or `step:` followed
by `12` on the next line. A term always matches as it is written, so
`03/12/1985` and `12, Quillmore Street` match themselves. Text that writes
characters as escapes (`\u00e9`, `\x41`, `\n`, `\b`, `%20`, `&eacute;`, or
`&eacute` without a semicolon) is also matched decoded, once and twice, for
escapes that were themselves escaped, such as `&amp;quot;`, and with a
backslash followed by a letter left as written, for words that follow a
backslash, as in `C:\Users\name`. Enclosing marks, such as keycaps, are
not invisible: they separate what they enclose from what follows. List only
terms that never belong in a repository: not the GitHub usernames of
maintainers, which appear in noreply addresses and attributions, and not
common words, which also match inside names such as `max_value`, since the
denylist has no exceptions.

The first step of the job masks the common spellings of each term (as
written, in lower, upper and title case, without accents, with spaces,
underscores, hyphens, dots or nothing between words and between letters and
the digits after them, except that two numbers of a short term are never
masked glued, and a term of two numbers alone, such as `12 30`, is not
masked with a dash unless it is written so, since spellings such as `1230`
or `12-30` are common in logs) for the rest of the job log, before the
checkout prints the branch names. Masking is a safety net that cannot cover
every spelling: the checks never print a term, and they redact the file
paths they print.

The **Hygiene** job checks:

- **Pull request title**: Conventional Commits, at most 100 characters.
- **Secrets**: gitleaks over the whole history of the pull request head,
  with the default rules of gitleaks 8.30.1, minus their allowlists of paths
  and values (lock files, `node_modules`, virtual environments, images and
  the GitHub token rules' `@octokit/auth-token/README.md`). Package versions
  in JavaScript lock files (`package-lock.json`, `npm-shrinkwrap.json`,
  `pnpm-lock.yaml`, `bun.lock`) are accepted by the `generic-api-key` rule.
  Commit messages, the pull request title and body, and the lines added to
  UTF-16 (with or without a byte order mark) or UTF-32 files, to the text
  files that ZIP, gzip and PDF files hold compressed, and to paths ending
  with a backslash are scanned too, and the scan fails when gitleaks skips
  any of them. The action passes
  its own configuration and runs outside the checkout, so a `.gitleaks.toml`
  or `.gitleaksignore` in the repository has no effect.
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
  messages and the pull request title and body. A line is French when it
  holds a French-only word, including a lowercase word with French accents
  (English loanwords such as café excepted), or enough of the short French
  words that English also uses. A capitalized accented word, a
  French word in capitals and a capitalized French word inside a sentence
  count less, because they are often names, constants or codes. Commit
  trailers that name people are skipped. Translation files are skipped:
  - files in `translations/`, `i18n/`, `locale/`, `locales/`, `lang/` and
    `languages/` folders that hold data or documentation, or whose name or
    folder is a language code (`locales/fr.js`, `locales/fr/common.js`);
  - gettext catalogs;
  - documents named after their language (`README.fr.md`, `README_fr.md`,
    `README_FR.md`, or `DOCS_fr.md` for a name in capitals) next to their
    English original (`README.md`);
  - pages under `docs/<language>/` whose English version exists under
    `docs/en/`.

  Language codes are also common folder names (`docs/os/` for Home
  Assistant OS), so a translation without its English original is checked.
  Codes that file names more often use for something else (`ha`, `os`,
  `to`, `is`, `be`, `as`, `an`, `am`, `or`, `so`) never make a document a
  translation, so `docs/install.ha.md` is checked.
  Translations kept elsewhere, such as at the root of `docs/`, need
  `english-exclude`.
- **Workflows**: actionlint with shellcheck.

The first push of a branch, a force push and a manual run check every commit
of the history as new.

The **Licenses** job checks that the LICENSE file holds the text of the
expected license and that every runtime dependency (manifest
`requirements`, the `requirements.txt` of each Home Assistant app, and
extra requirements files, transitive dependencies included) has an allowed
license. An app is a folder, at the root or one level down, that holds a
`Dockerfile` and a `config.yaml`, `config.yml` or `config.json`. The
LICENSE file is compared with phrases of the common permissive, GNU and
Mozilla licenses, in any case; for another identifier, the job warns that
it did not compare the file. Installing packages may run their build code, so this job runs
separately and never receives the denylist secret. How a license is read:

- `License-Expression` is used as written.
- Otherwise the `License` field is read together with the license
  classifiers. A classifier the field accounts for is left out: the same
  license, a version of it (such as `BSD-3-Clause` for "BSD License" or
  `LGPL-2.1-or-later` for the versionless LGPL classifier), or
  "Other/Proprietary License", which Poetry adds to every license it has no
  classifier for. Every other classifier is added with AND, because
  classifiers cannot tell a choice from a combination.
- If the field accounts for no classifier, the classifiers decide, unless
  the field names Commons Clause, proprietary or non-commercial terms, or a
  GNU license that no classifier names: it is then reported as written and
  fails. A field that names licenses the classifiers contradict, such as
  `BUSL-1.1` next to the MIT classifier, is combined with them with AND, so
  both must be allowed; loose words such as "Custom" or "BSD-like" leave
  the classifiers to decide.
- A one-line `License` field is read as a license name or expression.
  Known names are translated (for example "3-Clause BSD License" becomes
  `BSD-3-Clause`), and `and` and `or` in any case are operators. The name
  of a GNU classifier and short names such as `LGPLv3+`, `GPLv2` or `MPL2`
  are translated too. A one-line field that cannot be translated is
  reported as written and fails. A classifier without an SPDX identifier
  becomes a `LicenseRef`, which is not allowed until the package is
  exempted.
- A multi-line `License` field is read as a full license text. It is
  recognized only from phrases of the MIT, BSD and Apache 2.0 texts, only
  if it names no GNU license and no restriction, and only if its first line,
  when that line names a license, names a known one. Any other text is
  reported as unknown.
- After `WITH`, only SPDX license exceptions (license list 3.29.0) are
  accepted. `X-N-or-later` (or the deprecated `X-N+`) is allowed when
  version N or a later version of X is on the allowed list.

Manifest requirements must be PEP 508 requirements or the legacy
`<url>#<requirement>` form that Home Assistant accepts from custom
integrations (for example `git+https://example.com/lib.git#lib>=1`).
Options, paths, archive names and line breaks fail the job.

Findings report where something was found, never what, so logs do not
repeat the data. When a file path contains a denylisted term, the matching
path segments are shown as `[redacted]`.

A line that is not personal data despite matching a pattern can opt out of
one category with a comment such as `# ci-allow: private-ip`. The categories
are `private-ip`, `public-ip`, `email`, `phone`, `url`, `home-path`, `mac`,
`device-id`, `coordinates` and `french`. The denylist cannot be opted out
of. A gitleaks finding can be ignored through `secrets-ignore` (see the
exemptions below) or gitleaks' own `gitleaks:allow` comment, which works
only in files git can diff as text: the privacy check warns about every
added line that uses it, in text and binary files alike, and reviewers
must question it. Files over 20 MB fail the privacy check, so they cannot
hide one. It has no effect in commit messages, the pull request text,
UTF-16 and UTF-32 files or the files inside archives.

Exemptions, kept narrow on purpose:

- License files (`LICENSE`, `LICENCE`, `COPYING` and `NOTICE`, with an
  optional suffix such as `-APACHE` or `.md`) skip the generic patterns,
  because license texts quote their authors' sites.
- Dependabot commits skip the generic patterns for their added lines and
  messages, and its pull request body skips them too, because these quote
  upstream release notes and carry service addresses in trailers. In a pull
  request this only applies when Dependabot opened it, since anyone can
  write a bot address into a commit. The denylist still applies.
- `secrets-ignore` lists the fingerprints of known gitleaks false
  positives, as a failing run prints them. Only commits already on the base
  branch can be ignored, so a pull request cannot hide a secret it adds;
  each ignored finding is reported as a warning. It exists for findings
  that merged history already holds, since history cannot be rewritten: a
  real secret there must be revoked first.
- Fork pull requests do not receive secrets, so the denylist cannot run on
  them and the check fails. Pushing the branch to this repository would run
  its workflows with every secret of the repository, so a maintainer first
  reviews the whole diff: any change under `.github/`, to the `homeloom/ci`
  pins or to a script that CI runs is removed or explicitly approved before
  the push. The safer route is to cherry-pick only the reviewed changes
  outside these paths onto a fresh branch of the repository.

Limits:

- The generic patterns cannot recognize names, street addresses or public
  IPv4 addresses outside URLs (they look like version numbers), nor text in
  images, archives or encoded data beyond their metadata. The denylist and
  the review cover what the patterns cannot.
- The denylist and the metadata checks also read what ZIP files (Office,
  OpenDocument, EPUB, wheels), gzip files and the Flate streams of PDF files
  hold compressed, nested up to 4 levels deep, and the base64 `data:` URIs
  written on one line of a text file. Compressed content that cannot be
  read whole (an encrypted member, a malformed archive, a chain of PDF
  filters, more nesting, or more than 20 MB once inflated) fails the check,
  as does metadata too large to be read whole.
- In binary files, terms of three or four letters only count inside phrases
  of several words (such as a title in image metadata), and shorter terms not
  at all, because random bytes spell short words by chance. Single byte
  (Latin-1) strings are only searched for the longer terms. PDF files are
  always read as binary files.
- Files larger than 20 MB fail the check, because their content cannot be
  checked.
- The gitleaks rules limited to some file names (PHP, Terraform, Kubernetes
  YAML, `nuget.config`, PKCS#12) do not apply to UTF-16 or UTF-32 files or
  to the files inside archives. The line numbers of a finding inside an
  archive count in its text files, one after the other.
- The language check recognizes French only. A label of one capitalized
  accented word (which may be a name) or a short subject of one such word
  can pass, and a capitalized French word at the start of a value, such as
  a brand name, is reported unless it is listed in `english-allowed-words`.
- Classifiers cannot express a choice, so a dual-licensed package whose
  `License` field does not state the choice is rejected and needs a reviewed
  exception. Restrictions worded differently, or written inside a
  multi-line license text of a package that also has classifiers, are not
  detected. The license check does not replace reviewing the license of a
  new dependency.

### python-lint.yml

| Input | Default | Description |
| --- | --- | --- |
| `path` | `.` | Directory to lint. |

### ha-tests.yml

| Input | Default | Description |
| --- | --- | --- |
| `homeassistant-minimum` | `homeassistant` in `hacs.json` | Oldest supported Home Assistant version. |
| `python-minimum` | the oldest Python the oldest version supports | Python used with the oldest version, from 3.12 to `python-latest`. |
| `python-latest` | `3.14` | Python used with the latest version. |
| `requirements` | `requirements_test.txt` | Test requirements, installed when the file exists. |
| `coverage-source` | `custom_components` | Package or directory measured for coverage, as pytest imports or finds it (for example `custom_components`, `./custom_components`, or a package under `src/` with pytest `pythonpath = src`). |
| `coverage-minimum` | `95` | Minimum total coverage in percent. Lowering it needs a written justification in the pull request. |

The workflow picks the versions of `homeassistant` and
`pytest-homeassistant-custom-component`, so the test requirements must not
pin them. The latest leg takes the latest releases (0.13 or later of the
plugin). The minimum leg takes the oldest version and the plugin release
that pins it, and fails with the versions that nearby plugin releases pin
when none does. Its Python is the oldest one that the oldest version
supports, and the job fails with a clear error when `python-minimum` names
one it does not. Runtime requirements from the manifests are installed
too.

Coverage ignores the coverage settings of the repository, including `--cov`
options in the pytest configuration. Only lines marked
`# pragma: no cover - <reason>`, `if TYPE_CHECKING:` blocks and `...` stub
bodies are excluded. A pragma without a reason excludes nothing and fails
the job; every tracked Python file is checked.

### ha-integration.yml

| Input | Default | Description |
| --- | --- | --- |
| `hacs-ignore` | | HACS checks to skip. |

HACS validation only runs on public repositories, because HACS cannot read
private ones. The visibility is read from the API, so scheduled runs, whose
event carries no repository, get it right too.

### ha-app.yml

| Input | Default | Description |
| --- | --- | --- |
| `paths` | required | JSON array of app directories. |

The image is built with the build arguments that the Supervisor passes:
`BUILD_FROM` is `build_from` of `build.yaml`, `build.yml` or `build.json`
(one image, or the `amd64` entry of a map), or the Home Assistant base image
when it is missing; `BUILD_ARCH` is `amd64`; `BUILD_VERSION` is the
`version` of the app configuration; and the `args` of the build file come
last.

### release.yml

| Input | Default | Description |
| --- | --- | --- |
| `sha` | required | Commit to release. |
| `version-file` | the only integration manifest | `manifest.json`, `config.yaml`, `pyproject.toml` or a plain text file. |
| `changelog` | `CHANGELOG.md` | Changelog with a `## [<version>]` section per release. |
| `build-command` | none | Command that builds the asset folder, such as `npm run build`. It runs after `npm ci --ignore-scripts`, with Node 24. Needs `asset-path`. |
| `asset-path` | none | Folder whose contents are zipped and attached to the release. |
| `asset-name` | none | File name of the zip. With `zip_release` in `hacs.json`, it must be the `filename` there. |

Call it from a workflow triggered by `workflow_run` after CI succeeds on a
push to `main` (see the templates). Versions with a pre-release suffix are
published as pre-releases. A tag that already exists must be this commit's
release: a tag on another commit, or one without a GitHub release, fails
the job instead of leaving the version unreleased.

Without an asset, a single Release job runs, as in earlier versions. With
`asset-path` and `asset-name`:

- A **Plan** job checks, with a read-only token, whether the commit is
  released. Nothing is built otherwise, so a merge that does not change the
  version costs one short job.
- A **Build asset** job, read-only as well, runs the build and zips the
  contents of the folder, without the folder itself, as HACS expects. Links
  are refused and the zip is the same for the same files.
- The **Release** job creates the release as a draft, uploads the zip and
  only then publishes it, so that an installer never sees the release
  without its asset. If the upload or the publication fails, the draft is
  deleted. The build never runs in the job that holds the token that may
  write releases.

## Runners

Every job of the reusable workflows runs on the runner that the `runs-on`
input names, else the one that the `CI_RUNS_ON` configuration variable names,
else on `ubuntu-24.04`. The value is JSON, as `fromJSON` reads it:

| Value | Runner |
| --- | --- |
| `"ubuntu-24.04"` | A GitHub-hosted runner, the default. The quotes are part of the value. |
| `["self-hosted", "linux", "x64", "ci"]` | A self-hosted runner that has every one of these labels. |
| `{"group": "ci", "labels": ["linux"]}` | A runner of the `ci` runner group with these labels. |

A value that is not valid JSON fails the job. A called workflow runs in the
context of the repository that calls it, so `vars.CI_RUNS_ON` is the variable
of that repository, or else of its organization. The Report job of the
templates reads the same variable, so that a whole run moves at once.

Self-hosted runners are for private repositories only. Anyone can open a pull
request on a public repository, and its code would then run on the machine
of the runner:

- Create the organization variable with the **Private repositories** access
  policy, and keep the runner group closed to public repositories, which is
  the default. A public repository then does not see the variable, and runs
  on GitHub-hosted runners.
- A repository that becomes public returns to GitHub-hosted runners by
  itself under that policy. Otherwise, give it a repository variable
  `CI_RUNS_ON` set to `"ubuntu-24.04"`, which takes precedence over the
  organization variable.
- The CI of this repository, which is public, always passes `"ubuntu-24.04"`.
- Register the runners as ephemeral, so that each one runs a single job and
  starts the next one clean. The license job installs third party packages
  that may run their build code, and the jobs receive the secrets and the
  token of the calling repository.

The jobs expect what the GitHub-hosted `ubuntu-24.04` image provides. A
self-hosted runner needs:

- Linux on x64: `actions/setup-tools` installs Linux x64 builds only.
  Ubuntu 24.04 is the safe choice, because `actions/setup-python` and
  `actions/setup-node` download builds made for a given Ubuntu release.
- `bash`, coreutils (`sha256sum`), `curl`, `tar`, `git`, `jq`, the GitHub CLI
  `gh` (release) and `yq` 4 by Mike Farah (`ha-app.yml`), not the Python
  `yq` wrapper.
- Python 3.12 or later as `python3`: the checks run on the system Python of
  the runner, without `setup-python`.
- Docker, usable by the runner: the hassfest, HACS and app linter actions run
  container images, and `ha-app.yml` builds the app images. When the runner
  itself runs in a container that uses the Docker socket of its host, mount
  its work directory at the same path on the host and in the container,
  because container actions mount the workspace by that path.
- A writable tool cache, where `setup-python` and `setup-node` install their
  versions, and outbound HTTPS to GitHub, `ghcr.io`, PyPI and npm.

Jobs that a repository adds itself may need more, such as the system
libraries of a headless browser.

A self-hosted runner keeps its tool cache from one job to the next, and with
it every package installed into a Python of `setup-python`. So no job of
these workflows installs into it: `ha-tests.yml` installs into a virtual
environment under `RUNNER_TEMP`, the license check into a temporary
directory, and `actions/setup-tools` its tools under `RUNNER_TEMP`, which the
runner empties after each job. A job that a repository adds itself should do
the same, for example:

```yaml
- name: Create a virtual environment
  run: |
    python -m venv "${RUNNER_TEMP}/venv"
    echo "${RUNNER_TEMP}/venv/bin" >> "$GITHUB_PATH"
```

Otherwise, test plugins installed by one job load in the tests of another,
and the two legs of `ha-tests.yml` mix their versions of Home Assistant.

## Organization settings

- **Visibility**: GitHub only lets private repositories use workflows and
  actions from a private repository. This repository must be made public
  before the first repository that calls it becomes public.
- **Actions access**: while private, this repository is accessible from
  repositories in the organization (Settings, Actions, General, Access).
- **Secrets**: each denylist secret (a name starting with `PRIVACY_DENYLIST`)
  exists as an organization Actions secret and as an organization Dependabot
  secret of the same name, both available to every repository that calls
  `hygiene.yml`. The step headers of the Hygiene job list the name of every
  secret a repository can see, so every secret name stays neutral, and the
  denylists are numbered (`PRIVACY_DENYLIST_1`, `PRIVACY_DENYLIST_2`…) and
  never say what a list holds.
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
  Python code (masking, personal data, secrets and English). That code keeps
  the `PRIVACY_DENYLIST*` values and removes the variable before it starts
  git or gitleaks, so they never receive it, nor do actionlint and the
  license job. As a
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
- `actions/privacy/gitleaks.toml` is the upstream gitleaks configuration
  with the changes its header lists; update it with gitleaks, as the header
  explains.
- `SPDX_EXCEPTIONS` in `src/ci_checks/licenses.py` copies the exceptions of
  the SPDX license list 3.29.0. An exception added to SPDX later is rejected
  until it is added there.
- To release this repository, bump `version` in `pyproject.toml` and add the
  matching `CHANGELOG.md` section. Releases are tagged automatically once CI
  passes on `main`.

## Development

```sh
uv venv --python 3.12
uv pip install --require-hashes --requirement requirements-dev.txt
.venv/bin/python -m pytest
```

The secret scan tests need gitleaks on `PATH`, at the version that
`actions/setup-tools/install.sh` pins; they skip without it, and a test
fails when another version is found. The tests run git without the global
and system configuration of the machine, as on a runner, so a test that
needs a git identity must give one.

## License

[MIT](LICENSE)

`actions/privacy/gitleaks.toml` is adapted from the configuration of
[gitleaks](https://github.com/gitleaks/gitleaks), distributed under the MIT
License; the file carries its copyright and permission notice.
