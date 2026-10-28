# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.5]

### Fixed

- `ha-tests.yml` no longer puts its virtual environment on `PATH` for the
  rest of the job, only in the test step. Home Assistant installs its own,
  older uv into the environment, so since 0.2.4 the "Prune uv cache" step ran
  that uv, which fails on a cache written by the pinned one when no package
  was built from source.
- The uv cache of `ha-tests.yml` moves from `~/.cache/uv` to `RUNNER_TEMP`,
  on the same file system as the virtual environment, so that uv links the
  files it installs instead of copying them. The cache path is part of the
  cache version, so the first run of each repository after the update starts
  without a cache.

## [0.2.4]

### Fixed

- `ha-tests.yml` installs Home Assistant and the test requirements into a
  virtual environment under `RUNNER_TEMP`, no longer into the Python of
  `setup-python`. A self-hosted runner keeps that Python between jobs, so the
  packages of one job loaded in the next: the two legs mixed their versions of
  Home Assistant, and the integration's test plugins broke other test jobs.
  The README says how a repository's own jobs do the same.

## [0.2.3]

### Added

- Every job of the reusable workflows runs on the runner that the new
  `runs-on` input names, else the `CI_RUNS_ON` configuration variable of the
  calling repository or its organization, else `ubuntu-24.04`. The value is
  JSON, so it can name self-hosted runners by labels or by runner group. The
  Report job of the templates follows the same variable, and the CI of this
  repository always stays on GitHub-hosted runners. The README lists what a
  self-hosted runner needs.

### Fixed

- `setup-tools` tries a failed download twice more, after 5 then 15
  seconds, since curl does not retry a 403 by itself. The archive kept is
  still checked against its digest.

## [0.2.2]

### Changed

- Licenses: the LICENSE file is compared with the text of the common
  permissive, GNU and Mozilla licenses, whatever the case of `license`, and
  the job warns when it does not know the text of the expected license.
- Licenses: the `requirements.txt` of Home Assistant apps (a folder with a
  `Dockerfile` and a `config.yaml`, `config.yml` or `config.json`) is
  checked. `hygiene.yml` takes `license-python-version`.
- Licenses: GNU classifier names and short names such as `LGPLv3+`, `GPLv2`
  or `MPL2` in the License field are translated. A License field that names
  licenses the classifiers contradict is combined with them, so both must
  be allowed, and a license that comes from a classifier without an SPDX
  identifier is explained.
- Language: tags in capitals (`README_FR.md`), names in capitals with a
  separator (`DOCS_fr.md`) and codes that file names use for something else
  (`docs/install.ha.md`) are classified right. An accented word that
  starts a sentence and has an ending of French labels, such as the one of
  verbs in the infinitive, counts as French.
- Binary content that starts with the bytes of a UTF-16 or UTF-32 byte
  order mark is no longer read as text.
- `ha-tests.yml`: the minimum leg derives its Python from the oldest Home
  Assistant version (`python-minimum` defaults to empty) and installs the
  `pytest-homeassistant-custom-component` release that pins that version,
  naming the nearby pinned versions when none does.
- `release.yml`: a tag on another commit, or a tag without a GitHub
  release, fails instead of passing silently.
- `ha-app.yml`: `build_from` may be one image, a map without `amd64` or
  missing, as for the Supervisor; `BUILD_VERSION` and the `args` of the
  build file are passed.

## [0.2.1]

### Changed

- Privacy: a file or history blob over 20 MB fails instead of giving a
  warning, since its content cannot be checked.
- Privacy: the content that ZIP files (Office, OpenDocument, EPUB, wheels),
  gzip files and the Flate streams of PDF files hold compressed, and base64
  `data:` URIs written on one line of a text file, go through the denylist
  and the metadata checks, nested up to 4 levels deep and within 20 MB once
  inflated. Content that cannot be read whole fails, as does metadata too
  large to be read whole.
- Privacy: PDF information fields written as hexadecimal strings or inside
  compressed streams, EXIF 3.0 UTF-8 fields and the location of QuickTime
  and MP4 videos are read. Hostile metadata is read in linear time.
- Privacy: file paths, in the checkout and in history, and the branch name
  go through the generic patterns a path can hold, and the parts that match
  are redacted. A term split across folders is redacted too.
- Privacy: a force push that leaves the replaced commits out of the
  checked range is reported. License files only skip URLs and e-mail
  addresses.
- Privacy: firewall and switch addresses, coordinates under short keys
  such as `home_lat`, and IPv4 addresses under keys such as `IPAddress`,
  `IPADDR`, `DNS1` or a `nameserver` line are reported again. Coordinate
  pairs are weighed by how they are written.
- Privacy: Windows-1252 text with a stray NUL byte is read as text.
- Phone numbers: `1-NNN-NNN-NNNN`, a French number followed by an hour
  range, and a trunk prefix after the country code (`+44 (0)20 ...`) are
  read. A fiction number with more digits after it is not exempt, and the
  Ofcom drama blocks are complete.
- Secrets: the text files inside ZIP, gzip and PDF files and UTF-16 files
  without a byte order mark are scanned too. gitleaks does not open
  archives in a history scan.

## [0.2.0]

### Added

- `release.yml` can attach a zip to the release: `asset-path` names the
  folder to zip and `asset-name` the file name, which must match the
  `filename` of `hacs.json` when it sets `zip_release`. `build-command`
  builds the folder first, after `npm ci --ignore-scripts` with Node 24.
  The build runs in its own read-only job, only when the commit is released.
  Without these inputs, `release.yml` works as before.
- The release with an asset is created as a draft, gets the zip and is
  published only then. A failed upload or publication deletes the draft.
- The `release` action takes `asset` and `plan` inputs, and the new
  `release-asset` action builds and zips the asset.

## [0.1.1]

### Changed

- The calling workflow templates run no job at all on draft pull requests,
  so that work in progress costs no runner minutes. Report is skipped on
  drafts too, and no longer fails there.
- The contribution guide template and `AGENTS.md` ask for tests that do not
  depend on the machine that runs them, and `AGENTS.md` asks for the final
  pull request text before it leaves draft.
- Denylist: a comma or a colon between a word and a number is accepted when
  it follows the word and comes before a space or a tab, as in an address
  (`Quillmore Lane, 12`), while `"step": 12`, `["step", 12]` and `step:`
  followed by `12` on the next line still do not match `step 12`. Unquoted
  lists and mappings, such as `[bus, 917]`, now match `bus 917`.
- Denylist: a `v` that starts a word may come right before a term when the
  text writes its first numbers with a dot, as in `v12.3.0`.
- Denylist: a term that glues digits after letters, such as `Name5G`, also
  matches `Name 5G`.
- Denylist: where a camel case term has a part of three letters or less, as
  in `LeBlanc`, only nothing or one punctuation character may separate its
  parts, unless the text writes the next part with a capital after white
  space, as in `Le Blanc`, so that it does not match the words `le blanc`
  of a sentence.
- Denylist: phone numbers and other terms of eight digits or more also
  match with a dash and spaces around it between their numbers.
- Masking: two numbers of a short term are no longer masked glued, and a
  term of two numbers alone is not masked with a dash unless it is written
  so, so that spellings such as `1230` or `12-30` stay readable in logs.
  Letters and the digits glued after them are masked with separators too.

### Fixed

- Privacy check: a commit that adds a `gitleaks:allow` line to a binary
  file gets a warning, as one that adds it to a text file does.
- Denylist: text is also decoded a second time, for escapes that were
  themselves escaped (`&amp;quot;`, `%2520`), which hid a term and left it
  unredacted in file paths.
- Denylist: `\b`, `\f` and `\v` escapes, references without a semicolon,
  the combining grapheme joiner and variation selectors no longer hide a
  term, and invisible characters and marks no longer glue the parts of a
  camel case name, as in `get` and `Name` with a zero width space between.
- Denylist: a word right after a backslash, as in `C:\Users\name`, is no
  longer hidden when an escape touches it.
- Denylist: escapes written with upper case hexadecimal digits, or with
  `&#X`, are no longer split by the camel case view, which made the result
  depend on the case of the digits.
- Denylist: a decimal character reference of more than 4,300 digits no
  longer stops the check.
- Denylist: camel case names in binary content are searched too.

## [0.1.0]

### Added

- Reusable workflows: hygiene (pull request title, secrets, personal data,
  English, licenses, actionlint), Python lint, Home Assistant tests on the
  oldest supported and the latest release, hassfest and HACS validation,
  Home Assistant app lint and build, and releases from `CHANGELOG.md`.
- Privacy check: generic personal data patterns, image and document
  metadata, the content of commits that later commits remove, and a
  denylist merged from every secret whose name starts with
  `PRIVACY_DENYLIST`.
- Secret scan: the default gitleaks rules without their allowlists of paths
  and values, over the whole history, the commit messages, the pull request
  text and UTF-16 and UTF-32 files, with exact fingerprints for known false
  positives.
- Language check: French outside translation files, with translations
  recognized next to their English original.
- License check: `License-Expression`, or the `License` field read with the
  license classifiers, for every runtime dependency.
- Home Assistant tests: coverage measured with the workflow's own
  configuration, at least 95 % by default, excluding only lines whose
  `# pragma: no cover` gives a reason. The oldest version tested can be
  Home Assistant 2023.3 or later (`pytest-homeassistant-custom-component`
  0.13), and the job stops with a clear error when that version needs
  another Python than `python-minimum`.
- Denylist matching that ignores case, accents and separators between the
  words of a term, with stricter rules for numbers, so that versions such as
  `v1.12.3.0`, lists such as `[12, 3, 0]` and SVG coordinates do not match
  the term `12 3 0`, while phone numbers and other terms of eight digits or
  more also match their usual spellings.
- Composite actions for each check, and a tool installer that verifies
  SHA-256 digests.
- Templates for new repositories: license, security policy, contribution
  guide, pull request and issue templates, Dependabot configuration, and
  calling workflows for integrations and apps.
- Review checklist (`REVIEW.md`) and contributor rules (`AGENTS.md`).
