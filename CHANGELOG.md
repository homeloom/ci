# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.1]

### Changed

- Denylist: a comma or a colon between a word and a number is accepted when
  it follows the word and comes before white space, as in an address
  (`Quillmore Lane, 12`), while `"step": 12` and `["step", 12]` still do not
  match `step 12`.
- Denylist: letters may come right before a term that starts with a dotted
  number, as in `v12.3.0`.
- Denylist: a term that glues digits after letters, such as `Name5G`, also
  matches `Name 5G`.
- Denylist: where a camel case term has a part of three letters or less, as
  in `LeBlanc`, only nothing or one punctuation character may separate its
  parts, so that it does not match the words of a sentence.
- Denylist: phone numbers and other terms of eight digits or more also
  match with a dash and spaces around it between their numbers.
- The contribution guide template and `AGENTS.md` ask for tests that do not
  depend on the machine that runs them.
- Masking: two numbers of a short term are no longer masked glued, nor with
  a dash when the term has only two numbers in a row, so that spellings
  such as `1230` or `12-30` stay readable in logs.

### Fixed

- Privacy check: a commit that adds a `gitleaks:allow` line to a binary
  file gets a warning, as one that adds it to a text file does.
- Denylist: text is also decoded a second time, for escapes that were
  themselves escaped (`&amp;quot;`, `%2520`), which hid a term and left it
  unredacted in file paths.
- Denylist: `\b`, `\f` and `\v` escapes, references without a semicolon,
  the combining grapheme joiner and variation selectors no longer hide a
  term.
- Denylist: escapes written with upper case hexadecimal digits are no longer
  split by the camel case view, which made the result depend on the case of
  the digits.
- Denylist: a numeric character reference of more than 4,300 digits no longer
  stops the check.
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
