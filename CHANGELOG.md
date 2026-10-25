# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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
  words of a term, with stricter rules for numbers, so that dates, times and
  versions never match a term made of numbers.
- Composite actions for each check, and a tool installer that verifies
  SHA-256 digests.
- Templates for new repositories: license, security policy, contribution
  guide, pull request and issue templates, Dependabot configuration, and
  calling workflows for integrations and apps.
- Review checklist (`REVIEW.md`) and contributor rules (`AGENTS.md`).
