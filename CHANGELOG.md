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
- Composite actions for each check, and a tool installer that verifies
  SHA-256 digests.
- Templates for new repositories: license, security policy, contribution
  guide, pull request and issue templates, Dependabot configuration, and
  calling workflows for integrations and apps.
- Review checklist (`REVIEW.md`) and contributor rules (`AGENTS.md`).
