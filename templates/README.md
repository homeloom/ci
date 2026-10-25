# Templates

Files to copy into a new repository. They are kept generic on purpose: copy
them as they are, then adjust only what the comments point out.

| Directory | Use |
| --- | --- |
| `common/` | Every repository: license, security policy, contribution guide, pull request and issue templates, Dependabot configuration. |
| `integration/` | A Home Assistant integration (`custom_components/<domain>/`): CI and release workflows. |
| `app/` | A repository of Home Assistant apps: CI and release workflows. |

## Pinning the shared workflows

The workflows call `homeloom/ci` by commit SHA, as the organization policy
requires. Replace every `REPLACE_WITH_RELEASE_SHA # vX.Y.Z` with the commit
of the latest [release](https://github.com/homeloom/ci/releases) and its tag,
for example `@<40 character sha> # v1.2.3`. Dependabot then keeps the pin up
to date.

## Repository settings

After copying the files:

1. Add a ruleset on `main` that requires a pull request, allows squash
   merging only and requires the **Report** status check.
2. In Settings, General, Pull Requests, set the default commit message of
   squash merging to **Pull request title and description**. The commit on
   `main` then takes the title, which CI checks against Conventional
   Commits, and the description, which CI checks for secrets and personal
   data. GitHub's default message reuses the commit message instead when a
   pull request has a single commit, so the title would not reach `main`.
3. Enable private vulnerability reporting (Settings, Security).
4. Give the repository access to every organization secret whose name
   starts with `PRIVACY_DENYLIST`, both as Actions secrets and as Dependabot
   secrets. The CI workflow passes them with `secrets: inherit`. GitHub
   prints secret names in every job log, so the names stay neutral and
   numbered (`PRIVACY_DENYLIST_1`, `PRIVACY_DENYLIST_2`…) and never say what
   a list holds.
5. Once the first pull request is merged, run the CI workflow by hand
   (Actions, CI, Run workflow). A manual run checks every commit of the
   history as new; do it before the first release and before making the
   repository public.
