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
2. Enable private vulnerability reporting (Settings, Security).
3. Give the repository access to every organization secret whose name
   starts with `PRIVACY_DENYLIST`, both as Actions secrets and as Dependabot
   secrets. The CI workflow passes them with `secrets: inherit`.
