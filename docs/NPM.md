<!--
Copyright 2026 Insomniac-VibeLabs
Author: Stephan Busch
SPDX-License-Identifier: Apache-2.0
-->

# Release on npm

This page is how the TypeScript tool-check helper,
[`@insomniac-vibelabs/two-key-toolcheck`](https://www.npmjs.com/package/@insomniac-vibelabs/two-key-toolcheck),
is published. Its source is `typescript/toolcheck/`, and what it does is
[TOOL_CHECK.md](TOOL_CHECK.md). Publishing it does not change Two-Key.

## Contents

<!-- toc -->
- [What a consumer will install](#what-a-consumer-will-install)
- [Versions](#versions)
- [Once: the npm organization](#once-the-npm-organization)
- [Once: the first publish, from a Codespace](#once-the-first-publish-from-a-codespace)
- [Once: trusted publishing](#once-trusted-publishing)
- [Each release](#each-release)
<!-- /toc -->

## What a consumer will install

```bash
npm install @insomniac-vibelabs/two-key-toolcheck
```

Node 22.13 or later, or Node 24. The package has one dependency,
`@noble/post-quantum`, pinned to an exact version.

## Versions

The helper has its own version line in `typescript/toolcheck/package.json`,
starting at `0.9.1`, published separately from PyPI. Its README says which
Two-Key versions it works with. The wire format has not changed since 0.9.0,
so any helper version works with Two-Key 0.9.0 and later until the format
changes.

## Once: the npm organization

The organization `insomniac-vibelabs` on npmjs.com holds the package name. It
was created on 2026-11-09. Each maintainer needs an npm account with
two-factor authentication on, as a member of the organization.

## Once: the first publish, from a Codespace

npm can only trust this repository's workflow for a package that already
exists, so the first version is published by hand. In the GitHub web
interface: **Code** → **Codespaces** → **Create codespace on working** (or
the branch being released). In its terminal (`node --version` must say 22.13
or later; if not, run `nvm install 24` first):

```bash
cd typescript/toolcheck
npm ci
npm test
npm login            # opens a browser sign-in; use the npm account, with its second factor
npm publish --access public --provenance=false
npm logout
```

`--provenance=false` is needed only here: a provenance statement can be
made only inside GitHub Actions. Every later release has one.

## Once: trusted publishing

On npmjs.com, open the package → **Settings** → **Trusted Publisher** →
**GitHub Actions**, and enter:

| Field | Value |
| --- | --- |
| Organization or user | `Insomniac-VibeLabs` |
| Repository | `two-key` |
| Workflow filename | `npm-publish.yml` |
| Environment | `npm` |

Then, under **Publishing access**, choose **Require two-factor authentication
and disallow tokens**. From then on, only the workflow can publish, and no
npm token exists anywhere.

In the repository, **Settings** → **Environments** → **New environment**
`npm`, with yourself as a required reviewer, so each publish waits for your
approval as the `pypi` environment does.

## Each release

1. Bump `version` in `typescript/toolcheck/package.json` (and its
   `package-lock.json`, `npm version X.Y.Z --no-git-tag-version` in that
   folder), and say what changed in `CHANGES.md`.
2. Bring the change to the `PyPI` branch, as for a Python release
   ([PYPI.md](PYPI.md)).
3. **Actions** → **npm-publish** → **Run workflow** on branch `PyPI`, and
   approve the `npm` environment.

The workflow refuses a version that is already on npm, runs the audit, the
linter and the tests, and publishes with provenance. The package page then
shows which commit and workflow built it.
