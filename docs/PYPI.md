<!--
Copyright 2026 Insomniac-VibeLabs
Author: Stephan Busch
SPDX-License-Identifier: Apache-2.0
-->

# Release on PyPI

This page is how a release of `two-key` is published, and how the project was
registered. It does not change what Two-Key does.

`two-key` has been on [pypi.org](https://pypi.org/project/two-key/) since
2026-10-17. PyPI has `0.7.0`, `0.7.1` and `0.7.2`, all uploaded that day.
`0.7.1` and `0.7.2` are packaging releases made from the `PyPI` branch, which
swaps the Mermaid diagrams for pictures (PyPI shows the README and nothing
under `docs/`) and names its own version in the install lines. They are not
on this branch: `pyproject.toml` and `two_key.__version__` here still say
`0.7.0`, and the next release is numbered above `0.7.2`, a number chosen at
release time. PyPI treats `two-key`, `two_key`, and `two.key` as the same
project. The import name stays `two_key`. The public 1.0 review in
[ROADMAP.md](../ROADMAP.md) is still ahead.

## What a consumer will install

```bash
pip install "two-key==X.Y.Z"
pip install "two-key[yaml]==X.Y.Z"
pip install "two-key[mcp]==X.Y.Z"
```

`X.Y.Z` is a version listed on the [project page](https://pypi.org/project/two-key/#history).
The tag `v0.7.0` on `main` is the git snapshot of `0.7.0`, and can be installed
directly:

```bash
pip install "two-key[yaml] @ git+https://github.com/Insomniac-VibeLabs/two-key.git@v0.7.0"
```

| Extra | Pulls in | Needed for |
| --- | --- | --- |
| (none) | `cryptography>=41` | The library and the `two-key` command |
| `yaml` | PyYAML | YAML constitutions, rules, and judge files |
| `mcp` | `mcp>=2.2,<3` and PyYAML | `two-key mcp-proxy` and `two-key mcp-draft-specs` |

Python 3.10 to 3.14 (docs/HOWTO.md "Platforms" says why not 3.15 yet). One
wheel for Linux, macOS, and Windows: there is no compiled extension. `uv.lock` is what CI installs. It is not what pip
installs from PyPI.

## Files

| File | Role |
| --- | --- |
| [pyproject.toml](../pyproject.toml) | Name, version, license, dependencies, extras, the `two-key` script, and the URLs PyPI shows |
| [README.md](../README.md) | The project page's long description |
| [LICENSE](../LICENSE) | Apache-2.0, declared as the SPDX expression `Apache-2.0` |
| [MANIFEST.in](../MANIFEST.in) | Docs and examples in the source distribution. The wheel is still only the `two_key` package |
| [.github/workflows/pypi-publish.yml](../.github/workflows/pypi-publish.yml) | Build, `twine check --strict`, a CycloneDX SBOM, then a tokenless upload |

No `setup.py`, no `requirements.txt`, and no `.pypirc`. A `.pypirc` holds a
token, so `.gitignore` ignores that name. Do not add a PyPI token as a
GitHub secret. The workflow uses OpenID Connect
([trusted publishing](https://docs.pypi.org/trusted-publishers/)).

The license field is the SPDX expression. A `License ::` classifier is not
set beside it: current build tools may reject the pair.

## What the workflow does

It runs only from this branch (`refs/heads/PyPI`) or from a tag whose name
starts with `v`. A pull request does not publish.

1. Build an sdist and a wheel with `build==1.6.1` (same pin as
   `.github/workflows/build.yml`).
2. `twine check --strict`. A warning fails the job. Nothing is uploaded.
3. Install that wheel into a throwaway virtualenv and write
   `sbom.cdx.json` (CycloneDX, `cyclonedx-bom==7.5.0`). The SBOM is a
   workflow artifact kept 90 days. It is not a file on PyPI. The upload
   directory contains only the sdist and the wheel, so the SBOM cannot be
   sent to the index by mistake.
4. The publish job runs in a GitHub environment, `testpypi` or `pypi`, and
   exchanges a short-lived token. `pypa/gh-action-pypi-publish` v1.14.2
   (pinned by commit) signs each file with Sigstore and uploads the
   [PEP 740](https://peps.python.org/pep-0740/) attestations with it.

A tag push always targets PyPI, and only when the tag is `v` plus the
version in `pyproject.toml`. `v0.7.1` on a tree that still says `0.7.0`
fails before the upload. A manual run defaults to TestPyPI.

`v0.7.0` already points at `main` and must not be moved. A release gets a
new version in both `pyproject.toml` and `two_key.__version__`, then a new
signed tag `vX.Y.Z` on a commit that contains this workflow, or a manual
run of this workflow on the `PyPI` branch. PyPI never replaces a version.
A metadata fix after the upload needs a new version number.

## Register the name

Done: the project exists and its pending publisher became a trusted
publisher with the first upload. These steps are what was done, for a
fresh setup or a new index. A pending publisher is what reserves a name for
this repository before the project exists there.

PyPI accounts need two-factor authentication.

### TestPyPI first

1. Sign in at [test.pypi.org](https://test.pypi.org/).
2. Open [publishing](https://test.pypi.org/manage/account/publishing/) and
   add a pending publisher:
   - PyPI project name: `two-key`
   - Owner: `Insomniac-VibeLabs`
   - Repository name: `two-key`
   - Workflow name: `pypi-publish.yml`
   - Environment name: `testpypi`
3. On GitHub, in this repository: Settings, Environments, New environment,
   name `testpypi`. Add yourself as a required reviewer. Add no secrets.
4. Actions, workflow `publish`, Run workflow, branch `PyPI`, repository
   `testpypi`. Approve the environment prompt.
5. When it finishes, the project page is
   `https://test.pypi.org/project/two-key/`. Confirm the version, the
   Apache-2.0 license, the README, and that each file has an attestation.
6. Install from TestPyPI. Dependencies such as `cryptography` are on the
   real index, so both indexes are named:

```bash
pip install --index-url https://test.pypi.org/simple/ \
  --extra-index-url https://pypi.org/simple/ \
  "two-key[yaml]==X.Y.Z"
python -c "import two_key; print(two_key.__version__)"
two-key --help
```

TestPyPI and PyPI do not share projects. Uploading a version to TestPyPI
does not consume it on PyPI. Uploading a version twice to the same index
fails.

### PyPI

Repeat the pending publisher on the real index.

1. Sign in at [pypi.org](https://pypi.org/).
2. Open [publishing](https://pypi.org/manage/account/publishing/) and add a
   pending publisher with the same owner, repository, and workflow name.
   Environment name: `pypi` (not `testpypi`).
3. Create a GitHub environment named `pypi`, with a required reviewer and
   no secrets.
4. Run workflow `publish` from branch `PyPI` and choose repository `pypi`.
   Approve it.
5. Confirm `https://pypi.org/project/two-key/` and then:

```bash
pip install "two-key[yaml]==X.Y.Z"
```

The pending publisher becomes a trusted publisher on the project after
the first successful upload. Leave it in place. Do not add an API token
beside it.

Create both GitHub environments before the first run. GitHub will otherwise
create an environment with no reviewer the first time the job asks for it.

## Tags and `main`

- Do not move `v0.7.0`, `v0.6.0`, `v0.5.0`, `v0.4.0`, or any older tag. A
  fix to what is on the index is a new version, never a retag.
- Do not choose branch `main` in **Run workflow**. The workflow file is on
  `main`, which is why GitHub lists it. The jobs still refuse every ref
  except `refs/heads/PyPI` and a `vX.Y.Z` tag. A GitHub Release is not a
  trigger. A later release is a signed tag on a commit that already
  contains this workflow, and that tag push publishes to PyPI only when
  the tag matches the version in `pyproject.toml`.
- A later tag must be on a commit that already contains
  `pypi-publish.yml`. The tag push runs the workflow from that commit.
- Sign the tag (`git tag -s vX.Y.Z`). The workflow does not create the tag
  and does not check the signature. The signature is the maintainer's.
- The SBOM for a tag run is the `sbom` artifact on that workflow run.
  Attach it to the GitHub release if you cut one. It is not inside the
  wheel.

## After the project exists

- Yank a broken file from the project page. Do not delete a version that
  anyone may have installed. Yanking stops new installs from choosing it
  and leaves existing pins working.
- To change the README, the classifiers, or a dependency range on the
  index, publish a new version. Editing `pyproject.toml` on this branch
  does not change a version already uploaded.
- When the release line moves, point the project URLs in `pyproject.toml`
  at that line. They currently point at this `PyPI` branch so the page
  matches the commit that would be uploaded.
- The README's banner uses an absolute URL so the project page can load
  it. Other links in the README are repository-relative. They open on
  GitHub and do not resolve on pypi.org. The page still carries the full
  README. Nothing was cut from it to make the page.

## Checks before you run it

From a clone of this branch:

```bash
pip install "build==1.6.1" "twine==7.0.0"
python -m build
twine check --strict dist/*
```

`twine check` passing here is the same check the workflow runs. It does
not upload.
