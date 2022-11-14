# Release with in-toto attestations

This document describes how to create local maintainer attestations for the 'tag' and
'build' steps of the release process, and how to verify them together with attestations
from the online CD build job against an in-toto supply chain layout.

The instructions are based on RELEASE.md and require the GitHub release environment to
be configured as described. You can follow below instructions in addition to those in
RELEASE.md, except that `git tag ...` must be called with `in-toto-run` as described
below.

**Prerequisites (one-time setup)**
- Install `in-toto` with *ed25519* support (e.g. `pip install in-toto[pynacl]`)
- Create CD build job signing key, and signed in-toto layouts (see
  `.in_toto/create_layout.py` module docstring for instructions)
- Configure a GitHub secret `IN_TOTO_KEY` pasting the contents from the encrypted
  private key created above, and a GitHub secret `IN_TOTO_KEY_PW` for the decryption
  password (see `cd.yml` for how the secrets are used).

**Define vars used by the CLI below**

```bash
# Attestations are signed using the gpg key identified by `signing_key`, which means the
# corresponding **private** key must be in your local gpg keychain.
signing_key="****** REPLACE WITH YOUR GPG KEYID ******"

# The fingerprints in `verification_keys` are used to verify the signatures on the
# layouts created and signed above, which requires the corresponding **public**
# keys to be in your local gpg keychain.
verification_keys=("****** REPLACE WITH YOUR GPG KEYID ******")

# Define GitHub repo name to fetch CD build job attestations
github_repo=theupdateframework/python-tuf # <- CHANGE TO EXPERIMENT IN YOUR FORK!!

# Grab tuf version string to infer tag name and build artifact names needed below
version=$(python3 -c 'import tuf; print(tuf.__version__)')

# Define patterns to exclude files we from attestations created below
exclude=('__pycache__' 'build' 'htmlcov' '.?*' '*~' '*.egg-info' '*.pyc')

# Make sure that neither builds nor attestations include unwanted files
# CAUTION: This deletes all untracked files (except above created layouts)
git clean -xf -e ".in_toto/*.layout"
```

## Tag

Call `git tag ...` with `in-toto` as shown to create a release tag along with a signed
attestation. The attestation records the names and hashes of files in cwd as
*materials*. The attestation is written to `.in_toto/tag.<signing keyid>.link`.

```bash
in-toto-run \
  --step-name tag \
  --gpg ${signing_key} \
  --materials . \
  --exclude ${exclude[@]} \
  --metadata-directory .in_toto \
  -- git tag --sign v${version} -m "v${version}"
```

**--> push tag to GitHub to trigger CD build job as described in RELEASE.md**

## Build

Call `python3 -m build --sdist ...` and `python3 -m build --wheel ...` with `in-toto` as
shown to create two signed attestations, recording the names and hashes of files in cwd
as *materials*, and the name and hash of each respective build artifact as product. The
attestations are written to `.in_toto/sdist.<signing keyid>.link` and
`.in_toto/wheel.<signing keyid>.link`.

```bash
in-toto-run \
  --step-name sdist \
  --gpg ${signing_key} \
  --materials . \
  --products dist/tuf-${version}.tar.gz \
  --exclude ${exclude[@]} \
  --metadata-directory .in_toto \
  -- python3 -m build --sdist --outdir dist/ .
```

```bash
in-toto-run \
  --step-name wheel \
  --gpg ${signing_key} \
  --materials . \
  --products dist/tuf-${version}-py3-none-any.whl \
  --exclude ${exclude[@]} dist/tuf-${version}.tar.gz \
  --metadata-directory .in_toto \
  -- python3 -m build --wheel --outdir dist/ .
```

## Verify

Use `in-toto` as shown to verify the supply chain of each build artifact. This means:
- Check layout signatures and layout expiration. *(Note: in-toto requires a valid layout
  signature for every key passed to the verify command, and at least one)*

- Check that there is a threshold of attestations per step, each signed with an
  authorized key, both as defined in the layout. *(Note: the attestation signature
  verification keys are included in the layout)*

  i.e.:
  - one 'tag' attestation signed by any maintainer (we will take the one created above)
  - two 'build' attestations per build artifact signed by any maintainer or the CD build
    job (we will take the one created above and by the CD build job, which we will
    download below)

- Check that each build artifact matches the product listed in the corresponding 'build'
  attestation, and the materials of the 'build' attestations align with the materials in
  the 'tag' attestation.


**Download CD build job attestations**
```bash
# Workaround to glob download '{wheel, sdist}.*.link' files from release page
cd_keyid=$(wget -q -O - https://github.com/${github_repo}/releases/tag/v${version} | \
    grep -o "sdist.*.link" | head -1 | cut -d "." -f 2)

wget -P .in_toto https://github.com/${github_repo}/releases/download/v${version}/sdist.${cd_keyid}.link
wget -P .in_toto https://github.com/${github_repo}/releases/download/v${version}/wheel.${cd_keyid}.link
```

**Verify 'tuf-${version}.tar.gz' against policies in 'sdist.layout'**
```bash
mkdir empty && cp dist/tuf-${version}.tar.gz empty/ && cd empty
in-toto-verify \
  --link-dir ../.in_toto \
  --layout ../.in_toto/sdist.layout \
  --gpg ${verification_keys[@]} \
  --verbose
cd .. && rm -rf empty
```

**Verify 'tuf-${version}-py3-none-any.whl' against policies in 'wheel.layout'**
```bash
mkdir empty && cp dist/tuf-${version}-py3-none-any.whl empty/ && cd empty
in-toto-verify \
  --link-dir ../.in_toto \
  --layout ../.in_toto/wheel.layout \
  --gpg ${verification_keys[@]} \
  --verbose
cd .. && rm -rf empty
```

*Note about mkdir/cp/cd/rm: `in-toto-verify` requires a directory that contains nothing
but the final product, i.e. the corresponding build artifact (see in-toto/docs#27 for
details).*

## User verification (TODO)

The verification instructions above assume that the maintainer tag and build
attestations are available to the verifier, and that the verifier knows the keys to
verify the layout root signatures. For user verification the following items need to be
resolved:

- publish maintainer public keys to establish trust root (preferably out-of-band)
- sign metadata with multiple maintainer keys
- publish layout and maintainer attestations in canonical place (e.g. GitHub release)
- provide maintainer tools + docs for easy threshold layout signing and metadata upload
- provide user tools + docs for easy verification (w/o wget, mkdir, cp, ...)
