# Release process


**Prerequisites (one-time setup)**

1. Enable "Trusted Publishing" in PyPI project settings
   * Publisher: GitHub
   * Owner: theupdateframework
   * Project: python-tuf
   * Workflow: cd.yml
   * Environment: release
1. Go to [GitHub
   settings](https://github.com/theupdateframework/python-tuf/settings/environments),
   create an
   [environment](https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment#creating-an-environment)
   called `release` and configure [review
   protection](https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment#required-reviewers).

## Release

1. Ensure `docs/CHANGELOG.md` contains a one-line summary of each [notable
  change](https://keepachangelog.com/) since the prior release
2. Update `tuf/__init__.py` to the new version number `A.B.C`
3. Create a PR with updated `CHANGELOG.md` and version bumps

&#10132; Review PR on GitHub

4. Once the PR is merged, pull the updated `develop` branch locally
5. Create a signed tag for the version number on the merge commit
  `git tag --sign vA.B.C -m "vA.B.C"`
6. Push the tag to GitHub `git push origin vA.B.C`

  *A tag push triggers the [CD
  workflow](https://github.com/theupdateframework/python-tuf/blob/develop/.github/workflows/cd.yml),
  which runs the tests, builds source dist and wheel, creates a preliminary GitHub
  release under `vA.B.C-rc`, and pauses for review.*

7. Run `verify_release --skip-pypi` locally to make sure a build on your machine matches
  the preliminary release artifacts published on GitHub.

&#10132; [Review *deployment*](https://docs.github.com/en/actions/managing-workflow-runs/reviewing-deployments)
on GitHub

  *An approval resumes the CD workflow to publish the release on PyPI, and to finalize the
  GitHub release (removes `-rc` suffix and updates release notes).*

8. Run `verify_release` to make sure the PyPI release artifacts match the local build as
   well. When called as `verify_release --sign [<key id>]` the script additionally
   creates gpg release signatures. When signed by maintainers with a corresponding GPG
   fingerprint in the MAINTAINERS.md file, these signature files should be made available on
   the GitHub release page under Assets.
9. Announce the release on [#tuf on CNCF Slack](https://cloud-native.slack.com/archives/C8NMD3QJ3)
10. Ensure [POUF 1](https://github.com/theupdateframework/taps/blob/master/POUFs/reference-POUF/pouf1.md),
    for the reference implementation, is up-to-date
