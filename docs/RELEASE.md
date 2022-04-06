# Release process

1. Ensure `docs/CHANGELOG.md` contains a one-line summary of each [notable
  change](https://keepachangelog.com/) since the prior release
2. Update `tuf/__init__.py` to the new version number `A.B.C`
3. Create a PR with updated `CHANGELOG.md` and version bumps

&#10132; Review PR on GitHub

4. Once the PR is merged, pull the updated `develop` branch locally
5. Create a signed tag for the version number on the merge commit
  `git tag --sign vA.B.C -m "vA.B.C"`
6. Push the tag to GitHub `git push origin vA.B.C`

  *A push triggers the [CI workflow](.github/workfows/ci.yml), which, on success, triggers
  the [CD worfklow](.github/workfows/cd.yml), which builds source dist and wheel,
  creates a preliminary GitHub release under `vA.B.C-rc`, and pauses for review.*

7. Run `verify_release --skip-pypi` locally to make sure a build on your machine matches
  the preliminary release artifacts published on GitHub.

&#10132; [Review *deployemnt*](https://docs.github.com/en/actions/managing-workflow-runs/reviewing-deployments) on GitHub

  *An approval resumes the CD workflow to publish the release on PyPI, and to finalize the
  GitHub release (removse `-rc` suffix and updates release notes).*

8. `verify_release` may be used again to make sure the release artifacts PyPI.
9. Announce the release on [#tuf on CNCF Slack](https://cloud-native.slack.com/archives/C8NMD3QJ3)
10. Ensure [POUF 1](https://github.com/theupdateframework/taps/blob/master/POUFs/reference-POUF/pouf1.md), for the reference implementation, is up-to-date
