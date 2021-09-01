# Deprecation strategy for current release series (0.x)

* Date: 2020-11-05

Technical Story: https://github.com/theupdateframework/python-tuf/issues/1127

## Context and Problem Statement

We plan to refactor the reference implementation significantly and, as part of
that effort, drop support for no-longer maintained versions of Python
(see ADR 0001).

However, a major user of (and contributor to) the project has users of the
client stuck on older Python versions.

We would like to define a reasonable support policy for the current, Python 2.7
supporting, codebase.

## Decision Drivers

* We have finite resources.
* A major adopter/user of the project has a need to maintain support for
  Python 2.7 clients.

## Considered Options

* Maintain the code in parallel for a fixed period of time after releasing the
  refactored code.
* Abandon the old code once the refactored code is released.
* Support the old code on a best-effort basis once the refactored code is
  released.

## Decision Outcome

Chosen option: "Support the old code on a best-effort basis once the refactored
code is released", because we only have finite resources and want to focus them
on moving the project forward, including supporting PyPI/pip integration and
providing a solid implementation for developing specification enhancements in.

We should document this outcome clearly in a governance document describing
the release process with words along the lines of:

"Support for older releases:
Bugs reported with tuf versions prior to 1.0.0 will likely not be addressed
directly by tuf’s maintainers. Pull Requests to fix bugs in the last release
prior to 1.0.0 will be considered, and merged (subject to normal review
processes). Note that there may be delays due to the lack of developer resources
for reviewing such pull requests."

## Links

* [ADR 0001](0001-python-version-3-6-plus.md) Python version
