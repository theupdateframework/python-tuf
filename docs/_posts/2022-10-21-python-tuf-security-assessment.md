---
title: "Python-tuf source code audit"
author: Joshua Lock
---

We are pleased to announce completion of a source code audit of the recently
refactored python-tuf codebase.

# Background

In February 2022 the python-tuf team [released version 1.0](
    https://theupdateframework.github.io/python-tuf/2022/02/21/release-1-0-0.html
). This release was the product of a significant refactoring effort with the
code being rewritten from scratch to provide two new stable API’s:
* A low-level interface for creating and consuming TUF metadata
* A robust and pluggable client implementation

Unifying both of these APIs is a focus on developer ergonomics and flexibility
of the API.

While the new python-tuf codebase is much leaner, a mere 1,400 lines of code at
release, compared to the legacy code’s 4,700 lines, and builds on the lessons
learned from development (and developers) on the prior versions of python-tuf,
we were very conscious of the fact that our first major release of a security
project was made up of newly authored code.

To improve our confidence in this newly authored code we engaged with the Open
Source Technology Improvement Fund (OSTIF) to have an independent security
assessment of the new python-tuf code. OSTIF connected us with the team at X41
D-Sec who performed a thorough source code audit, the results of which we are
releasing today.

# Results and resolutions

The report prepared by X41 included one medium severity and three low severity
issues, we describe below how we are addressing each of those reported items.

**Private Key World-Readable (TUF-CR-22-01) – Medium**

This vulnerability is not in any code called by python-tuf, but was included in
demonstrative code the python-tuf team provided to the X41 team. The underlying
issue is in 
[securesystemslib](https://github.com/secure-systems-lab/securesystemslib), a
utility library used by python-tuf which provides a consistent interface around
various cryptography APIs and related functionality, where any files were
created with the default permissions of the running process.

We resolved this issue by [adding an optional restrict parameter](
    https://github.com/secure-systems-lab/securesystemslib/pull/231/files)
to the `storage.put()` interface and in the corresponding filesystem
implementation of the interface ensuring that when `restrict=True` files are
created with octal permissions `0o600` (read and write for the user only).

This enhancement has been included in the recent release of 
[securesystemslib 0.25.0](
    https://github.com/secure-systems-lab/securesystemslib/releases/tag/v0.25.0
).

**Shallow Build Artifact Verification (TUF-CR-22-02) – Low**

The `verify_release` script, run by python-tuf developers as part of the
release process and available to users to verify that a release on GitHub or
PyPI matches a build of source code from the repository, was only performing
a shallow comparison of files. That is, only the type, size, and modification
times were compared. We have [modified the script](
    https://github.com/theupdateframework/python-tuf/pull/2122/files
) to perform a deep comparison of the contents and attributes of files being
verified.

**Quadratic Complexity in JSON Number Parsing (TUF-CR-22-03) – Low**

This issue was not in python-tuf itself, rather the problem was in Python’s
built-in json module.

Fortunately, we did not need to take any action for this issue as it was
independently reported upstream and has been fixed in Python. Find more details
in [CVE-2020-10735: Prevent DoS by large int<->str conversions](
    https://github.com/python/cpython/issues/95778) on Python’s issue tracker.

**Release Signatures Add No Protection (TUF-CR-22-04) – Low**

python-tuf releases are built by GitHub Actions in response to a developer
pushing a tag. However, before those releases are published to the project’s
GitHub releases page and PyPI a developer must verify (using the
`verify_release` script discussed earlier) and approve the release. Part of the
approval includes creating a detached signature and including that in the
release artifacts. While these do not add any additional protection, we do
believe that the additional authenticity signal is worthwhile to users.

Furthermore, along with the above notice and the recommendations in the
informational notes we will continue to iterate on our build and release
process to provide additional security for users of python-tuf.

# Thank you

We are extremely grateful to X41 for their thorough audit of the python-tuf
code, to [Open Source Technology Improvement Fund](https://ostif.org) (OSTIF)
for connecting us with the [X41 D-Sec, GMBH](https://x41-dsec.de) team, and to
the [Cloud Native Computing Foundation](https://www.cncf.io) (CNCF) for funding
the source code audit – thank you all.

Read the full report here: [Source Code Audit on The Update Framework for Open Source Technology Improvement Fund (OSTIF)](
    https://theupdateframework.io/audits/x41-python-tuf-audit-2022-09-09.pdf).
