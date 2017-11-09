# TUF governance
This document covers the project's governance and committer process.  The
project consists of the TUF
[specification](https://github.com/theupdateframework/specification) and
[reference implementation](https://github.com/theupdateframework/tuf).

## Management and maintainership
The project is managed by Prof. Justin Cappos and is maintained by the people
indicated in [MAINTAINERS.md](MAINTAINERS.md).  A maintainer is expected to (1)
submit and review GitHub pull requests and (2) open issues or [submit
vulnerability
reports](https://github.com/theupdateframework/tuf#security-issues-and-bugs).
A maintainer has the authority to approve or reject pull requests submitted by
contributors.

## Contributions
[A contributor can submit GitHub pull
requests](https://github.com/theupdateframework/tuf#instructions-for-contributors)
to the reference implementation repository.  They must follow the project's
[code of conduct](CODE-OF-CONDUCT.md), the [developer certificate of
origin](https://developercertificate.org/), and the [code style
guidelines](https://github.com/secure-systems-lab/code-style-guidelines).
Submitted pull requests undergo review and automated testing and checking,
including but not limited to:

* Unit and build testing via Travis CI
* Static Analysis
* Checks for Signed-off-by commits
* Review by one or more maintainers

A contributor can propose changes to the specification with a [TUF Augmentation
Proposal](https://github.com/theupdateframework/taps) (TAP).  It is a design
document providing information to the TUF community, or describing a new
feature for TUF or its processes or environment.  TAPs can be approved or
rejected by Justin Cappos after the TAP has been reviewed and discussed on the
mailing list or the TAPs GitHub issue tracker.

## Changes in maintainership

A contributor to the project must express interest in becoming a maintainer.
Justin Cappos has the authority to add or remove maintainers.

## Changes in governance
Justin Cappos supervises changes in governance.
