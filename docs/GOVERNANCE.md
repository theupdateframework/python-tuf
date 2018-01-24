# TUF governance
This document covers the project's governance and committer process.  The
project consists of the TUF
[specification](https://github.com/theupdateframework/specification) and
[reference implementation](https://github.com/theupdateframework/tuf).

## Maintainership and Consensus Builder
The project is maintained by the people indicated in
[MAINTAINERS](MAINTAINERS.txt).  A maintainer is expected to (1) submit and
review GitHub pull requests and (2) open issues or [submit vulnerability
reports](https://github.com/theupdateframework/tuf#security-issues-and-bugs).
A maintainer has the authority to approve or reject pull requests submitted by
contributors.  The project's Consensus Builder (CB) is
Justin Cappos <jcappos@nyu.edu, @JustinCappos>.

## Contributions
[A contributor can submit GitHub pull
requests](CONTRIBUTORS.rst)
to the project's repositories.  They must follow the project's [code of
conduct](CODE-OF-CONDUCT.md), the [developer certificate of
origin](https://developercertificate.org/), the [code style
guidelines](https://github.com/secure-systems-lab/code-style-guidelines), and
must unit test any new software feature or change.  Submitted pull requests
undergo review and automated testing, including, but not limited to:

* Unit and build testing via [Travis CI](https://travis-ci.org/) and
[Tox](https://tox.readthedocs.io/en/latest/).
* Static code analysis via [Pylint](https://www.pylint.org/) and
[Bandit](https://wiki.openstack.org/wiki/Security/Projects/Bandit).
* Checks for Signed-off-by commits via [Probot: DCO](https://github.com/probot/dco).
* Review by one or more
[maintainers](MAINTAINERS.txt).

A contributor can propose changes to the specification with a [TUF Augmentation
Proposal](https://github.com/theupdateframework/taps) (TAP).  It is a design
document providing information to the TUF community, or describing a new
feature for TUF or its processes or environment.

A [TAP](TAP.rst) can be approved or rejected by the CB after it has been reviewed and
discussed.  Discussions take place on the project's [mailing
list](https://groups.google.com/forum/?fromgroups#!forum/theupdateframework) or
the TAPs GitHub issue tracker.

## Changes in maintainership

A contributor to the project must express interest in becoming a maintainer.
The CB has the authority to add or remove maintainers.

## Changes in governance
The CB supervises changes in governance.
