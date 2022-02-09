# TUF governance
This document covers the project's governance and committer process.  The
project consists of the TUF
[specification](https://github.com/theupdateframework/specification) and
[reference implementation](https://github.com/theupdateframework/python-tuf).

## Maintainership and Consensus Builder
The project is maintained by the people indicated in
[MAINTAINERS](MAINTAINERS.txt).  A maintainer is expected to (1) submit and
review GitHub pull requests and (2) open issues or [submit vulnerability
reports](https://github.com/theupdateframework/python-tuf#security-issues-and-bugs).
A maintainer has the authority to approve or reject pull requests submitted by
contributors.

More significant changes in the project, such as those that require a TAP or
changes in governance, are guided by a maintainer called the Consensus
Builder (CB).  The project's Consensus Builder (CB) is Justin Cappos
<jcappos@nyu.edu, @JustinCappos>, who has a lifetime appointment.

## Contributions
[A contributor can submit GitHub pull
requests](CONTRIBUTING.rst)
to the project's repositories.  They must follow the project's [code of
conduct](CODE-OF-CONDUCT.md), the [developer certificate of
origin](https://developercertificate.org/), the [code style
guidelines](https://github.com/secure-systems-lab/code-style-guidelines), and
must unit test any new software feature or change.  Submitted pull requests
undergo review and automated testing, including, but not limited to:

* Unit and build testing via [GitHub Actions](https://github.com/theupdateframework/python-tuf/actions) and
[Tox](https://tox.readthedocs.io/en/latest/).
* Static code analysis via [Pylint](https://www.pylint.org/) and
[Bandit](https://wiki.openstack.org/wiki/Security/Projects/Bandit).
- Auto-formatting with [black](https://black.readthedocs.io/) and
[isort](https://pycqa.github.io/isort/).
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

The CB supervises changes in governance, but a majority of maintainers must vote +1 on the PR.

## Changes in the consensus builder

The consensus builder may be appointed for a fixed term or it may be a lifetime appointment.  To initiate a change of consensus builder, or a change in the length of the appointment,  a GitHub PR must be opened.  If a fixed term is specified, the PR should be opened no earlier than 6 weeks before the end of the CB's term. If there is not a fixed term appointment, the PR may be opened at any time.  In either case, the PR must be kept open for no less than 4 weeks.  Additionally, the PR can only be merged with more +1 than -1 in the binding votes.

Anyone from the community can vote on the PR with either +1 or -1.

Only votes from maintainers that have been listed in the top-level [MAINTAINERS](MAINTAINERS.txt) file before the PR is opened are binding.

When there are conflicting PRs about changes in the consensus builder, the PR with the most binding +1 votes is merged.

The consensus builder can volunteer to step down.
