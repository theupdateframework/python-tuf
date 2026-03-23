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
Contributors can submit pull requests to the project's repositories. They must
follow the project's [code of conduct](CODE-OF-CONDUCT.md), the
[developer certificate of origin](https://developercertificate.org/), and the
repository specific contribution guidelines, such as
[CONTRIBUTING.rst](CONTRIBUTING.rst).

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
