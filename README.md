A Framework for Securing Software Update Systems
------------------------------------------------

[![Travis-CI](https://travis-ci.org/theupdateframework/tuf.svg?branch=develop)](https://travis-ci.org/theupdateframework/tuf)
[![Coveralls](https://coveralls.io/repos/theupdateframework/tuf/badge.svg?branch=develop)](https://coveralls.io/r/theupdateframework/tuf?branch=develop)
[![PyUp](https://pyup.io/repos/github/theupdateframework/tuf/shield.svg)](https://pyup.io/repos/github/theupdateframework/tuf/)
[![Python 3](https://pyup.io/repos/github/theupdateframework/tuf/python-3-shield.svg)](https://pyup.io/repos/github/theupdateframework/tuf/)
[![FOSSA](https://app.fossa.io/api/projects/git%2Bgithub.com%2Ftheupdateframework%2Ftuf.svg?type=shield)](https://app.fossa.io/projects/git%2Bgithub.com%2Ftheupdateframework%2Ftuf?ref=badge_shield)
[![CII](https://bestpractices.coreinfrastructure.org/projects/1351/badge)](https://bestpractices.coreinfrastructure.org/projects/1351)

# <img src="https://cdn.rawgit.com/theupdateframework/artwork/3a649fa6/tuf-logo.svg" height="100" valign="middle" alt="TUF"/>

The Update Framework (TUF) helps developers maintain the security of a software
update system, even against attackers that compromise the repository or signing
keys. TUF provides a flexible framework and specification that developers can
adopt into any software update system.

TUF is hosted by the [Linux Foundation](https://www.linuxfoundation.org/) as
part of the [Cloud Native Computing Foundation](https://www.cncf.io/) (CNCF)
and is used [in production](docs/ADOPTERS.md) by companies such as Docker,
DigitalOcean, Flynn, LEAP, Kolide, Cloudflare, and VMware. A variant of TUF
called [Uptane](https://uptane.github.io/) is widely used to secure
over-the-air updates in automobiles.


Documentation
-------------
* [Overview](docs/OVERVIEW.rst)
* [Specification](https://github.com/theupdateframework/specification/blob/master/tuf-spec.md)
* [Getting Started](docs/GETTING_STARTED.rst)
* [Governance](docs/GOVERNANCE.md) and [Maintainers](docs/MAINTAINERS.txt)
* [Miscellaneous Docs](docs/)


Contact
-------
Please contact us via our [mailing
list](https://groups.google.com/forum/?fromgroups#!forum/theupdateframework).
Questions, feedback, and suggestions are welcomed on this low volume mailing
list.

We strive to make the specification easy to implement, so if you come across
any inconsistencies or experience any difficulty, do let us know by sending an
email, or by reporting an issue in the GitHub [specification
repo](https://github.com/theupdateframework/specification/issues).

Security Issues and Bugs
------------------------

Security issues can be reported by emailing jcappos@nyu.edu.

At a minimum, the report must contain the following:

* Description of the vulnerability.
* Steps to reproduce the issue.

Optionally, reports that are emailed can be encrypted with PGP.  You should use
PGP key fingerprint **E9C0 59EC 0D32 64FA B35F  94AD 465B F9F6 F8EB 475A**.

Please do not use the GitHub issue tracker to submit vulnerability reports.
The issue tracker is intended for bug reports and to make feature requests.
Major feature requests, such as design changes to the specification, should
be proposed via a [TUF Augmentation Proposal](docs/TAP.rst) (TAP).

License
-------

This work is [dual-licensed](https://en.wikipedia.org/wiki/Multi-licensing) and
distributed under the (1) MIT License and (2) Apache License, Version 2.0.
Please see [LICENSE-MIT](LICENSE-MIT) and [LICENSE](LICENSE).


Acknowledgements
----------------

This project is managed by Prof. [Justin
Cappos](https://ssl.engineering.nyu.edu/personalpages/jcappos/) and other
members of the [Secure Systems Lab](https://ssl.engineering.nyu.edu/) at [New
York University](https://engineering.nyu.edu/).
[Contributors](https://github.com/theupdateframework/tuf/blob/develop/docs/AUTHORS.txt)
and
[maintainers](https://github.com/theupdateframework/tuf/blob/develop/docs/MAINTAINERS.txt)
are governed by the [CNCF Community Code of
Conduct](https://github.com/cncf/foundation/blob/master/code-of-conduct.md).

This material is based upon work supported by the National Science Foundation
under Grant Nos. CNS-1345049 and CNS-0959138. Any opinions, findings, and
conclusions or recommendations expressed in this material are those of the
author(s) and do not necessarily reflect the views of the National Science
Foundation.
