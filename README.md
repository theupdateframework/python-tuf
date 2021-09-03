# <img src="https://cdn.rawgit.com/theupdateframework/artwork/3a649fa6/tuf-logo.svg" height="100" valign="middle" alt="TUF"/> A Framework for Securing Software Update Systems

![Build](https://github.com/theupdateframework/python-tuf/workflows/Run%20TUF%20tests%20and%20linter/badge.svg)
[![Coveralls](https://coveralls.io/repos/theupdateframework/python-tuf/badge.svg?branch=develop)](https://coveralls.io/r/theupdateframework/python-tuf?branch=develop)
[![Docs](https://readthedocs.org/projects/theupdateframework/badge/)](https://theupdateframework.readthedocs.io/)
[![CII](https://bestpractices.coreinfrastructure.org/projects/1351/badge)](https://bestpractices.coreinfrastructure.org/projects/1351)
[![PyPI](https://img.shields.io/pypi/v/tuf)](https://pypi.org/project/tuf/)

----------------------------
This repository is the **reference implementation** of
[The Update Framework (TUF)](https://theupdateframework.github.io/).
It is written in Python and intended to conform to version 1.0 of the
[TUF specification](https://theupdateframework.github.io/specification/latest/).

The repository currently includes two implementations:
1) A *legacy implementation*, with
   [`tuf/client/updater.py`](tuf/client/updater.py) implementing the detailed
   client workflow and [`tuf/repository_tool.py`](tuf/repository_tool.py)
   providing a high-level interface for repository operations.
   The legacy implementation is in use in production systems, but is [no longer
   being actively worked on](docs/adr/0002-pre-1-0-deprecation-strategy.md).
2) A *modern implementation*. We are in the process of rewriting the reference
   implementation in [modern Python](docs/adr/0001-python-version-3-6-plus.md)
   to both: a) address scalability and integration issues identified in
   supporting integration into the Python Package Index (PyPI), and other
   large-scale repositories, and b) to ensure maintainability of the project.
   This implementation consists of:
   * a "low-level" metadata API, designed to provide easy and safe access to
     TUF metadata and handle (de)serialization from/to files, provided in the
     [`tuf/api/metadata.py`](tuf/api/metadata.py) module.
   * an implementation of the detailed client workflow built on top of the
     metadata API, provided in the
     [`tuf/ngclient/updater.py`](tuf/ngclient/updater.py) module.
   The modern implementation is not considered production ready and does not yet
   provide any high-level support for implementing
   [repository operations](https://theupdateframework.github.io/specification/latest/#repository-operations),
   though the addition of API to support them is planned.



The reference implementation strives to be a readable guide and demonstration
for those working on implementing TUF in their own languages, environments, or
update systems.


About The Update Framework
--------------------------
The Update Framework (TUF) design helps developers maintain the security of a
software update system, even against attackers that compromise the repository
or signing keys.
TUF provides a flexible
[specification](https://github.com/theupdateframework/specification/blob/master/tuf-spec.md)
defining functionality that developers can use in any software update system or
re-implement to fit their needs.

TUF is hosted by the [Linux Foundation](https://www.linuxfoundation.org/) as
part of the [Cloud Native Computing Foundation](https://www.cncf.io/) (CNCF)
and its design is [used in production](https://theupdateframework.io/adoptions/)
by various tech companies and open source organizations. A variant of TUF
called [Uptane](https://uptane.github.io/) is used to secure over-the-air
updates in automobiles.

Please see the [TUF Introduction](docs/OVERVIEW.rst) and
[TUF's website](https://theupdateframework.com/) for more information about TUF!


Documentation
-------------
* [Introduction to TUF's Design](docs/OVERVIEW.rst)
* [The TUF Specification](https://theupdateframework.github.io/specification/latest/)
* [Getting Started with the TUF Reference Implementation](docs/GETTING_STARTED.rst)
* [Governance](docs/GOVERNANCE.md) and [Maintainers](docs/MAINTAINERS.txt)
for the reference implementation
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

Limitations
-----------

The reference implementation may behave unexpectedly when concurrently
downloading the same target files with the same TUF client.

License
-------

This work is [dual-licensed](https://en.wikipedia.org/wiki/Multi-licensing) and
distributed under the (1) MIT License and (2) Apache License, Version 2.0.
Please see [LICENSE-MIT](LICENSE-MIT) and [LICENSE](LICENSE).


Acknowledgements
----------------

This project is hosted by the Linux Foundation under the Cloud Native Computing
Foundation.  TUF's early development was managed by
members of the [Secure Systems Lab](https://ssl.engineering.nyu.edu/) at [New
York University](https://engineering.nyu.edu/).  We appreciate the efforts of
Konstantin Andrianov, Geremy Condra, Vladimir Diaz, Yuyu Zheng, Sebastien Awwad,
Santiago Torres-Arias, Trishank Kuppusamy, Zane Fisher, Pankhuri Goyal, Tian Tian,
Konstantin Andrianov, and Justin Samuel who are among those who helped significantly
with TUF's reference implementation.  [Contributors](https://github.com/theupdateframework/python-tuf/blob/develop/docs/AUTHORS.txt)
and
[maintainers](https://github.com/theupdateframework/python-tuf/blob/develop/docs/MAINTAINERS.txt)
are governed by the [CNCF Community Code of
Conduct](https://github.com/cncf/foundation/blob/master/code-of-conduct.md).

This material is based upon work supported by the National Science Foundation
under Grant Nos. CNS-1345049 and CNS-0959138. Any opinions, findings, and
conclusions or recommendations expressed in this material are those of the
author(s) and do not necessarily reflect the views of the National Science
Foundation.
