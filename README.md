# <img src="https://cdn.rawgit.com/theupdateframework/artwork/3a649fa6/tuf-logo.svg" height="100" valign="middle" alt="TUF"/> A Framework for Securing Software Update Systems

![Build](https://github.com/theupdateframework/python-tuf/actions/workflows/ci.yml/badge.svg)
[![Coveralls](https://coveralls.io/repos/theupdateframework/python-tuf/badge.svg?branch=develop)](https://coveralls.io/r/theupdateframework/python-tuf?branch=develop)
[![Docs](https://readthedocs.org/projects/theupdateframework/badge/)](https://theupdateframework.readthedocs.io/)
[![CII](https://bestpractices.coreinfrastructure.org/projects/1351/badge)](https://bestpractices.coreinfrastructure.org/projects/1351)
[![PyPI](https://img.shields.io/pypi/v/tuf)](https://pypi.org/project/tuf/)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/theupdateframework/python-tuf/badge)](https://scorecard.dev/viewer/?uri=github.com/theupdateframework/python-tuf)

----------------------------
[The Update Framework (TUF)](https://theupdateframework.io/) is a framework for
secure content delivery and updates. It protects against various types of
supply chain attacks and provides resilience to compromise. This repository is a
**reference implementation** written in Python. It is intended to conform to
version 1.0 of the [TUF
specification](https://theupdateframework.github.io/specification/latest/).

Python-TUF provides the following APIs:
  * [`tuf.api.metadata`](https://theupdateframework.readthedocs.io/en/latest/api/tuf.api.html),
    a "low-level" API, designed to provide easy and safe access to TUF
    metadata and to handle (de)serialization from/to files.
  * [`tuf.ngclient`](https://theupdateframework.readthedocs.io/en/latest/api/tuf.ngclient.html),
    a client implementation built on top of the metadata API.
  * `tuf.repository`, a repository library also built on top of the metadata
    API. This module is currently not considered part of python-tuf stable API.

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

Please see [TUF's website](https://theupdateframework.com/) for more information about TUF!


Documentation
-------------
* [Introduction to TUF's Design](https://theupdateframework.io/overview/)
* [The TUF Specification](https://theupdateframework.github.io/specification/latest/)
* [Developer documentation](https://theupdateframework.readthedocs.io/), including
  [API reference](
    https://theupdateframework.readthedocs.io/en/latest/api/api-reference.html) and [instructions for contributors](https://theupdateframework.readthedocs.io/en/latest/CONTRIBUTING.html)
* [Usage examples](https://github.com/theupdateframework/python-tuf/tree/develop/examples/)
* [Governance](https://github.com/theupdateframework/python-tuf/blob/develop/docs/GOVERNANCE.md)
and [Maintainers](https://github.com/theupdateframework/python-tuf/blob/develop/docs/MAINTAINERS.txt)
for the reference implementation
* [Miscellaneous Docs](https://github.com/theupdateframework/python-tuf/tree/develop/docs)
* [Python-TUF development blog](https://theupdateframework.github.io/python-tuf/)


Contact
-------
Questions, feedback, and suggestions are welcomed on our low volume [mailing
list](https://groups.google.com/forum/?fromgroups#!forum/theupdateframework) or
the [#tuf](https://cloud-native.slack.com/archives/C8NMD3QJ3) channel on [CNCF
Slack](https://slack.cncf.io/).

We strive to make the specification easy to implement, so if you come across
any inconsistencies or experience any difficulty, do let us know by sending an
email, or by reporting an issue in the GitHub [specification
repo](https://github.com/theupdateframework/specification/issues).

Security Issues and Bugs
------------------------

See [SECURITY.md](docs/SECURITY.md)

License
-------

This work is [dual-licensed](https://en.wikipedia.org/wiki/Multi-licensing) and
distributed under the (1) MIT License and (2) Apache License, Version 2.0.
Please see [LICENSE-MIT](https://github.com/theupdateframework/python-tuf/blob/develop/LICENSE-MIT)
and [LICENSE](https://github.com/theupdateframework/python-tuf/blob/develop/LICENSE).


Acknowledgements
----------------

This project is hosted by the Linux Foundation under the Cloud Native Computing
Foundation.  TUF's early development was managed by members of the [Secure
Systems Lab](https://ssl.engineering.nyu.edu/) at [New York
University](https://engineering.nyu.edu/). We appreciate the efforts of all
[maintainers and emeritus
maintainers](https://github.com/theupdateframework/python-tuf/blob/develop/docs/MAINTAINERS.txt),
as well as the contributors Konstantin Andrianov, Kairo de Araujo, Ivana
Atanasova, Geremy Condra, Zane Fisher, Pankhuri Goyal, Justin Samuel, Tian
Tian, Martin Vrachev and Yuyu Zheng who are among those who helped
significantly with TUF's reference implementation. Maintainers and Contributors
are governed by the [CNCF Community Code of
Conduct](https://github.com/cncf/foundation/blob/master/code-of-conduct.md).

This material is based upon work supported by the National Science Foundation
under Grant Nos. CNS-1345049 and CNS-0959138. Any opinions, findings, and
conclusions or recommendations expressed in this material are those of the
author(s) and do not necessarily reflect the views of the National Science
Foundation.
