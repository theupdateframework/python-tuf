A Framework for Securing Software Update Systems
------------------------------------------------

.. image:: https://travis-ci.org/theupdateframework/tuf.svg?branch=develop
   :target: https://travis-ci.org/theupdateframework/tuf
   :alt: Travis

.. image:: https://coveralls.io/repos/theupdateframework/tuf/badge.svg?branch=develop
   :target: https://coveralls.io/r/theupdateframework/tuf?branch=develop
   :alt: Coveralls

.. image:: https://pyup.io/repos/github/theupdateframework/tuf/shield.svg
   :target: https://pyup.io/repos/github/theupdateframework/tuf/
   :alt: pyup

.. image:: https://pyup.io/repos/github/theupdateframework/tuf/python-3-shield.svg
   :target: https://pyup.io/repos/github/theupdateframework/tuf/
   :alt: Python 3

.. image:: https://app.fossa.io/api/projects/git%2Bgithub.com%2Ftheupdateframework%2Ftuf.svg?type=shield
   :target: https://app.fossa.io/projects/git%2Bgithub.com%2Ftheupdateframework%2Ftuf?ref=badge_shield
   :alt: FOSSA

.. image:: https://bestpractices.coreinfrastructure.org/projects/1351/badge
   :target: https://bestpractices.coreinfrastructure.org/projects/1351
   :alt: CII

.. raw:: html

   <img
   src="https://github.com/theupdateframework/artwork/blob/master/tuf-logo-text.svg"
   height="200px">

---------------------------------------------------------------

The Update Framework (TUF) helps developers secure new or existing software
update systems, which are often found to be vulnerable to many known attacks.
TUF addresses this widespread problem by providing a comprehensive, flexible
security framework that developers can integrate with any software update
system.  The framework can be easily integrated (or implemented in the native
programming languages of these update systems) due to its concise,
self-contained architecture and specification.  `Adopters <docs/ADOPTERS.md>`_
have so far implemented the framework in the Go (`1
<https://github.com/theupdateframework/notary>`_, `2
<https://github.com/flynn/go-tuf>`_), `Haskell
<https://www.well-typed.com/blog/2015/07/hackage-security-alpha/>`_, `Python
<https://github.com/theupdateframework/tuf>`_, `Ruby
<https://medium.com/square-corner-blog/securing-rubygems-with-tuf-part-1-d374fdd05d85>`_,
and `Rust <https://github.com/heartsucker/rust-tuf>`_ programming languages.

The Update Framework (TUF) helps developers maintain the security of a software
update system, even against attackers that compromise the repository or signing
keys. TUF provides a flexible framework and specification that developers can
adopt into any software update system.

TUF is hosted by the `Linux Foundation <https://www.linuxfoundation.org/>`_ as
part of the `Cloud Native Computing Foundation <https://www.cncf.io/>`_ (CNCF)
and is used `in production <docs/ADOPTERS.md>`_ by companies such as Docker,
DigitalOcean, Flynn, LEAP, Kolide, Cloudflare, and VMware. A variant of TUF
called `Uptane <https://uptane.github.io/>`_ is widely used to secure
over-the-air updates in automobiles.


Documentation
-------------
* `Overview <docs/OVERVIEW.rst>`_
* `Specification <https://github.com/theupdateframework/specification/blob/master/tuf-spec.md>`_
* `Getting Started <docs/GETTING_STARTED.rst>`_
* `Governance <docs/GOVERNANCE.md>`_ and `Maintainers <docs/MAINTAINERS.txt>`_
* `Miscellaneous Docs <docs/>`_


Contact
-------
Please contact us via our `mailing list
<https://groups.google.com/forum/?fromgroups#!forum/theupdateframework>`_.
Questions, feedback, and suggestions are welcomed on this low-volume mailing
list.

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
be proposed via a `TUF Augmentation Proposal <docs/TAP.rst>`_.

License
-------

This work is `dual-licensed <https://en.wikipedia.org/wiki/Multi-licensing>`_
and distributed under the (1) MIT License and (2) Apache License, Version 2.0.
Please see `LICENSE-MIT <LICENSE-MIT>`_ and `LICENSE
<LICENSE>`_.


Acknowledgements
----------------

This project is managed by Prof. `Justin Cappos
<https://ssl.engineering.nyu.edu/personalpages/jcappos/>`_ and other members of
the `Secure Systems Lab <https://ssl.engineering.nyu.edu/>`_ at `New York
University <https://engineering.nyu.edu/>`_.  `Contributors
<https://github.com/theupdateframework/tuf/blob/develop/docs/AUTHORS.txt>`_ and
`maintainers
<https://github.com/theupdateframework/tuf/blob/develop/docs/MAINTAINERS.txt>`_
are governed by the `CNCF Community Code of Conduct
<https://github.com/cncf/foundation/blob/master/code-of-conduct.md>`_.

This material is based upon work supported by the National Science Foundation
under Grant Nos. CNS-1345049 and CNS-0959138. Any opinions, findings, and
conclusions or recommendations expressed in this material are those of the
author(s) and do not necessarily reflect the views of the National Science
Foundation.
