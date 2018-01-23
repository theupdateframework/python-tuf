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

.. image:: /docs/images/banner_readme.JPG
   :scale: 50 %

The Update Framework (TUF) helps developers to secure new or existing software
update systems, which are often found to be vulnerable to many known attacks.
TUF addresses this widespread problem by providing a comprehensive, flexible
security framework that developers can integrate with any software update
system.  The framework can be easily integrated (or implemented in the native
programming languages of these update systems) due to its concise,
self-contained architecture and specification.

TUF is hosted by the `Cloud Native Computing Foundation
<https://www.cncf.io/>`_ (CNCF) and follows the `CNCF Code of Conduct
<https://github.com/cncf/foundation/blob/master/code-of-conduct.md>`_.

Security Issues and Bugs
------------------------

Security issues can be reported by emailing justincappos@gmail.com.

At a minimum, the report must contain the following:

* Description of the vulnerability.
* Steps to reproduce the issue.

Optionally, reports that are emailed can be encrypted with PGP.  You should use
PGP key fingerprint E9C0 59EC 0D32 64FA B35F  94AD 465B F9F6 F8EB 475A.

Please do not use the GitHub issue tracker to submit vulnerability reports.
The issue tracker is intended for bug reports and to make feature requests.
Major feature requests, such as design changes to the specification, should
be proposed via TUF Augmentation Proposals, which are discussed below.

Mailing List
------------
Please visit our `mailing list
<https://groups.google.com/forum/?fromgroups#!forum/theupdateframework>`_ if
you would like to contact us.  Questions, feedback, and suggestions are
welcomed in this low-volume mailing list.

A `group feed
<https://groups.google.com/forum/feed/theupdateframework/msgs/atom.xml?num=50>`_
is available.

What is a TAP?
--------------

A TAP (TUF Augmentation Proposal) is a design document providing information to
the TUF community, or describing a new feature for TUF or its processes or
environment.  We intend TAPs to be the primary mechanisms for proposing major
new features, for collecting community input on an issue, and for documenting
the design decisions that have gone into TUF.

Please visit the `TAPs GitHub repo <https://github.com/theupdateframework/taps>`_
to review design changes that have been proposed to date, or to submit
your own new feature.

Using TUF
---------

TUF has four major classes of users: clients, for whom TUF is largely
transparent; mirrors, who will (in most cases) have nothing at all to do
with TUF; upstream servers, who will largely be responsible for care and
feeding of repositories; and integrators, who do the work of putting TUF
into existing projects.

An integration requires importing a single module into the new or existing
software updater and calling particular methods to perform updates.  Generating
metadata files stored on upstream servers can be handled by repository tools that
we provide for this purpose.


- `Integrating with a Software Updater <https://github.com/theupdateframework/tuf/tree/develop/tuf/client/README.md>`_

- `Creating a TUF Repository  <https://github.com/theupdateframework/tuf/tree/develop/tuf/README.md>`_

License
-------

This work is `dual-licensed <https://en.wikipedia.org/wiki/Multi-licensing>`_
and distributed under the (1) MIT License and (2) Apache License, Version 2.0.
Please see `LICENSE-MIT.txt
<https://github.com/theupdateframework/tuf/blob/develop/LICENSE-MIT.txt>`_
and `LICENSE-APACHE.txt
<https://github.com/theupdateframework/tuf/blob/develop/LICENSE-APACHE.txt>`_.


Acknowledgements
----------------

This project is managed by Prof. Justin Cappos and other members of the
`Secure Systems Lab <https://ssl.engineering.nyu.edu/>`_ at NYU.

This material is based upon work supported by the National Science
Foundation under Grant Nos. CNS-1345049 and CNS-0959138. Any opinions,
findings, and conclusions or recommendations expressed in this material
are those of the author(s) and do not necessarily reflect the views of
the National Science Foundation.
