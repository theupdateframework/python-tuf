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
   :alt: Pyup

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

The Update Framework (TUF) helps developers to secure new or existing
software update systems, which are often found to be vulnerable to many
known attacks. TUF addresses
this widespread problem by providing a comprehensive, flexible security
framework that developers can integrate with any software update system.
The framework can be easily integrated (or implemented in the native
programming languages of these update systems) due to its concise,
self-contained architecture and specification.

TUF is hosted by the `Cloud Native Computing Foundation
<https://www.cncf.io/>`_ (CNCF) and follows the `CNCF Code of Conduct
<https://github.com/cncf/foundation/blob/master/code-of-conduct.md>`_.

What Is a Software Update System?
---------------------------------

Generally, a software update system is an application (or part of an
application) running on a client system that obtains and installs
software. These systems typically update the applications installed
on client systems to introduce new features, enhancements, and security
fixes.

Three major classes of software update systems are:

-  **Application updaters** which are used by applications to update
   themselves. For example, Firefox updates itself through its own
   application updater.

-  **Library package managers** such as those offered by many
   programming languages for installing additional libraries. These are
   systems such as Python's pip/easy_install + PyPI, Perl's CPAN,
   Ruby's RubyGems, and PHP's Composer.

-  **System package managers** used by operating systems to update and
   install all of the software on a client system. Debian's APT, Red
   Hat's YUM, and openSUSE's YaST are examples of these.

Our Approach
------------

There are literally thousands of different software update systems in
common use today. (In fact the average Windows user has about `two
dozen <http://secunia.com/gfx/pdf/Secunia_RSA_Software_Portfolio_Security_Exposure.pdf>`_
different software updaters on their machine!)

We are building a library that can be universally (and in most cases
transparently) used to secure software update systems.

Overview
--------

On the surface, the update procedure followed by a software update system can be regarded
as straightforward.  Obtaining and installing an update just means:

-  Knowing when an update exists.
-  Downloading the update.
-  Applying the changes introduced by the update.

The problem with this view is that it is only straightforward when there
are no malicious parties involved throughout the update procedure. If an attacker
is trying to interfere with these seemingly simple steps, there is plenty
that they can do.

TUF is designed to perform the first two steps of the above update procedure,
while guarding against the majority of attacks that malicious actors have at
their disposal; especially those attacks that are overlooked by security-conscious
developers.


Background
----------

Let's assume you take the approach that most systems do (at least, the
ones that even try to be secure). You download both the file you want
and a cryptographic signature of the file. You already know which key
you trust to make the signature. You check that the signature is correct
and was made by this trusted key. All seems well, right? Wrong. You are
still at risk in many ways, including:

-  An attacker keeps giving you the same file, so you never realize
   there is an update.
-  An attacker gives you an older, insecure version of a file that you
   already have, so you download that one and blindly use it thinking
   it's newer.
-  An attacker gives you a newer version of a file you have but it's not
   the newest one. It's newer to you, but it may be insecure and
   exploitable by the attacker.
-  An attacker compromises the key used to sign these files and now you
   download a malicious file that is properly signed.

These are just some of the attacks software update systems are
vulnerable to when only using signed files. See
`Security <https://github.com/theupdateframework/tuf/tree/develop/SECURITY.md>`_ for a full list of attacks and updater
weaknesses TUF is designed to prevent.

The following papers provide detailed information on securing software
updater systems, TUF's design and implementation details, attacks on
package managers, and package management security:

-  `Mercury: Bandwidth-Effective Prevention of Rollback Attacks Against Community Repositories
   <https://github.com/theupdateframework/tuf/tree/develop/docs/papers/prevention-rollback-attacks-atc2017.pdf?raw=true>`_

-  `Diplomat: Using Delegations to Protect Community Repositories
   <https://github.com/theupdateframework/tuf/tree/develop/docs/papers/protect-community-repositories-nsdi2016.pdf?raw=true>`_

-  `Survivable Key Compromise in Software Update
   Systems <https://github.com/theupdateframework/tuf/tree/develop/docs/papers/survivable-key-compromise-ccs2010.pdf?raw=true>`_

-  `A Look In the Mirror: Attacks on Package
   Managers <https://github.com/theupdateframework/tuf/tree/develop/docs/papers/package-management-security-tr08-02.pdf?raw=true>`_

-  `Package Management
   Security <https://github.com/theupdateframework/tuf/tree/develop/docs/papers/attacks-on-package-managers-ccs2008.pdf?raw=true>`_

What TUF Does
-------------

In order to securely download and verify target files, TUF requires a
few extra files to exist on a repository. These are called metadata
files. TUF metadata files contain additional information, including
information about which keys are trusted, the cryptographic hashes of
files, signatures on the metadata, metadata version numbers, and the
date after which the metadata should be considered expired.

When a software update system using TUF wants to check for updates, it
asks TUF to do the work. That is, your software update system never has
to deal with this additional metadata or understand what's going on
underneath. If TUF reports back that there are updates available, your
software update system can then ask TUF to download these files. TUF
downloads them and checks them against the TUF metadata that it also
downloads from the repository. If the downloaded target files are
trustworthy, TUF hands them over to your software update system. See
`Metadata <https://github.com/theupdateframework/tuf/tree/develop/METADATA.md>`_ for more information and examples.

TUF specification document is also available:

-  `The Update Framework Specification <https://github.com/theupdateframework/specification/blob/master/tuf-spec.md>`_

TUF Home Page
-------------

The home page for the TUF project can be found at:
https://updateframework.com

Security Issues and Bugs
------------------------

Security issues can be reported by emailing justincappos@gmail.com.

At a minimum, the report must contain the following:

* Description of the vulnerability.
* Steps to reproduce the issue.

Optionally, reports that are emailed can be encrypted with PGP.  You should use
PGP key fingerprint E9C0 59EC 0D32 64FA B35F  94AD 465B F9F6 F8EB 475.

Please do not use the GitHub issue tracker to submit vulnerability reports.
The issue tracker is intended for bug reports and to make feature requests.
Major feature requests, such as design changes to the specification, should
be proposed via TUF Augmentation Proposals, which are discussed below.

Mailing List
------------
Please visit
`https://groups.google.com/forum/?fromgroups#!forum/theupdateframework
<https://groups.google.com/forum/?fromgroups#!forum/theupdateframework>`_ if
you would like to contact the TUF team.  Questions, feedback, and suggestions
are welcomed in this low-volume mailing list.

A group feed is available at:
https://groups.google.com/forum/feed/theupdateframework/msgs/atom.xml?num=50

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

Installation
------------

::

    pip - installing and managing Python packages (recommended)

    Installing from Python Package Index (https://pypi.python.org/pypi).
    Note: Please use "pip install --no-use-wheel tuf" if your version
    of pip <= 1.5.6
    $ pip install tuf

    Installing from local source archive.
    $ pip install <path to archive>

    Or from the root directory of the unpacked archive.
    $ pip install .

Instructions for Contributors
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Note: Development of TUF occurs on the "develop" branch of this repository.

Contributions can be made by submitting GitHub pull requests.  Submitted code
should follow our `code style guidelines
<https://github.com/secure-systems-lab/code-style-guidelines>`_, which provide
examples of what to do (or not to do) when writing Python code.

Contributors must also indicate acceptance of the `Developer Certificate of
Origin <https://developercertificate.org/>`_  (DCO) when making a contribution
to the project.  Acceptance of the DCO can be established by appending a
``Signed-off-by: Your Name <example@domain.com>`` to the Git commit message.
For example:

::

    Commit message

    Signed-off-by: Vladimir Diaz <vladimir.v.diaz@gmail.com>

The required ``Signed-off-by`` text can be automatically appended to the commit
message via the ``-s`` command-line option to ``git commit``:

::

  $ git commit -s -m "Commit message"

The full text of the DCO:

::

    Developer Certificate of Origin
    Version 1.1

    Copyright (C) 2004, 2006 The Linux Foundation and its contributors.
    1 Letterman Drive
    Suite D4700
    San Francisco, CA, 94129

    Everyone is permitted to copy and distribute verbatim copies of this
    license document, but changing it is not allowed.

    Developer's Certificate of Origin 1.1

    By making a contribution to this project, I certify that:

    (a) The contribution was created in whole or in part by me and I have the
    right to submit it under the open source license indicated in the file; or

    (b) The contribution is based upon previous work that, to the best of my
    knowledge, is covered under an appropriate open source license and I have
    the right under that license to submit that work with modifications,
    whether created in whole or in part by me, under the same open source
    license (unless I am permitted to submit under a different license), as
    indicated in the file; or

    (c) The contribution was provided directly to me by some other person who
    certified (a), (b) or (c) and I have not modified it.

    (d) I understand and agree that this project and the contribution are
    public and that a record of the contribution (including all personal
    information I submit with it, including my sign-off) is maintained
    indefinitely and may be redistributed consistent with this project or the
    open source license(s) involved.


To facilitate development and installation of edited version of the code base,
developers are encouraged to install `Virtualenv <https://virtualenv.pypa.io/en/latest/index.html>`_,
which is a tool to create isolated Python environments.  It includes
``pip`` and ``setuptools``, Python packages that can be used to
install TUF and its dependencies. All installation methods of
virtualenv are outlined in the `installation
section <https://virtualenv.pypa.io/en/latest/installation.html>`_,
and instructions for installing locally from source are provided here:
::

    $ curl -O https://pypi.python.org/packages/source/v/virtualenv/virtualenv-15.0.3.tar.gz
    $ tar xvfz virtualenv-15.0.3.tar.gz
    $ cd virtualenv-15.0.3
    $ python virtualenv.py myVE

External Dependencies
=====================

Before installing TUF, a couple of its Python dependencies have non-Python dependencies
of their own that should installed first.  PyCrypto and PyNaCl (third-party dependencies
needed by the repository tools) require Python and FFI (Foreign Function Interface)
development header files. Debian-based distributions can install these header
libraries with apt (Advanced Package Tool.)
::

    $ apt-get install build-essential libssl-dev libffi-dev python-dev

Fedora-based distributions can install these libraries with dnf.
::

    $ dnf install libffi-devel redhat-rpm-config openssl-devel

OS X users can install these header libraries with the `Homebrew <http://brew.sh/>`_ package manager.
::

    $ brew install python
    $ brew install libffi

Development Installation
========================

Installation of minimal, optional, development, and testing requirements
can then be accomplished with one command:
::

    $ pip install -r dev-requirements.txt

Testing
=======

The Update Framework's unit tests can be executed by invoking
`tox <https://testrun.org/tox/>`_. All supported Python versions are
tested, but must already be installed locally.
::

    $ tox

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
