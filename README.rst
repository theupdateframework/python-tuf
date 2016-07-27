A Framework for Securing Software Update Systems
------------------------------------------------

.. image:: https://travis-ci.org/theupdateframework/tuf.svg?branch=develop
   :target: https://travis-ci.org/theupdateframework/tuf

.. image:: https://coveralls.io/repos/theupdateframework/tuf/badge.png?branch=develop
   :target: https://coveralls.io/r/theupdateframework/tuf?branch=develop

.. image:: /docs/images/banner_readme.JPG

The Update Framework (TUF) helps developers to secure new or existing
software update systems, which are often found to be vulnerable to many
known attacks. TUF addresses
this widespread problem by providing a comprehensive, flexible security
framework that developers can integrate with any software update system.
The framework can be easily integrated (or implemented in the native
programming languages of these update systems) due to its concise,
self-contained architecture and specification.

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
   Ruby's RubyGems, and PHP's PEAR.

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
their disposable; especially those attacks that are overlooked by security-conscious
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

-  `The Update Framework Specification <https://github.com/theupdateframework/tuf/tree/develop/docs/tuf-spec.txt?raw=true>`_

TUF Home Page
-------------

The home page for the TUF project can be found at:
https://updateframework.com

Mailing List
------------
Please visit `https://groups.google.com/forum/?fromgroups#!forum/theupdateframework <https://groups.google.com/forum/?fromgroups#!forum/theupdateframework>`_ if you would like to contact the TUF team.  Questions, feedback, and suggestions are welcomed in this low-volume mailing list.

A group feed is available at: https://groups.google.com/forum/feed/theupdateframework/msgs/atom.xml?num=50


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

Installation of Optional Requirements (after minimal install)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The optional ``tuf[tools]`` can be installed by repository maintainers
that need to generate TUF repository files, such as metadata,
cryptographic keys, and signatures. Whereas the minimal install can only
verify ed25519 signatures and is intended for sofware updater clients,
``tuf[tools]`` provides repository maintainers secure ed25519 key and
signature generation with PyNaCl / libsodium.

TUF tools also enable general-purpose cryptography with PyCrypto
and/or PyCA's Cryptography.  Software updaters that want to support
verification of RSASSA-PSS signatures should require their clients
to install ``tuf[tools]``.

Installing extras does not work if minimal install was a wheel (pip <= 1.5.6.)
`https://github.com/pypa/pip/issues/1885 <https://github.com/pypa/pip/issues/1885>`_

::

    $ pip install --no-use-wheel tuf
    $ pip install tuf[tools]

Instructions for Contributors
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Note: Development of TUF occurs on the "develop" branch of this repository.

To facilitate development and installation of edited version of the code base,
developers are encouraged to install `Virtualenv <https://virtualenv.pypa.io/en/latest/index.html>`_,
which is a tool to create isolated Python environments.  It includes
``pip`` and ``setuptools``, Python packages that can be used to
install TUF and its dependencies. All installation methods of
virtualenv are outlined in the `installation
section <https://virtualenv.pypa.io/en/latest/installation.html>`_,
and instructions for installing locally from source are provided here:
::

    $ curl -O https://pypi.python.org/packages/source/v/virtualenv/virtualenv-1.11.6.tar.gz
    $ tar xvfz virtualenv-1.11.6.tar.gz
    $ cd virtualenv-1.11.6
    $ python virtualenv.py myVE


Before installing TUF, a couple of its Python dependencies have non-Python dependencies
of their own that should installed first.  PyCrypto and PyNaCl (third-party dependencies
needed by the repository tools) require Python and FFI (Foreign Function Interface)
development header files. Debian-based distributions can install these header
libraries with apt (Advanced Package Tool.)
::

    $ apt-get install python-dev
    $ apt-get install libffi-dev

Installation of minimal, optional, development, and testing requirements
can then be accomplished with one command:
::

    $ pip install -r dev-requirements.txt

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



Acknowledgements
----------------

This material is based upon work supported by the National Science
Foundation under Grant No. CNS-1345049 and CNS-0959138. Any opinions,
findings, and conclusions or recommendations expressed in this material
are those of the author(s) and do not necessarily reflect the views of
the National Science Foundation.
