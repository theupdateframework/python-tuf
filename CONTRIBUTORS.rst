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
