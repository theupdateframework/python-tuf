Installation
============

*pip* is the recommended installer for installing and managing Python packages.
The project can be installed either locally or from the Python Package Index.
All `TUF releases
<https://github.com/theupdateframework/tuf/releases>`_ are cryptographically
signed, with GPG signatures available on both GitHub and `PyPI
<https://pypi.python.org/pypi/tuf/>`_.  PGP key information for our maintainers
is available on our `website
<https://theupdateframework.github.io/people.html>`_, on major keyservers,
and on the `maintainers page
<https://github.com/theupdateframework/tuf/blob/develop/docs/MAINTAINERS.txt>`_.

The latest release and its packaging information, such as who signed the
release and their PGP fingerprint, can also be found on our 1-year `roadmap
<ROADMAP.md>`_.



Release Verification
--------------------

Assuming you trust `the maintainer's PGP key <MAINTAINERS.txt>`_, the detached
ASC signature can be downloaded and verified.  For example:

::

   $ gpg --verify securesystemslib-0.10.8.tar.gz.asc
   gpg: assuming signed data in 'securesystemslib-0.10.8.tar.gz'
   gpg: Signature made Wed Nov  8 15:21:47 2017 EST
   gpg:                using RSA key 3E87BB339378BC7B3DD0E5B25DEE9B97B0E2289A
   gpg: Good signature from "Vladimir Diaz (Vlad) <vladimir.v.diaz@gmail.com>" [ultimate]



Simple Installation
-------------------

If you are only using ed25519-based cryptography, you can employ a pure-Python
installation, done simply with one of the following commands:

Installing from Python Package Index (https://pypi.python.org/pypi).
(Note: Please use "pip install --no-use-wheel tuf" if your version
of pip <= 1.5.6)
::
    $ pip install tuf


**Alternatively**, if you wish to install from a GitHub release you've already
downloaded, or a package you obtained in another way, you can instead:

Install from a local source archive:
::
    $ pip install <path to archive>

Or install from the root directory of the unpacked archive:
::
    $ pip install .



Install with More Cryptographic Flexibility
-------------------------------------------

By default, C extensions are not installed and only Ed25519 signatures can
be verified, in pure Python.  To fully support RSA, Ed25519, ECDSA, and
other crypto, you must install the extra dependencies declared by
securesystemslib.  **Note**: that may require non-Python dependencies, so if
you encounter an error attempting this pip command, see
`more instructions below <#non-python-dependencies>`_).
::
    $ pip install securesystemslib[crypto,pynacl] tuf



Non-Python Dependencies
-----------------------

If you encounter errors during installation, you may be missing
certain system libraries.

For example, PyNaCl and Cryptography -- two libraries used in the full
installation to support certain cryptographic functions -- may require FFI
(Foreign Function Interface) development header files.

Debian-based distributions can install the necessary header libraries with apt
(Advanced Package Tool.)
::
    $ apt-get install build-essential libssl-dev libffi-dev python-dev

Fedora-based distributions can instead install these libraries with dnf.
::
    $ dnf install libffi-devel redhat-rpm-config openssl-devel

OS X users can install these header libraries with the `Homebrew <https://brew.sh/>`_
package manager, among other options.
::
    $ brew install python
    $ brew install libffi
