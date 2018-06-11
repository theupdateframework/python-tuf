Installation
------------

*pip* is the recommended installer.  The project can be installed either
locally or from the Python Package Index.  All `TUF releases
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

Assuming you trust the maintainer's PGP key, the detached ASC signature
can be downloaded and verified.  For example:

::

   $ gpg --verify securesystemslib-0.10.8.tar.gz.asc
   gpg: assuming signed data in 'securesystemslib-0.10.8.tar.gz'
   gpg: Signature made Wed Nov  8 15:21:47 2017 EST
   gpg:                using RSA key 3E87BB339378BC7B3DD0E5B25DEE9B97B0E2289A
   gpg: Good signature from "Vladimir Diaz (Vlad) <vladimir.v.diaz@gmail.com>" [ultimate]

Installation instructions:

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

    By default, C extensions are not installed and only Ed25519 signatures can
    be verified in pure Python.  To fully support RSA, Ed25519, ECDSA, and
    other crypto, you must install the extra dependencies declared by
    securesystemslib:
    $ pip install securesystemslib[crypto,pynacl]
