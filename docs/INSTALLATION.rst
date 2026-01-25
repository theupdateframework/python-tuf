Installation
============

All versions of ``python-tuf`` can be installed from
`PyPI <https://pypi.org/project/tuf/>`_ with
`pip <https://pip.pypa.io/en/stable/>`_.

::

   python3 -m pip install tuf

By default tuf is installed as pure python package with limited cryptographic
abilities. See `Install with full cryptographic abilities`_ for more options.


Install with full cryptographic abilities
-----------------------------------------

Default installation supports signature verification only, using a pure Python
*ed25519* implementation. While this allows to operate a *basic client* on
almost any computing device, you will need additional cryptographic abilities
for *repository* code, i.e. key and signature generation, additional
algorithms, and more performant backends. Opt-in is available via
``securesystemslib``.

.. note::

   Please consult with underlying crypto backend installation docs. e.g.
   `cryptography <https://cryptography.io/en/latest/installation/>`_
   for possible system dependencies.

::

   python3 -m pip securesystemslib[crypto] tuf


Install for development
-----------------------

To install tuf in editable mode together with development dependencies,
`clone <https://docs.github.com/en/repositories/creating-and-managing-repositories/cloning-a-repository>`_ the
`python-tuf repository <https://github.com/theupdateframework/python-tuf>`_
from GitHub, change into the project root directory, and install with pip
(using `venv <https://docs.python.org/3/library/venv.html>`_ is recommended).

.. note::

   Development installation will `Install with full cryptographic abilities`_.
   Please check above for possible system dependencies.

::

   python3 -m pip install -r requirements/dev.txt


Bootstrap root metadata
-----------------------

The initial trusted root metadata (``root.json``) is the trust anchor for all
subsequent metadata verification. Applications should deploy a trusted root
with the application and provide it to :class:`tuf.ngclient.Updater`.

Recommended storage locations for bootstrap root metadata include:

* a system-wide read-only path (e.g. ``/usr/share/your-app/root.json``)
* an application bundle with appropriate permissions
* a read-only mounted volume in containerized deployments

Not recommended:

* ``metadata_dir`` (the metadata cache) since it is writable by design
* user-writable install paths (e.g. a user site-packages directory)
* any location writable by the account running the updater

Example::

   from tuf.ngclient import Updater

   with open("/usr/share/your-app/root.json", "rb") as f:
       bootstrap = f.read()

   updater = Updater(
       metadata_dir="/var/lib/your-app/tuf/metadata",
       metadata_base_url="https://example.com/metadata/",
       bootstrap=bootstrap,
   )


Verify release signatures
-------------------------

Releases on PyPI are signed with a maintainer key using
`gpg <https://gnupg.org/>`_  (see
`MAINTAINERS.txt <https://github.com/theupdateframework/python-tuf/blob/develop/docs/MAINTAINERS.txt>`_
for key fingerprints). Signatures can be downloaded from the
`GitHub release <https://github.com/theupdateframework/python-tuf/releases>`_
page (look for *\*.asc* files in the *Assets* section).

Below code shows how to verify the signature of a
`built <https://packaging.python.org/en/latest/glossary/#term-Built-Distribution>`_ distribution,
signed by the maintainer *Lukas Pühringer*. It works
alike for `source  <https://packaging.python.org/en/latest/glossary/#term-Source-Distribution-or-sdist>`_ distributions.

::

   # Get wheel from PyPI and signature from GitHub
   python3 -m pip download --no-deps tuf==0.20.0
   wget https://github.com/theupdateframework/python-tuf/releases/download/v0.20.0/tuf-0.20.0-py3-none-any.whl.asc

   # Get public key, compare fingerprint in MAINTAINERS.txt, and verify with gpg
   gpg --recv-keys 89A2AD3C07D962E8
   gpg --verify tuf-0.20.0-py3-none-any.whl.asc

   # Output:
   # gpg: assuming signed data in 'tuf-0.20.0-py3-none-any.whl'
   # gpg: Signature made Thu Dec 16 09:21:38 2021 CET
   # gpg:                using RSA key 8BA69B87D43BE294F23E812089A2AD3C07D962E8
   # gpg: Good signature from "Lukas Pühringer <lukas.puehringer@nyu.edu>" [ultimate]
