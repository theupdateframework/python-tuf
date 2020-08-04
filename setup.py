#!/usr/bin/env python

# Copyright 2013 - 2018, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
<Program Name>
  setup.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  March 2013.

<Copyright>
  See LICENSE-MIT OR LICENSE for licensing information.

<Purpose>
  BUILD SOURCE DISTRIBUTION

  The following shell command generates a TUF source archive that can be
  distributed to other users.  The packaged source is saved to the 'dist'
  folder in the current directory.

  $ python setup.py sdist


  INSTALLATION OPTIONS

  pip - installing and managing Python packages (recommended):

  # Installing from Python Package Index (https://pypi.python.org/pypi).
  $ pip install tuf

  # Installing from local source archive.
  $ pip install <path to archive>

  # Or from the root directory of the unpacked archive.
  $ pip install .

  # Installing optional requirements (i.e., after installing tuf).
  # Support for creation of Ed25519 signatures and support for RSA and ECDSA
  # signatures in general requires optional dependencies:
  $ pip install securesystemslib[crypto,pynacl]


  Alternate installation options:

  Navigate to the root directory of the unpacked archive and
  run one of the following shell commands:

  Install to the global site-packages directory.
  $ python setup.py install

  Install to the user site-packages directory.
  $ python setup.py install --user

  Install to a chosen directory.
  $ python setup.py install --home=<directory>


  Note: The last two installation options may require modification of
  Python's search path (i.e., 'sys.path') or updating an OS environment
  variable.  For example, installing to the user site-packages directory might
  result in the installation of TUF scripts to '~/.local/bin'.  The user may
  then be required to update his $PATH variable:
  $ export PATH=$PATH:~/.local/bin
"""

from setuptools import setup
from setuptools import find_packages


with open('README.md') as file_object:
  long_description = file_object.read()


setup(
  name = 'tuf',
  version = '0.13.0', # If updating version, also update it in tuf/__init__.py
  description = 'A secure updater framework for Python',
  long_description = long_description,
  long_description_content_type='text/markdown',
  author = 'https://www.updateframework.com',
  author_email = 'theupdateframework@googlegroups.com',
  url = 'https://www.updateframework.com',
  keywords = 'update updater secure authentication key compromise revocation',
  classifiers = [
    'Development Status :: 4 - Beta',
    'Intended Audience :: Developers',
    'License :: OSI Approved :: MIT License',
    'License :: OSI Approved :: Apache Software License',
    'Natural Language :: English',
    'Operating System :: POSIX',
    'Operating System :: POSIX :: Linux',
    'Operating System :: MacOS :: MacOS X',
    'Operating System :: Microsoft :: Windows',
    'Programming Language :: Python',
    'Programming Language :: Python :: 2',
    'Programming Language :: Python :: 2.7',
    'Programming Language :: Python :: 3',
    'Programming Language :: Python :: 3.5',
    'Programming Language :: Python :: 3.6',
    'Programming Language :: Python :: 3.7',
    'Programming Language :: Python :: 3.8',
    'Programming Language :: Python :: Implementation :: CPython',
    'Topic :: Security',
    'Topic :: Software Development'
  ],
  project_urls={
    'Source': 'https://github.com/theupdateframework/tuf',
    'Issues': 'https://github.com/theupdateframework/tuf/issues'
  },
  python_requires=">=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, !=3.4.*, <4",
  install_requires = [
    'iso8601>=0.1.12',
    'requests>=2.19.1',
    'six>=1.11.0',
    'securesystemslib>=0.15.0'
  ],
  tests_require = [
    'mock; python_version < "3.3"'
  ],
  packages = find_packages(exclude=['tests']),
  scripts = [
    'tuf/scripts/repo.py',
    'tuf/scripts/client.py'
  ]
)
