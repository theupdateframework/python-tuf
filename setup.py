#! /usr/bin/env python

"""
<Program Name>
  setup.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  March 2013.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  BUILD SOURCE DISTRIBUTION

  The following shell command generates a TUF source archive that can be
  distributed to other users.  The packaged source is saved to the 'dist'
  folder in the current directory.
  
  $ python setup.py sdist



  INSTALLATION OPTIONS
  
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
  variable.
  
  E.g., Installing to the user site-packages directory might result in the
  installation of TUF scripts to '~/.local/bin'.  The user may then be
  required to update his $PATH variable:

  $ export PATH=$PATH:~/.local/bin

  TUF scripts can then be run from any directory.

  $ quickstart.py --project ./project-files
  $ signercli.py --genrsakey ./keystore

"""

from setuptools import setup

setup(
  name='tuf',
  version='0.7.5',
  description='A secure updater framework for Python',
  author='https://www.updateframework.com',
  author_email='info@updateframework.com',
  url='https://www.updateframework.com',
  install_requires=['pycrypto>=2.6'],
  packages=[
    'tuf',
    'tuf.client',
    'tuf.compatibility',
    'tuf.interposition',
    'tuf.pushtools',
    'tuf.pushtools.transfer',
    'tuf.repo',
    'tuf.tests'
  ],
  scripts=[
    'tuf/repo/quickstart.py',
    'tuf/pushtools/push.py',
    'tuf/pushtools/receivetools/receive.py',
    'tuf/repo/signercli.py'
  ]
)
