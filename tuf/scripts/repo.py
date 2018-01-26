#!/usr/bin/env python

# Copyright 2018, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
<Program Name>
  repo.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  January 2018.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Provide a command-line interface to create and modify TUF repositories.  The
  CLI removes the need to write Python code when creating or modifying
  repositories, which is the case with repository_tool.py and
  developer_tool.py.

<Usage>
  $ repo.py --init [/path/to/repo] [--consistent_snapshot=false, bare=False]

  # Not implemented yet:
  $ repo.py gen-key <role> --keytype <keytype> --keystore </path/to/keystore> [--expires=<days>]
  $ repo add <target> --repo </path/to/repo>
  $ repo remove <target> --repo </path/to/repo>
  $ repo snapshot </path/to/repo>
  $ repo timestamp </path/to/repo>
  $ repo sign <role> --repo </path/to/repo>
  $ repo commit </path/to/repo>
  $ repo regenerate </path/to/repo>
  $ repo clean --repo

<Arguments>
  --init, -i:
    Initialize a TUF repository.  By default, repo.py creates one key per
    role, and consistent snapshots is disabled.

  --verbose, -v:
    Set the verbosity level of logging messages.  Accepts values 1-5.

  # Not implemented yet:
  gen-key
  add
  remove
  snapshot
  timestamp
  sign
  commit
  regenerate
  clean
"""

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import sys
import logging
import argparse

import tuf
import tuf.log
import tuf.formats
from tuf.repository_tool import *

import securesystemslib

# See 'log.py' to learn how logging is handled in TUF.
logger = logging.getLogger('tuf.script.repo')

PROG_NAME = 'repo.py'


def process_repository(parsed_args):
  """
  <Purpose>
    Create or modify the repository.

  <Arguments>
    parsed_args:

  <Exceptions>
    securesystemslib.exceptions.FormatError, if any of the arugments are
    improperly formatted.

  <Side Effects>
    None.

  <Returns>
    None.
  """

  # Do we have a valid argparse Namespace?
  if not isinstance(parsed_args, argparse.Namespace):
    raise tuf.exception.Error('Invalid namespace.')

  else:
    logger.debug('We have a valid argparse Namespace: ' + repr(parsed_args))

  print('parsed_args: ' + repr(parsed_args))


def parse_arguments():
  """
  <Purpose>
    Parse the command-line arguments.  Set the logging level as specified via
    the --verbose argument (2, by default).

    Example:
      # Create a TUF repository in the current working directory.  The
      # top-level roles are created, each containing one key.
      $ repo.py --init

      $ repo.py --init /path/to/repository --bare True --consistent-snapshot False --verbose 3

    If a required argument is unset, a parser error is printed and the script
    exits.

  <Arguments>
    None.

  <Exceptions>
    None.

  <Side Effects>
    Sets the logging level for TUF logging.

  <Returns>
    A tuple ('options.REPOSITORY_PATH', command, command_arguments).  'command'
    'command_arguments' correspond to a repository tool fuction.
  """

  parser = argparse.ArgumentParser(
      description='Create or modify a TUF repository.')

  # Add the parser arguments supported by PROG_NAME.
  parser.add_argument('-v', '--verbose', type=int, default=2,
      choices=range(0, 6), help='Set the verbosity level of logging messages.'
      ' The lower the setting, the greater the verbosity.  Supported logging'
      ' levels: 0=UNSET, 1=DEBUG, 2=INFO, 3=WARNING, 4=ERROR,'
      ' 5=CRITICAL')

  parser.add_argument('-i', '--init', nargs='?', const='.',
      help='Create a repository.')

  parser.add_argument('--consistent_snapshots', type=bool, nargs='?',
      choices=[True, False], const=True, default=False,
      help='Enable consistent snapshots.')

  parser.add_argument('-b', '--bare', type=bool, nargs='?', const=True,
      default=False, choices=[True, False],
      help='If initializing a repository, ' + repr(PROG_NAME) + ' should not'
      ' create nor set keys for any of the top-level roles.')

  """
  parser.add_argument('gen-key', dest='GEN-KEY', type='string', default='.',
      help='')

  parser.add_argument('keytype', dest='KEYTYPE', type='string', default='ed25519',
      help='')

  parser.add_argument('expires', dest='EXPIRES', type=int, default=365,
      help='')

  parser.add_argument('--add', dest='ADD', type='string', default='',
      help='')

  parser.add_argument('--remove', dest='REMOVE', type='string', default='',
      help='')

  parser.add_argument('--snapshot', dest='SNAPSHOT', type='string', default='.',
      help='')

  parser.add_argument('--timestamp', dest='TIMESTAMP', type='string', default='.',
      help='')

  parser.add_argument('--sign', dest='SIGN', type='string', default='.',
      help='')

  parser.add_argument('--commit', dest='COMMIT', type='string', default='.',
      help='')

  parser.add_argument('--regenerate', dest='REGENERATE', type='string', default='.',
      help='')

  parser.add_argument('--clean', dest='CLEAN', type='string', default='.',
      help='')
  """

  parsed_args = parser.parse_args()

  # Set the logging level.
  if parsed_args.verbose == 5:
    tuf.log.set_log_level(logging.CRITICAL)

  elif parsed_args.verbose == 4:
    tuf.log.set_log_level(logging.ERROR)

  elif parsed_args.verbose == 3:
    tuf.log.set_log_level(logging.WARNING)

  elif parsed_args.verbose == 2:
    tuf.log.set_log_level(logging.INFO)

  elif parsed_args.verbose == 1:
    tuf.log.set_log_level(logging.DEBUG)

  else:
    tuf.log.set_log_level(logging.NOTSET)

  return parsed_args



if __name__ == '__main__':

  # Parse the arguments and set the logging level.
  parsed_args = parse_arguments()

  # Create or modify the repository depending on the option specified on the
  # command line.  For example,
  # tuf.repository_tool.generate_and_write_ed25519_keypair('/path/to/keystore/root')
  # is called if the user invokes:
  # $ repo.py --gen-key root keystore /path/to/keystore keytype ed25519

  try:
    process_repository(parsed_args)

  except (tuf.exceptions.Error) as e:
    sys.stderr.write('Error: ' + str(e) + '\n')
    sys.exit(1)

  # Successfully created or updated the TUF repository.
  sys.exit(0)
