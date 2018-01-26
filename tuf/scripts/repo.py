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
  $ repo.py --init [/path/to/repo] [--consistent_snapshot, --bare]

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

import os
import sys
import logging
import argparse
import shutil

import tuf
import tuf.log
import tuf.formats
import tuf.repository_tool as repo_tool

import securesystemslib

# See 'log.py' to learn how logging is handled in TUF.
logger = logging.getLogger('tuf.script.repo')

repo_tool.disable_console_log_messages()

PROG_NAME = 'repo.py'
DEFAULT_REPO_PATH = 'repo'
DEFAULT_CLIENT_PATH = 'client'

DEFAULT_ROOT_KEY = 'keystore/root_key'
DEFAULT_TARGETS_KEY = 'keystore/targets_key'
DEFAULT_SNAPSHOT_KEY = 'keystore/snapshot_key'
DEFAULT_TIMESTAMP_KEY = 'keystore/timestamp_key'

DEFAULT_STAGED_DIR = 'metadata.staged'
DEFAULT_METADATA_DIR = 'metadata'

def process_arguments(parsed_arguments):
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
  if not isinstance(parsed_arguments, argparse.Namespace):
    raise tuf.exception.Error('Invalid namespace.')

  else:
    logger.debug('We have a valid argparse Namespace: ' + repr(parsed_arguments))

  # TODO print('parsed_args: ' + repr(parsed_arguments))

  if parsed_arguments.init:
    init_repo(parsed_arguments)

  if parsed_arguments.clean:
    clean_repo(parsed_arguments)


def clean_repo(parsed_arguments):
  repo_dir = os.path.join(parsed_arguments.clean, DEFAULT_REPO_PATH)
  client_dir = os.path.join(parsed_arguments.clean, DEFAULT_CLIENT_PATH)
  shutil.rmtree(repo_dir)
  shutil.rmtree(client_dir)



def init_repo(parsed_arguments):
  """
  Create default repo.  Each top-level role has one key, if
  'parsed_argument.bare' is False (default).
  """
  repository = repo_tool.create_new_repository(DEFAULT_REPO_PATH)

  if not parsed_arguments.bare:
    set_top_level_keys(repository)
    repository.writeall(
        consistent_snapshot=parsed_arguments.consistent_snapshot)

  else:
    repository.write('root', consistent_snapshot=parsed_arguments.consistent_snapshot)
    repository.write('targets')
    repository.write('snapshot')
    repository.write('timestamp')

  # Move staged metadata directory to "live" metadata directory.
  staged_meta_directory = os.path.join(DEFAULT_REPO_PATH, DEFAULT_STAGED_DIR)
  live_meta_directory = os.path.join(DEFAULT_REPO_PATH, DEFAULT_METADATA_DIR)
  shutil.copytree(staged_meta_directory, live_meta_directory)

  # Create the client files.  The client directory contains the required
  # directory structure and metadata files for clients to successfully perform
  # an update.
  repo_tool.create_tuf_client_directory(DEFAULT_REPO_PATH,
      os.path.join(DEFAULT_CLIENT_PATH, DEFAULT_REPO_PATH))



def set_top_level_keys(repository):
  """
  Generate, write, and set the top-level keys.  'repository' is modifed.
  """

  repo_tool.generate_and_write_ecdsa_keypair(DEFAULT_ROOT_KEY, password='pw')
  repo_tool.generate_and_write_ecdsa_keypair(DEFAULT_TARGETS_KEY, password='pw')
  repo_tool.generate_and_write_ecdsa_keypair(DEFAULT_SNAPSHOT_KEY, password='pw')
  repo_tool.generate_and_write_ecdsa_keypair(DEFAULT_TIMESTAMP_KEY, password='pw')

  # Import the public keys.  They are needed so that metadata roles are
  # assigned verification keys, which clients need in order to verify the
  # signatures created by the corresponding private keys.
  root_public = repo_tool.import_ecdsa_publickey_from_file(
      DEFAULT_ROOT_KEY + '.pub')
  targets_public = repo_tool.import_ecdsa_publickey_from_file(
      DEFAULT_TARGETS_KEY + '.pub')
  snapshot_public = repo_tool.import_ecdsa_publickey_from_file(
      DEFAULT_SNAPSHOT_KEY + '.pub')
  timestamp_public = repo_tool.import_ecdsa_publickey_from_file(
      DEFAULT_TIMESTAMP_KEY + '.pub')

  # Import the private keys.  They are needed to generate the signatures
  # included in metadata.
  root_private = repo_tool.import_ecdsa_privatekey_from_file(
      DEFAULT_ROOT_KEY, 'pw')
  targets_private = repo_tool.import_ecdsa_privatekey_from_file(
      DEFAULT_TARGETS_KEY, 'pw')
  snapshot_private = repo_tool.import_ecdsa_privatekey_from_file(
      DEFAULT_SNAPSHOT_KEY, 'pw')
  timestamp_private = repo_tool.import_ecdsa_privatekey_from_file(
      DEFAULT_TIMESTAMP_KEY, 'pw')

  # Add the verification keys to the top-level roles.
  repository.root.add_verification_key(root_public)
  repository.targets.add_verification_key(targets_public)
  repository.snapshot.add_verification_key(snapshot_public)
  repository.timestamp.add_verification_key(timestamp_public)

  # Load the previously imported signing keys for the top-level roles so that
  # valid metadata can be written.
  repository.root.load_signing_key(root_private)
  repository.targets.load_signing_key(targets_private)
  repository.snapshot.load_signing_key(snapshot_private)
  repository.timestamp.load_signing_key(timestamp_private)



def parse_arguments():
  """
  <Purpose>
    Parse the command-line arguments.  Also set the logging level, as specified
    via the --verbose argument (2, by default).

    Example:
      # Create a TUF repository in the current working directory.  The
      # top-level roles are created, each containing one key.
      $ repo.py --init

      $ repo.py --init /path/to/repository --bare --consistent-snapshot --verbose 3

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

  parser.add_argument('-b', '--bare', type=bool, nargs='?', const=True,
      default=False, choices=[True, False],
      help='If initializing a repository, ' + repr(PROG_NAME) + ' should not'
      ' create nor set keys for any of the top-level roles.')

  parser.add_argument('--consistent_snapshot', type=bool, nargs='?',
      choices=[True, False], const=True, default=False,
      help='Enable consistent snapshot.')

  parser.add_argument('-c', '--clean', type=str, nargs='?', const='.',
      help='Erase the repository directory.')

  """
  parser.add_argument('-a', '--add', dest='ADD', type='string', default='',
      help='Add a target file.')

  parser.add_argument('--remove', dest='REMOVE', type='string', default='',
      help='')

  parser.add_argument('gen-key', dest='GEN-KEY', type='string', default='.',
      help='')

  parser.add_argument('--snapshot', dest='SNAPSHOT', type='string', default='.',
      help='')

  parser.add_argument('--timestamp', dest='TIMESTAMP', type='string', default='.',
      help='')

  parser.add_argument('--sign', dest='SIGN', type='string', default='.',
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
  parsed_arguments = parse_arguments()

  # Create or modify the repository depending on the option specified on the
  # command line.  For example,
  # tuf.repository_tool.generate_and_write_ed25519_keypair('/path/to/keystore/root')
  # is called if the user invokes:
  # $ repo.py --gen-key root keystore /path/to/keystore keytype ed25519

  try:
    process_arguments(parsed_arguments)

  except (tuf.exceptions.Error) as e:
    sys.stderr.write('Error: ' + str(e) + '\n')
    sys.exit(1)

  # Successfully created or updated the TUF repository.
  sys.exit(0)
