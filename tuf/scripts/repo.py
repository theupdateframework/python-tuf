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
  See LICENSE-MIT OR LICENSE for licensing information.

<Purpose>
  Provide a command-line interface to create and modify TUF repositories.  The
  CLI removes the need to write Python code when creating or modifying
  repositories, which is the case with repository_tool.py and
  developer_tool.py.

<Usage>
  $ repo.py --init [--consistent_snapshot, --bare, --path]
  $ repo.py --add <target> <dir> ... [--path, --recursive]
  $ repo.py --verbose
  $ repo.py --clean [--path]
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
import errno
import getpass

import tuf
import tuf.log
import tuf.formats
import tuf.repository_tool as repo_tool

import securesystemslib

# See 'log.py' to learn how logging is handled in TUF.
logger = logging.getLogger('tuf.script.repo')

repo_tool.disable_console_log_messages()

PROG_NAME = 'repo.py'

REPO_DIR = 'tufrepo'
CLIENT_DIR = 'tufclient'
KEYSTORE_DIR = 'tufkeystore'

ROOT_KEY_NAME = 'root_key'
TARGETS_KEY_NAME = 'targets_key'
SNAPSHOT_KEY_NAME = 'snapshot_key'
TIMESTAMP_KEY_NAME = 'timestamp_key'

STAGED_METADATA_DIR = 'metadata.staged'
METADATA_DIR = 'metadata'



def process_arguments(parsed_arguments):
  """
  <Purpose>
    Create or modify the repository.  Which operation is executed depends
    on 'parsed_arguments'.

  <Arguments>
    parsed_arguments:
      The parsed arguments returned by argparse.parse_args().

  <Exceptions>
    securesystemslib.exceptions.Error, if any of the arguments are
    improperly formatted or if any of the argument could not be processed.

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

  # TODO: Process all of the supported command-line actions.  --init, --clean,
  # --add are currently implemented.
  if parsed_arguments.init:
    init_repo(parsed_arguments)

  if parsed_arguments.clean:
    clean_repo(parsed_arguments)

  if parsed_arguments.add:
    add_targets(parsed_arguments)



def clean_repo(parsed_arguments):
  repo_dir = os.path.join(parsed_arguments.path, REPO_DIR)
  client_dir = os.path.join(parsed_arguments.path, CLIENT_DIR)
  keystore_dir = os.path.join(parsed_arguments.path, KEYSTORE_DIR)

  shutil.rmtree(repo_dir, ignore_errors=True)
  shutil.rmtree(client_dir, ignore_errors=True)
  shutil.rmtree(keystore_dir, ignore_errors=True)



def write_to_live_repo():
  staged_meta_directory = os.path.join(
      parsed_arguments.path, REPO_DIR, STAGED_METADATA_DIR)
  live_meta_directory = os.path.join(
      parsed_arguments.path, REPO_DIR, METADATA_DIR)

  shutil.rmtree(live_meta_directory, ignore_errors=True)
  shutil.copytree(staged_meta_directory, live_meta_directory)



def add_target_to_repo(target_path, repo_targets_path, repository):
  """
  (1) Copy 'target_path' to 'repo_targets_path'.
  (2) Add 'target_path' to Targets metadata of 'repository'.
  """

  if not os.path.exists(target_path):
    print(repr(target_path) + ' does not exist.  Skipping.')

  else:
    securesystemslib.util.ensure_parent_dir(
        os.path.join(repo_targets_path, target_path))
    shutil.copy(target_path, os.path.join(repo_targets_path, target_path))
    repository.targets.add_target(
        os.path.join(repo_targets_path, target_path))



def add_targets(parsed_arguments):
  target_paths = os.path.join(parsed_arguments.add)

  repo_targets_path = os.path.join(parsed_arguments.path, REPO_DIR, 'targets')
  repository = repo_tool.load_repository(
      os.path.join(parsed_arguments.path, REPO_DIR))

  # Copy the target files in --path to the repo directory, and
  # add them to Targets metadata.  Make sure to also copy & add files
  # in directories (and subdirectories, if --recursive is True).
  for target_path in target_paths:
    if os.path.isdir(target_path):
      for sub_target_path in repository.get_filepaths_in_directory(
          target_path, parsed_arguments.recursive):
        add_target_to_repo(sub_target_path, repo_targets_path, repository)

    else:
      add_target_to_repo(target_path, repo_targets_path, repository)

  # Examples of how the --pw command-line option is interpreted:
  # repo.py --init': parsed_arguments.pw = 'pw'
  # repo.py --init --pw my_password: parsed_arguments.pw = 'my_password'
  # repo.py --init --pw: The user is prompted for a password, as follows:
  if not parsed_arguments.pw:
    parsed_arguments.pw = securesystemslib.interface.get_password(
        prompt='Enter a password for the top-level role keys: ', confirm=True)

  # Load the top-level, non-root, keys to make a new release.
  targets_private = repo_tool.import_ecdsa_privatekey_from_file(
      os.path.join(parsed_arguments.path, KEYSTORE_DIR, TARGETS_KEY_NAME),
      parsed_arguments.pw)
  snapshot_private = repo_tool.import_ecdsa_privatekey_from_file(
      os.path.join(parsed_arguments.path, KEYSTORE_DIR, SNAPSHOT_KEY_NAME),
      parsed_arguments.pw)
  timestamp_private = repo_tool.import_ecdsa_privatekey_from_file(
      os.path.join(parsed_arguments.path, KEYSTORE_DIR,
      TIMESTAMP_KEY_NAME), parsed_arguments.pw)

  repository.targets.load_signing_key(targets_private)
  repository.snapshot.load_signing_key(snapshot_private)
  repository.timestamp.load_signing_key(timestamp_private)

  repository.writeall()

  # Move staged metadata directory to "live" metadata directory.
  write_to_live_repo()



def init_repo(parsed_arguments):
  """
  Create a repo at the specified location in --path (the current working
  directory, by default).  Each top-level role has one key, if --bare' is False
  (default).
  """

  repo_path = os.path.join(parsed_arguments.path, REPO_DIR)
  repository = repo_tool.create_new_repository(repo_path)

  if not parsed_arguments.bare:
    set_top_level_keys(repository)
    repository.writeall(
        consistent_snapshot=parsed_arguments.consistent_snapshot)

  else:
    repository.write(
        'root', consistent_snapshot=parsed_arguments.consistent_snapshot)
    repository.write('targets')
    repository.write('snapshot')
    repository.write('timestamp')

  write_to_live_repo()

  # Create the client files.  The client directory contains the required
  # directory structure and metadata files for clients to successfully perform
  # an update.
  repo_tool.create_tuf_client_directory(
      os.path.join(parsed_arguments.path, REPO_DIR),
      os.path.join(parsed_arguments.path, CLIENT_DIR, REPO_DIR))



def set_top_level_keys(repository):
  """
  Generate, write, and set the top-level keys.  'repository' is modified.
  """

  # Examples of how the --pw command-line option is interpreted:
  # repo.py --init': parsed_arguments.pw = 'pw'
  # repo.py --init --pw my_pw: parsed_arguments.pw = 'my_pw'
  # repo.py --init --pw: The user is prompted for a password, here.
  if not parsed_arguments.pw:
    parsed_arguments.pw = securesystemslib.interface.get_password(
        prompt='Enter a password for the top-level role keys: ', confirm=True)

  repo_tool.generate_and_write_ecdsa_keypair(
      os.path.join(parsed_arguments.path, KEYSTORE_DIR,
      ROOT_KEY_NAME), password=parsed_arguments.pw)
  repo_tool.generate_and_write_ecdsa_keypair(
      os.path.join(parsed_arguments.path, KEYSTORE_DIR,
      TARGETS_KEY_NAME), password=parsed_arguments.pw)
  repo_tool.generate_and_write_ecdsa_keypair(
      os.path.join(parsed_arguments.path, KEYSTORE_DIR,
      SNAPSHOT_KEY_NAME), password=parsed_arguments.pw)
  repo_tool.generate_and_write_ecdsa_keypair(
      os.path.join(parsed_arguments.path, KEYSTORE_DIR,
      TIMESTAMP_KEY_NAME), password=parsed_arguments.pw)

  # Import the public keys.  They are needed so that metadata roles are
  # assigned verification keys, which clients need in order to verify the
  # signatures created by the corresponding private keys.
  root_public = repo_tool.import_ecdsa_publickey_from_file(
      os.path.join(parsed_arguments.path, KEYSTORE_DIR,
      ROOT_KEY_NAME) + '.pub')
  targets_public = repo_tool.import_ecdsa_publickey_from_file(
      os.path.join(parsed_arguments.path, KEYSTORE_DIR,
      TARGETS_KEY_NAME) + '.pub')
  snapshot_public = repo_tool.import_ecdsa_publickey_from_file(
      os.path.join(parsed_arguments.path, KEYSTORE_DIR,
      SNAPSHOT_KEY_NAME) + '.pub')
  timestamp_public = repo_tool.import_ecdsa_publickey_from_file(
      os.path.join(parsed_arguments.path, KEYSTORE_DIR,
      TIMESTAMP_KEY_NAME) + '.pub')

  # Import the private keys.  They are needed to generate the signatures
  # included in metadata.
  root_private = repo_tool.import_ecdsa_privatekey_from_file(
      os.path.join(parsed_arguments.path, KEYSTORE_DIR,
      ROOT_KEY_NAME), parsed_arguments.pw)
  targets_private = repo_tool.import_ecdsa_privatekey_from_file(
      os.path.join(parsed_arguments.path, KEYSTORE_DIR,
      TARGETS_KEY_NAME), parsed_arguments.pw)
  snapshot_private = repo_tool.import_ecdsa_privatekey_from_file(
      os.path.join(parsed_arguments.path, KEYSTORE_DIR,
      SNAPSHOT_KEY_NAME), parsed_arguments.pw)
  timestamp_private = repo_tool.import_ecdsa_privatekey_from_file(
      os.path.join(parsed_arguments.path, KEYSTORE_DIR,
      TIMESTAMP_KEY_NAME), parsed_arguments.pw)

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

      $ repo.py --init --bare --consistent-snapshot --verbose 3

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

  parser.add_argument('-p', '--path', nargs='?', default='.',
      help='Specify a repository path.  If used with --init, the initialized'
      ' repository is saved to the specified path.')

  parser.add_argument('-b', '--bare', type=bool, nargs='?', const=True,
      default=False, choices=[True, False],
      help='If initializing a repository, ' + repr(PROG_NAME) + ' should not'
      ' create nor set keys for any of the top-level roles.')

  parser.add_argument('--consistent_snapshot', type=bool, nargs='?',
      choices=[True, False], const=True, default=False,
      help='Enable consistent snapshot.')

  parser.add_argument('-c', '--clean', type=str, nargs='?', const='.',
      help='Erase the repository directory.')

  parser.add_argument('-a', '--add', type=str, nargs='+',
      help='Add one or more target files.')

  parser.add_argument('-r', '--recursive', type=bool, nargs='?',
      choices=[True, False], const=True, default=False,
      help='Specify whether a directory should be processed recursively.')

  parser.add_argument('--role', nargs='?', type=str, const='targets',
      default='targets', help='Specify a role.')

  parser.add_argument('--pw', nargs='?', default='pw',
      help='Specify a password for the top-level key files.')

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
  # command line.  For example, the following adds the 'foo.bar.gz' to the
  # default repository and updates the relevant metadata (i.e., Targets,
  # Snapshot, and Timestamp metadata are updated):
  # $ repo.py --add foo.bar.gz

  try:
    process_arguments(parsed_arguments)

  except (tuf.exceptions.Error) as e:
    sys.stderr.write('Error: ' + str(e) + '\n')
    sys.exit(1)

  # Successfully created or updated the TUF repository.
  sys.exit(0)
