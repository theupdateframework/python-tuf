#!/usr/bin/env python

"""
<Program Name>
  test_updater.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  January 26, 2017

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Provide a program that can be used for conformance testing with the
  specification.  The program's behavior is governed by the design requisites
  defined in TAP 7 (Conformance testing), available at
  https://github.com/theupdateframework/taps.  This program is expected
  to be executed by the official conformance tester.

<Usage>
  $ python test_updater.py --file foo.tgz --repo http://localhost:8001
    --metadata tmp/metadata --targets tmp/targets --verbose 3

  This command makes a request for foo.tgz to --repo, and saves downloaded
  metadata and foo.tgz to --metadata and --targets, respectively.

<Options>
  --file:
    The target file to update from the repository mirror.

  --repo:
    Set the repository mirror that will be responding to client requests.
    E.g., 'http://locahost:8001'.

  --metadata:
    The location where downloaded metadata is stored.

  --targets:
    The location where downloaded targets are stored.

  --verbose:
    Set the verbosity level of logging messages.  Accepts values 1-5.
"""

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import sys
import optparse
import logging
import os

import tuf
import tuf.client.updater
import tuf.settings
import tuf.log

import six
import securesystemslib

# See 'log.py' to learn how logging is handled in TUF.
logger = logging.getLogger('tuf.test_updater')


def update_client(target, repository_mirror, metadata_directory, targets_directory):
  """
  <Purpose>
    Perform an update of the metadata and target files located at
    'repository_mirror'.  Target files are saved to the 'targets' directory
    in the current working directory.  The current directory must already
    include a 'metadata' directory, which in turn must contain the 'current'
    and 'previous' directories.  At a minimum, these two directories require
    the 'root.json' metadata file.

  <Arguments>
    target:
      The target file that is updated from the repository mirror.

    repository_mirror:
      The URL to the repository mirror hosting the metadata and target
      files.  E.g., 'http://localhost:8001'

    metadata_directory:
      The local directory where downloaded metadata is stored.

    targets_directory:
      The local directory where the downloaded target file is stored.

  <Exceptions>
    tuf.exceptions.RepositoryError, if any of the arguments are improperly
    formatted.

  <Side Effects>
    Connects to a repository mirror and updates the target file and any
    metadata files.

  <Returns>
    None.
  """

  REPOSITORY_MIRROR = 'http://localhost:8001'

  # Do the arguments have the correct format?
  try:
    securesystemslib.formats.RELPATH_SCHEMA.check_match(target)
    securesystemslib.formats.URL_SCHEMA.check_match(repository_mirror)
    securesystemslib.formats.RELPATH_SCHEMA.check_match(metadata_directory)
    securesystemslib.formats.RELPATH_SCHEMA.check_match(targets_directory)

  except tuf.securesystemslib.exceptions.FormatError:
    raise tuf.exceptions.RepositoryError('The arguments are improperly'
      ' formatted, which prevents initialization of the updater.')

  # Set the local repository directory containing all of the metadata files.
  tuf.settings.repository_directory = metadata_directory

  # Set the repository mirrors.  This dictionary is needed by the Updater
  # class of updater.py.
  repository_mirrors = {'mirror': {'url_prefix': REPOSITORY_MIRROR,
                                  'metadata_path': 'metadata',
                                  'targets_path': 'targets',
                                  'confined_target_dirs': ['']}}

  # Create the repository object using the repository name 'repository'
  # and the repository mirrors defined above.
  updater = tuf.client.updater.Updater('repository', repository_mirrors)

  # The local destination directory to save the target files.
  destination_directory = targets_directory

  # Refresh the repository's top-level roles, store the target information for
  # all the targets tracked, and determine which of these targets have been
  # updated.
  updater.refresh(unsafely_update_root_if_necessary=False)

  # Retrieve the target info of 'target', which contains its length, hash, etc.
  file_targetinfo = updater.get_one_valid_targetinfo(target)
  updated_targets = updater.updated_targets([file_targetinfo], destination_directory)

  # Download each of these updated targets and save them locally.
  updater.download_target(file_targetinfo, destination_directory)





def parse_options():
  """
  <Purpose>
    Parse the command-line options and set the logging level as specified by
    the user through the --verbose option.

    'test_updater.py' expects the --repo, --metadata, and --targets
    command-line option to be set by the user.  --verbose is optional.

    Example:
      $ python test_updater.py foo.tgz --repo http://localhost:8001
        --metadata tmp/metadata --targets tmp/targes

    If the required option is unset, a parser error is printed and the scripts
    exits.

  <Arguments>
    None.

  <Exceptions>
    None.

  <Side Effects>
    Sets the logging level for TUF logging.

  <Returns>
    A (options.TARGET_FILE, options.REPOSITORY_MIRROR,
    options.METADATA_DIRECTORY, options.TARGETS_DIRECTORY) tuple.
  """

  parser = optparse.OptionParser()

  # Add the options supported by 'test_updater' to the option parser.
  parser.add_option('--file', dest='TARGET_FILE', type='string',
                    help='Specify the target file to request'
                    ' from the repository mirror.')

  parser.add_option('--repo', dest='REPOSITORY_MIRROR', type='string',
                    help='Specify the repository mirror\'s URL prefix '
                    '(e.g., http://www.example.com:8001/tuf/).'
                    ' The client will download the target file from this mirror.')

  parser.add_option('--metadata', dest='METADATA_DIRECTORY', type='string',
                    help='Specify the local metadata directory'
                    ' to save metadata.')

  parser.add_option('--targets', dest='TARGETS_DIRECTORY', type='string',
                    help='Specify the local targets directory'
                    ' to save the target file.')

  parser.add_option('--verbose', dest='VERBOSE', type=int, default=2,
                    help='Set the verbosity level of logging messages.'
                    '  The lower the setting, the greater the verbosity.')

  options, args = parser.parse_args()

  # Set the logging level.
  if options.VERBOSE == 5:
    tuf.log.set_log_level(logging.CRITICAL)

  elif options.VERBOSE == 4:
    tuf.log.set_log_level(logging.ERROR)

  elif options.VERBOSE == 3:
    tuf.log.set_log_level(logging.WARNING)

  elif options.VERBOSE == 2:
    tuf.log.set_log_level(logging.INFO)

  elif options.VERBOSE == 1:
    tuf.log.set_log_level(logging.DEBUG)

  else:
    tuf.log.set_log_level(logging.NOTSET)

  # Ensure the --file, --repo, --metadata, and --targets options were set by
  # the user.
  if options.TARGET_FILE is None:
    parser.error('"--file" must be set on the command-line.')

  if options.REPOSITORY_MIRROR is None:
    parser.error('"--repo" must be set on the command-line.')

  if options.METADATA_DIRECTORY is None:
    parser.error('"--metadata" must be set on the command-line.')

  if options.TARGETS_DIRECTORY is None:
    parser.error('"--targets" must be set on the command-line.')

  # Return the file, repository mirror, and metadata and targets directories.
  return (options.TARGET_FILE, options.REPOSITORY_MIRROR, options.METADATA_DIRECTORY, options.TARGETS_DIRECTORY)



if __name__ == '__main__':

  # Parse the options and set the logging level.
  (target, repository_mirror, metadata_directory, targets_directory) = parse_options()

  # Return codes for test_updater.py.  This list is not yet finalized.
  SUCCESS = 0
  UNSIGNED_METADATA_ERROR = 1
  UNKNOWN_TARGET_ERROR = 2
  MALICIOUS_TARGET_ERROR = 3
  ROLLBACK_ERROR = 4
  SLOW_RETRIEVAL_ERROR = 5
  ENDLESS_DATA_ERROR = 6
  REPOSITORY_ERROR = 7
  UNKNOWN_ERROR = 8

  # Perform an update from 'repository_mirror' for 'target'.  The updated
  # target is saved to 'targets_directory', and refreshed metadata to
  # 'metadata_directory'.  Any exceptions raised are caught here, and the
  # program ends with an appropriate return code.
  try:
    update_client(target, repository_mirror, metadata_directory, targets_directory)

  except (tuf.exceptions.NoWorkingMirrorError) as exception:

    # 'exception.mirror_errors' should only contain one (key, value) dict
    # entry, since only a single mirror is queried.
    for mirror_url, mirror_error in six.iteritems(exception.mirror_errors):
      sys.stderr.write('Error: ' + str(mirror_error) + '\n')

      if isinstance(mirror_error, tuf.exceptions.SlowRetrievalError):
        sys.exit(SLOW_RETRIEVAL_ERROR)

      elif isinstance(mirror_error, tuf.exceptions.RepositoryError):
        sys.exit(REPOSITORY_ERROR)

      else:
        sys.exit(UNKNOWN_ERROR)

  # Successfully updated the target file.
  sys.exit(SUCESS)
