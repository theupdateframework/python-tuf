#!/usr/bin/env python

# Copyright 2012 - 2018, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
<Program Name>
  client.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  September 2012.

<Copyright>
  See LICENSE-MIT OR LICENSE for licensing information.

<Purpose>
  Provide a basic TUF client that can update all of the metatada and target
  files provided by the user-specified repository mirror.  Updated files are
  saved to the 'targets' directory in the current working directory.  The
  repository mirror is specified by the user through the '--repo' command-
  line option.

  Normally, a software updater integrating TUF will develop their own costum
  client module by importing 'tuf.client.updater', instantiating the required
  object, and calling the desired methods to perform an update.  This basic
  client is provided to users who wish to give TUF a quick test run without the
  hassle of writing client code.  This module can also used by updaters that do
  not need the customization and only require their clients to perform an
  update of all the files provided by their repository mirror(s).

  For software updaters that DO require customization, see the
  'example_client.py' script.  The 'example_client.py' script provides an
  outline of the client code that software updaters may develop and then tailor
  to their specific software updater or package manager.

  Additional tools for clients running legacy applications will also be made
  available.  These tools will allow secure software updates using The Update
  Framework without the need to modify the original application.

<Usage>
  $ client.py --repo http://localhost:8001 <target>
  $ client.py --repo http://localhost:8001 --verbose 3 <target>

<Options>
  --verbose:
    Set the verbosity level of logging messages.  Accepts values 1-5.
    
  Example:
    $ client.py --repo http://localhost:8001 --verbose 3 README.txt

  --repo:
    Set the repository mirror that will be responding to client requests.
    E.g., 'http://localhost:8001'.
    
  Example:
    $ client.py --repo http://localhost:8001 README.txt
"""

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import sys
import argparse
import logging

import tuf
import tuf.client.updater
import tuf.settings
import tuf.log

# See 'log.py' to learn how logging is handled in TUF.
logger = logging.getLogger(__name__)


def update_client(parsed_arguments):
  """
  <Purpose>
    Perform an update of the metadata and target files located at
    'repository_mirror'.  Target files are saved to the 'targets' directory
    in the current working directory.  The current directory must already
    include a 'metadata' directory, which in turn must contain the 'current'
    and 'previous' directories.  At a minimum, these two directories require
    the 'root.json' metadata file.

  <Arguments>
    parsed_arguments:
      An argparse Namespace object, containing the parsed arguments.

  <Exceptions>
    tuf.exceptions.Error, if 'parsed_arguments' is not a Namespace object.

  <Side Effects>
    Connects to a repository mirror and updates the local metadata files and
    any target files.  Obsolete, local targets are also removed.

  <Returns>
    None.
  """

  if not isinstance(parsed_arguments, argparse.Namespace):
    raise tuf.exceptions.Error('Invalid namespace object.')

  else:
    logger.debug('We have a valid argparse Namespace object.')

  # Set the local repositories directory containing all of the metadata files.
  tuf.settings.repositories_directory = '.'

  # Set the repository mirrors.  This dictionary is needed by the Updater
  # class of updater.py.
  repository_mirrors = {'mirror': {'url_prefix': parsed_arguments.repo,
      'metadata_path': 'metadata', 'targets_path': 'targets',
      'confined_target_dirs': ['']}}

  # Create the repository object using the repository name 'repository'
  # and the repository mirrors defined above.
  updater = tuf.client.updater.Updater('tufrepo', repository_mirrors)

  # The local destination directory to save the target files.
  destination_directory = './tuftargets'

  # Refresh the repository's top-level roles...
  updater.refresh(unsafely_update_root_if_necessary=False)

  # ... and store the target information for the target file specified on the
  # command line, and determine which of these targets have been updated.
  target_fileinfo = []
  for target in parsed_arguments.targets:
    target_fileinfo.append(updater.get_one_valid_targetinfo(target))

  updated_targets = updater.updated_targets(target_fileinfo, destination_directory)

  # Retrieve each of these updated targets and save them to the destination
  # directory.
  for target in updated_targets:
    try:
      updater.download_target(target, destination_directory)

    except tuf.exceptions.DownloadError:
      pass

  # Remove any files from the destination directory that are no longer being
  # tracked.
  updater.remove_obsolete_targets(destination_directory)





def parse_arguments():
  """
  <Purpose>
    Parse the command-line options and set the logging level
    as specified by the user through the --verbose option.
    'client' expects the '--repo' to be set by the user.

    Example:
      $ client.py --repo http://localhost:8001 LICENSE

    If the required option is unset, a parser error is printed
    and the scripts exits.

  <Arguments>
    None.

  <Exceptions>
    None.

  <Side Effects>
    Sets the logging level for TUF logging.

  <Returns>
    The parsed_arguments (i.e., a argparse Namespace object).
  """

  parser = argparse.ArgumentParser(
    description='Retrieve file from TUF repository.')

  # Add the options supported by 'basic_client' to the option parser.
  parser.add_argument('-v', '--verbose', type=int, default=2,
      choices=range(0, 6), help='Set the verbosity level of logging messages.'
      ' The lower the setting, the greater the verbosity.  Supported logging'
      ' levels: 0=UNSET, 1=DEBUG, 2=INFO, 3=WARNING, 4=ERROR,'
      ' 5=CRITICAL')

  parser.add_argument('-r', '--repo', type=str, required=True, metavar='<URI>',
      help='Specify the remote repository\'s URI'
      ' (e.g., http://www.example.com:8001/tuf/).  The client retrieves'
      ' updates from the remote repository.')

  parser.add_argument('targets', nargs='+', metavar='<file>', help='Specify'
      ' the target files to retrieve from the specified TUF repository.')

  parsed_arguments = parser.parse_args()


  # Set the logging level.
  if parsed_arguments.verbose == 5:
    tuf.log.set_log_level(logging.CRITICAL)

  elif parsed_arguments.verbose == 4:
    tuf.log.set_log_level(logging.ERROR)

  elif parsed_arguments.verbose == 3:
    tuf.log.set_log_level(logging.WARNING)

  elif parsed_arguments.verbose == 2:
    tuf.log.set_log_level(logging.INFO)

  elif parsed_arguments.verbose == 1:
    tuf.log.set_log_level(logging.DEBUG)

  else:
    tuf.log.set_log_level(logging.NOTSET)

  # Return the repository mirror containing the metadata and target files.
  return parsed_arguments



if __name__ == '__main__':

  # Parse the command-line arguments and set the logging level.
  arguments = parse_arguments()

  # Perform an update of all the files in the 'targets' directory located in
  # the current directory.
  try:
    update_client(arguments)

  except (tuf.exceptions.NoWorkingMirrorError, tuf.exceptions.RepositoryError,
      tuf.exceptions.FormatError, tuf.exceptions.Error) as e:
    sys.stderr.write('Error: ' + str(e) + '\n')
    sys.exit(1)

  # Successfully updated the client's target files.
  sys.exit(0)
