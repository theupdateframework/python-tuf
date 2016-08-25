#!/usr/bin/env python

"""
<Program Name>
  tuf.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  August 2016.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Provide a command line interface to the repository tool
  (i.e., tuf.repository_tool.py).  This CLI removes the need to write code,
  which is required by the repository and developer tools.

<Usage>
  $ tuf.py --init </path/to/repo> [--consistent-snapshot=false]
  $ tuf.py --gen-key <role> --keytype <keytype> --keystore </path/to/keystore> [--expires=<days>]
  $ tuf.py --add <target> --repo <path/to/repo> 
  $ tuf.py --remove <target> --repo <path/to/repo>
  $ tuf.py --snapshot <path/to/repo>
  $ tuf.py --timestamp <path/to/repo>
  $ tuf.py --sign <role> --repo <path/to/repo>
  $ tuf.py --commit <path/to/repo>
  $ tuf.py --regenerate <path/to/repo>
  $ tuf.py --clean --repo

<Options>
  --init
  
  --gen-key

  --add

  --remove

  --snapshot

  --timestamp

  --sign

  --commit

  --regenerate

  --clean

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

import tuf
import tuf.log
import tuf.formats

from tuf.repository_tool import *

# See 'log.py' to learn how logging is handled in TUF.
logger = logging.getLogger('tuf.tuf')


def update_repository(repository_path, command, command_arguments):
  """
  <Purpose>
    Perform an update of the metadata and target files located at
    'repository_mirror'.  Target files are saved to the 'targets' directory
    in the current working directory.  The current directory must already
    include a 'metadata' directory, which in turn must contain the 'current'
    and 'previous' directories.  At a minimum, these two directories require
    the 'root.json' metadata file.

  <Arguments>
    repository_path:
      The URL to the repository mirror hosting the metadata and target
      files.  E.g., 'http://localhost:8001'

    command:

    command_arguments:


  <Exceptions>
    tuf.FormatError, if any of the arugments are improperly formatted.

  <Side Effects>
    The TUF repository at 'repository_path' is either created or modified. 

  <Returns>
    None.
  """

  # Do the arguments have the correct format?
  tuf.formats.URL_SCHEMA.check_match(repository_path)
  tuf.formats.NAME_SCHEMA.check_match(command)
  tuf.formats.NAMES_SCHEMA.check_match(command_arguments)
  
  # Set the local repository directory containing all of the metadata files.
  tuf.conf.repository_directory = repository_path 



def parse_options():
  """
  <Purpose>
    Parse the command-line options and set the logging level
    as specified by the user through the --verbose option.
    The 'tuf' command expects the repository path to be set by the user.

    Example:
      $ python --init ./repository --consistent-snapshot=false --verbose 3

    If a required option is unset, a parser error is printed and the scripts
    exits.

  <Arguments>
    None.

  <Exceptions>
    None.

  <Side Effects>
    Sets the logging level for TUF logging.

  <Returns>
    A tuple ('options.REPOSITORY_PATH', command, command_arguments).  'command'
    'command_arguments' corresponds to a repository tool fuction.

  """

  parser = optparse.OptionParser()

  # Add the options supported by 'tuf.py' to the option parser.
  parser.add_option('--verbose', dest='VERBOSE', type=int, default=2,
                    help='Set the verbosity level of logging messages.'
                         'The lower the setting, the greater the verbosity.')

  parser.add_option('--init', dest='INIT', type='string', default='.',
                    help='')
  
  parser.add_option('--gen-key', dest='GEN-KEY', type='string', default='.',
                    help='')
  
  parser.add_option('--keytype', dest='KEYTYPE', type='string', default='ed25519',
                    help='')
  
  parser.add_option('--expires', dest='EXPIRES', type=int, default=365,
                    help='')
  
  parser.add_option('--add', dest='ADD', type='string', default='',
                    help='')
  
  parser.add_option('--remove', dest='REMOVE', type='string', default='',
                    help='')
 
  parser.add_option('--snapshot', dest='SNAPSHOT', type='string', default='.',
                    help='')
  
  parser.add_option('--timestamp', dest='TIMESTAMP', type='string', default='.',
                    help='')
  
  parser.add_option('--sign', dest='SIGN', type='string', default='.',
                    help='')
  
  parser.add_option('--commit', dest='COMMIT', type='string', default='.',
                    help='')
  
  parser.add_option('--regenerate', dest='REGENERATE', type='string', default='.',
                    help='')
  
  parser.add_option('--clean', dest='CLEAN', type='string', default='.',
                    help='')

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

  # Ensure the repository path was set by the user.
  if options.REPOSITORY_PATH is None:
    parser.error('The repository path is unknown.')
    
  # Return a tuple containing the repository path, command, and command
  # arguments needed by the repository tool.
  return options.REPOSITORY_PATH, command, command_options 



if __name__ == '__main__':
  
  # Parse the options and set the logging level.
  repository_path, command, command_arguments = parse_options()

  # Update the repository depending on the option specified on the command
  # line.  For example,
  # tuf.repository_tool.generate_and_write_ed25519_keypair('./path/to/keystore/root')
  # is called if the user invokes:
  # $ tuf --gen-key root --keystore ./path/to/keystore --keytype ed25519 
  
  try:
    update_repository(repository_path, command, command_arguments)
  
  except (tuf.Error) as e:
    sys.stderr.write('Error: ' + str(e) + '\n')
    sys.exit(1)

  # Successfully updated the local repository.
  sys.exit(0)
