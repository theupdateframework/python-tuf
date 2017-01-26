#!/usr/bin/env python

"""
<Program Name>
  conformance_tester.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  January 26, 2017

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Provide a tool for conformance testing with the specification.  The tool's
  behavior is governed by the design requisites defined in TAP 7 (Conformance
  testing), available at https://github.com/theupdateframework/taps.  This tool
  executes a tuf-compliant program, which is specified in .tuf-tester.yml, to
  perform compliance testing.

  This tool launches an HTTP server that listens for requests for metadata and
  targets.  It initially generates a root.json, according to the restrictions
  set in tuf-tester.yml, and stores it in the metadata directory of the
  tuf-compliant program.  The tuf-compliant program is expected to make an
  update and save metadata and target requests to specified directories.  This
  tool runs a series of tests that validate the downloaded metadata, targets,
  and return codes of the program.  If all tests pass, this tool
  exits with a return code of SUCCESS (O).  If any of the tests fail, this tool
  exits with a return code of FAILURE (1) (optionally, it prints/logs a list of
  tests that the program failed to satisfy, or updater attacks it failed to
  block).

<Usage>
  $ python compliance_tester.py --config /tmp/.tuf-tester.yml --verbose 3

<Options>
  --config:
    Configuration file that includes the tuf-compliant program to run and
    restrictions of the repository.  For example, the tuf-compliant program may
    only support ECDSA keys, so the 'keytype' entry of the configuration file
    is set to 'ecdsa'.  The configuration file must be named '.tuf-tester.yml'
    and be a valid YML file.

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

import pyyaml
import securesystemslib

# See 'log.py' to learn how logging is handled in TUF.
logger = logging.getLogger('tuf.conformance_tester')


def run_compliance_testing(config_file):
  """
  <Purpose>

  <Arguments>
    config_file:
      The path of the configuration file, which must be named '.tuf-tester.yml'.

 <Exceptions>
    None.

  <Side Effects>
    None.

  <Returns>
    None.
  """





def parse_options():
  """
  <Purpose>
    Parse the command-line options and set the logging level as specified by
    the user through the --verbose option.

    'test_updater.py' expects the --config command-line option to be set by the
    user.  --verbose is optional.

    Example:
      $ python conformance_tester.py --config /tmp/.tuf-tester.yml

    If the required option is unset, a parser error is printed and the scripts
    exits.

  <Arguments>
    None.

  <Exceptions>
    None.

  <Side Effects>
    Sets the logging level for TUF logging.

  <Returns>
    A options.CONFIG_FILE string.
  """

  parser = optparse.OptionParser()

  # Add the options supported by 'conformance_tester' to the option parser.
  parser.add_option('--config', dest='CONFIG_FILE', type='string',
                    help='Specify the configuration file that includes the'
                    ' tuf-compliant command to execute.')

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

  # Ensure the --config command-line option is set by the user.
  if options.CONFIG_FILE is None:
    parser.error('"--config" must be set on the command-line.')

  # Return the path of the configuration file.
  return options.CONFIG_FILE



if __name__ == '__main__':

  # Parse the options and set the logging level.
  configuration_file = parse_options()

  # Return codes for test_updater.py.  This list is not yet finalized.
  SUCCESS = 0
  FAILURE = 1

  # Execute the tests..
  try:
    run_conformance_testing(configuration_file)

  except (tuf.exceptions.Error) as exception:
    sys.exit(FAILURE)

  # Successfully updated the target file.
  sys.exit(SUCESS)
