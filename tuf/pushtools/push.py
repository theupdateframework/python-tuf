#!/usr/bin/env python

"""
<Program Name>
  push.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  August 2012.  Based on a previous version by Geremy Condra.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  This script provides a way for developers to push a signed targets metadata
  file (i.e., 'targets.txt') and the referenced targets to a repository. The
  repository adds these files to the repository by running the
  'tuf/pushtools/receivetools/receive.py' script.

  'push.py' is not a required module of The Update Framework, but is provided
  to allow developers to remotely update the target files served by a
  repository.  The actual file transfers are completed by a separate command
  available on the client machine.  The 'SCP' (secure copy) command is currently
  supported.  This script may be viewed as a front-end to the python transfer
  modules (e.g., 'tuf.pushtools.transfer.scp').  A configuration file can be
  specified allowing the user to customize the transfer and supply the locations
  of targets and metadata.

  Usage:
    $ python push.py --config <config path>
    
  Example:
    $ python push.py --config ./push.cfg

  Details of the 'push.py' script:

  The developer provides the path to a configuration file that lists:
    * The path to the targets metadata file.
    * The name of the transfer module to use for transferring the
      files to the repository (e.g., 'scp').
    * Configuration information that is specific to the transfer
      module.

  See the 'push.cfg.sample' file for an example configuration file.

  The transfer module needs the following functionality:
    * A way to transfer target files and the new metadata file to the
      repository.  The 'scp' transfer modules is currently supported.
      
  The transfer module may also include the following functionality:
    * A way to determine whether the repository has rejected the push and, if
      so, the reason for the rejection.

"""

import os
import sys
import optparse

import tuf
import tuf.formats
import tuf.pushtools.pushtoolslib
import tuf.pushtools.transfer.scp



def push(config_filepath):
  """
  <Purpose>
    Perform a push/transfer of target files to a host.  The configuration file
    'config_filepath' provides the required settings needed by the transfer
    command.  In the case of an 'scp' configuration file, the configuration
    file would contain 'host', 'user', 'identity file', and 'remote directory'
    entries.
     
  <Arguments>
    config_filepath:
      The push configuration file (i.e., 'push.cfg').
      
  <Exceptions>
    tuf.FormatError, if any of the arguments are incorrectly formatted.

    tuf.Error, if there was an error while processing the push.

  <Side Effects>
    The 'config_filepath' file is read and its contents stored, the files
    in the targets directory (specified in the config file) are copied,
    and the copied targets transfered to a specified host.

  <Returns>
    None.
  
  """

  # Do the arguments have the correct format?
  # Raise 'tuf.FormatError' if there is a mismatch.
  tuf.formats.PATH_SCHEMA.check_match(config_filepath)
 
  # Is the path to the configuration file valid?
  if not os.path.isfile(config_filepath):
    message = 'The configuration file path is invalid.'
    raise tuf.Error(message)
  config_filepath = os.path.abspath(config_filepath)

  # Retrieve the push configuration settings required by the transfer
  # modules.  Raise ('tuf.FormatError', 'tuf.Error') if a valid
  # configuration file cannot be retrieved.
  config_dict = tuf.pushtools.pushtoolslib.read_config_file(config_filepath, 'push')

  # Extract the transfer module identified in the configuration file.
  transfer_module = config_dict['general']['transfer_module']
 
  # 'scp' is the only transfer module currently supported.  Perform
  # an scp-transfer of the targets located in the targets directory as
  # listed in the configuration file.
  if transfer_module == 'scp':
    tuf.pushtools.transfer.scp.transfer(config_dict)
  else:
    message = 'Cannot perform a transfer using '+repr(transfer_module) 
    raise tuf.Error(message)





def parse_options():
  """
  <Purpose>
    Parse the command-line options.  'push.py' expects the '--config'
    option to be set by the user.

    Example:
      $ python push.py --config ./push.cfg

    The '--config' option accepts a path argument to the push configuration
    file (i.e., 'push.cfg').  If the required option is unset, a parser error
    is printed and the script exits.

  <Arguments>
    None.

  <Exceptions>
    None.

  <Side Effects>
    None.

  <Returns>
    The options object returned by the parser's parse_args() method.

  """

  usage = 'usage: %prog --config <config path>'
  option_parser = optparse.OptionParser(usage=usage)

  # Add the options supported by 'push.py' to the option parser.
  option_parser.add_option('--config', action='store', type='string',
                            help='Specify the "push.cfg" configuration file.')

  (options, remaining_arguments) = option_parser.parse_args()

  # Ensure the '--config' option is set.  If the required option is unset,
  # option_parser.error() will print an error message and exit.
  if options.config is None:
    message = '"--config" must be set on the command-line.'
    option_parser.error(message)

  return options





if __name__ == '__main__':
  options = parse_options()

  # Perform a 'push' of the target files specified in the configuration file.
  try:
    push(options.config)
  except (tuf.FormatError, tuf.Error), e:
    sys.stderr.write('Error: '+str(e)+'\n')
    sys.exit(1)

  # The 'push' and command-line options were processed successfully.
  sys.exit(0)
