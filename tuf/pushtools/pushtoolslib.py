"""
<Program Name>
  pushtoolslib.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  September 2012.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Provide a central location for functions and data useful to multiple
  'tuf.pushtools' modules.  A 'read_config_file' function is currently
  provided that returns correctly formatted configuration dictionaries
  needed by the 'push.py' and 'receive.py' scripts.

"""

import ConfigParser
import os

import tuf.formats

PUSH_CONFIG = 'push.cfg'
RECEIVE_CONFIG = 'receive.cfg'
TRANSFER_MODULES = ['scp']
CONFIG_TYPES = ['push', 'receive']


def read_config_file(filename, config_type):
  """
  <Purpose>
    Return a dictionary where the keys are section names and the values
    dictionaries of the keys/values in that section.  The returned
    dict should be correctly formatted, contain the required data
    according to its config type, and be valid (i.e., a correctly named
    file and available).
    
    Example config:

    config_dict = {'general': {'transfer_module': 'scp', ...},
                   'scp': {'host': 'localhost', 'user': 'McFly', ...}}

  <Arguments>
    filename:
      The filepath to the configuration file.

    config_type:
      A string identifying the type of config file expected.  Supported
      config types: 'push' and  'receive'.
      
  <Exceptions>
    tuf.FormatError, if the arguments are improperly formatted.

    tuf.Error, if there is an error processing the config contents.

  <Side Effects>
    The contents of 'filename' are read and stored.

  <Returns>
    A dictionary containing the data loaded from the configuration file.

  """
  
  # Do the arguments have the correct format?
  # Raise 'tuf.FormatError' if there is a mismatch.
  tuf.formats.PATH_SCHEMA.check_match(filename)
  tuf.formats.NAME_SCHEMA.check_match(config_type)
  
  # RawConfigParser is used because unlike ConfigParser,
  # it does not provide magical interpolation/expansion
  # of variables (e.g., '%(option)s' would be ignored).
  config = ConfigParser.RawConfigParser()
  try:
    config.read(filename)
  except ConfigParser.MissingSectionHeaderError, error:
    raise tuf.Error(error)

  if config.sections() is None:
    raise tuf.Error('Could not read '+repr(filename))

  # Extract the relevant information from the config and build the
  # 'config_dict' dictionary.
  config_dict = {}
  for section in config.sections():
    config_dict[section] = {}
    for key, value in config.items(section):
      # Split comma-separated entries and store them in a list.
      # 'pushroots' is the only entry that currently accepts
      # multiple values.
      if key in ['pushroots']:
        value = value.split(',')
      config_dict[section][key] = value
 
  # Before returning a 'push' config dict, check the config is properly
  # formatted, valid, and contains the required data.
  if config_type == 'push':
    # Ensure 'filename' is an appropriately named push config file.
    if os.path.basename(filename) != PUSH_CONFIG:
      message = repr(filename)+' is not a valid push config file.'+\
        '  The push config file should be named: '+repr(PUSH_CONFIG)
      raise tuf.Error(message)
    
    # Retrieve the transfer module from the push config.  The caller
    # expects a valid config dict containing the required keys/values.
    try:
      transfer_module = config_dict['general']['transfer_module']
    except KeyError, e:
      message = 'The push config file did not contain the required '+\
        '"transfer_module" entry under "[general]".'
      raise tuf.Error(message)
   
    # Determine the transfer module and ensure the config file is properly
    # formatted for an "scp configuration file".  Raise 'tuf.FormatError'
    # if there is mismatch.
    if transfer_module == 'scp':
      try:
        tuf.formats.SCPCONFIG_SCHEMA.check_match(config_dict)
      except tuf.FormatError, e:
        message = repr(PUSH_CONFIG)+' rejected.  '+str(e)
        raise tuf.FormatError(message)
    # A supported transfer module was not found.  Raise 'tuf.Error'. 
    else:
      message = 'The config file contains an invalid "transfer_module" entry '+\
        'Supported transfer modules: '+repr(TRANSFER_MODULES)
      raise tuf.Error(message)

  # Before returning a 'receive' config dict, check the config is properly
  # formatted, valid, and contains the required data.
  elif config_type == 'receive':
    # Ensure 'filename' is an appropriately named receive config file.
    if os.path.basename(filename) != RECEIVE_CONFIG:
      message = repr(filename)+' is not a valid receive config file.'+\
      '  The receive config file should be named: '+repr(RECEIVE_CONFIG)
      raise tuf.Error(message)
    
    # Determine if the config file is properly formatted for a "receive
    # configuration file".  Raise 'tuf.FormatError' if there is a
    # mismatch.
    try: 
      tuf.formats.RECEIVECONFIG_SCHEMA.check_match(config_dict)
    except tuf.FormatError, e:
      message = repr(RECEIVE_CONFIG)+' rejected.  '+str(e)
      raise tuf.FormatError(message)

  # Invalid 'config_type' requested.
  else:
    message = 'Invalid "config_type" argument.  Supported: '+repr(CONFIG_TYPES)
    raise tuf.Error(message)

  return config_dict
