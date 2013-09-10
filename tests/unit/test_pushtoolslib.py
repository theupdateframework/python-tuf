"""
<Program Name>
  test_pushtoolslib.py

<Author>
  Konstantin Andrianov

<Started>
  April 2013.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Test pushtoolslib.py.

"""

import os
import tempfile
import unittest
import ConfigParser
import logging

import tuf
import tuf.log
import tuf.formats
import tuf.pushtools.pushtoolslib as pushtoolslib

logger = logging.getLogger('tuf.test_pushtoolslib')


class TestPushtoolslib(unittest.TestCase):
  src_push_dict = {}
  src_receive_dict = {}
  ORIGINAL_PUSH_CONFIG = pushtoolslib.PUSH_CONFIG
  ORIGINAL_RECEIVE_CONFIG = pushtoolslib.RECEIVE_CONFIG



  def setUp(self):
    # Create config tempfiles.
    cwd = os.getcwd()
    self.push_config_file = tempfile.mkstemp(prefix='tmp_push_conf_', dir=cwd)[1]
    self.receive_config_file = tempfile.mkstemp(prefix='tmp_receive_conf_', dir=cwd)[1]

    # Populate 'src_push_dict' and 'src_receive_dict'.
    self.src_push_dict = {'general':{'transfer_module':'scp', 
                                     'metadata_path':'some/path',
                                     'targets_directory':'some/path'},
                          'scp':{'host':'localhost',
                                 'user':'user',
                                 'identity_file':None,
                                 'remote_directory':'~/pushes'}}

    self.src_receive_dict = {'general':{'pushroots':['some/path'],
                                        'repository_directory':'some/path',
                                        'metadata_directory':'some/path',
                                        'targets_directory':'some/path',
                                        'backup_directory':'some/path'}}

    # Patch the 'pushtoolslib.PUSH_CONFIG' and 'pushtoolslib.RECEIVE_CONFIG'
    pushtoolslib.PUSH_CONFIG = os.path.basename(self.push_config_file)
    pushtoolslib.RECEIVE_CONFIG = os.path.basename(self.receive_config_file)



  def tearDown(self):
    # Remove tempfile.
    os.remove(self.push_config_file)
    os.remove(self.receive_config_file)

    # Clear dictionaries.
    self.src_push_dict.clear()
    self.src_receive_dict.clear()

    # Reassign 'pushtoolslib.PUSH_CONFIG' and 'pushtoolslib.RECEIVE_CONFIG'
    # to original values.
    pushtoolslib.PUSH_CONFIG = self.ORIGINAL_PUSH_CONFIG
    pushtoolslib.RECEIVE_CONFIG = self.ORIGINAL_RECEIVE_CONFIG



  @staticmethod
  def write_config_file(config_filename, config_dictionary):
    """Create a configuration file by writing supplied configuration
    dictionary ('config_dictionary') into the file ('config_filename')."""

    config = ConfigParser.RawConfigParser()

    for section, values_dict in config_dictionary.iteritems():
      config.add_section(section)
      for key in values_dict:
        config.set(section, key, values_dict[key])

    # Writing our configuration file to 'config_filename'.
    with open(config_filename, 'wb') as configfile:
      config.write(configfile)



  def test_expected_behavior_of_read_config_file(self):
    # Test 'push' configuration type.
    self.write_config_file(self.push_config_file, self.src_push_dict)
    config_dict = pushtoolslib.read_config_file(self.push_config_file, 'push')
    tuf.formats.SCPCONFIG_SCHEMA.check_match(config_dict)

    # Test 'receive' configuration type.
    self.write_config_file(self.receive_config_file, self.src_receive_dict)
    config_dict = pushtoolslib.read_config_file(self.receive_config_file, 'receive')
    tuf.formats.RECEIVECONFIG_SCHEMA.check_match(config_dict)



  def test_exceptions_handeling_of_read_config_file(self):
    # Test an incorrect configuration file.
    with open(self.push_config_file, 'wb') as configfile:
      configfile.write('test')
    self.assertRaises(tuf.Error, pushtoolslib.read_config_file,
      self.push_config_file, 'push')

    self.write_config_file(self.push_config_file, {})
    self.assertRaises(tuf.Error, pushtoolslib.read_config_file,
      self.push_config_file, 'push')

    self.write_config_file(self.receive_config_file, self.src_receive_dict)
    self.assertRaises(tuf.Error, pushtoolslib.read_config_file,
      self.receive_config_file, 'push')

    self.write_config_file(self.push_config_file, self.src_push_dict)
    self.assertRaises(tuf.Error, pushtoolslib.read_config_file,
      self.push_config_file, 'receive')

    # Test incorrect configuration type.
    self.write_config_file(self.push_config_file, self.src_push_dict)
    self.assertRaises(tuf.Error, pushtoolslib.read_config_file,
      self.push_config_file, 'junk')

    # Test 'push' type configuration with 'transfer_module' absent from 
    # config_dict['general'].
    saved_transfer_module = self.src_push_dict['general']['transfer_module']
    del self.src_push_dict['general']['transfer_module']
    self.write_config_file(self.push_config_file, self.src_push_dict)
    self.assertRaises(tuf.Error, pushtoolslib.read_config_file,
      self.push_config_file, 'push')

    # Test 'push' type configuration with 
    # config_dict['general']['transfer_module'] != 'scp'.
    self.src_push_dict['general']['transfer_module'] = 'test'
    self.write_config_file(self.push_config_file, self.src_push_dict)
    self.assertRaises(tuf.Error, pushtoolslib.read_config_file,
      self.push_config_file, 'push')

    # Test 'push' type configuration with one of the keys missing.
    self.src_push_dict['general']['transfer_module'] = 'scp'
    del self.src_push_dict['general']['metadata_path']
    self.write_config_file(self.push_config_file, self.src_push_dict)
    self.assertRaises(tuf.FormatError, pushtoolslib.read_config_file,
      self.push_config_file, 'push')

    # Test 'receive' type configuration with one of the keys missing. 
    del self.src_receive_dict['general']['repository_directory']
    self.write_config_file(self.receive_config_file, self.src_receive_dict)
    self.assertRaises(tuf.FormatError, pushtoolslib.read_config_file,
      self.receive_config_file, 'receive')





# Run the unittests
if __name__ == '__main__':
  unittest.main()
