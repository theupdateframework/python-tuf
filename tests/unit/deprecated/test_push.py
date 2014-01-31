"""
<Program Name>
  test_push.py

<Author>
  Konstantin Andrianov

<Started>
  April 2013.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Test push.py.

"""

import os
import getpass
import logging
import tempfile
import unittest
import ConfigParser

import tuf
import tuf.log
import tuf.pushtools.push as push
import tuf.pushtools.transfer.scp as scp
import tuf.pushtools.pushtoolslib as pushtoolslib
import tuf.tests.util_test_tools as util_test_tools

logger = logging.getLogger('tuf.test_push')


class TestPush(unittest.TestCase):
  src_push_dict = {}
  
  ORIGINAL_PUSH_CONFIG = pushtoolslib.PUSH_CONFIG



  @staticmethod
  def _mock_scp_transfer(config_dict):
    pass



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



  def setUp(self):
    # Create push configuration file, general temporary dir 'root_repo'.
    cwd = os.getcwd()
    self.push_config = tempfile.mkstemp(prefix='tmp_push_conf_', dir=cwd)[1]
    self.root_repo = tempfile.mkdtemp(prefix='tmp_tuf_repo_', dir=cwd)

    # Drop target files into the working project directory 'reg_repo'.
    # When targets metadata updates, the target files in the 'reg_repo'
    # will be copied into the tuf's targets directory.
    self.reg_repo = os.path.join(self.root_repo, 'reg_repo')
    os.mkdir(self.reg_repo)

    # Add a file to the 'reg_repo'.
    util_test_tools.add_file_to_repository(self.reg_repo, data='Test String')

    # Create TUF repository.
    util_test_tools.init_tuf(self.root_repo)

    # Update the tuf targets metadata.
    util_test_tools.make_targets_meta(self.root_repo)

    # Populate 'src_push_dict'.
    targets_dir = os.path.join(self.root_repo, 'tuf_repo', 'targets')
    metadate_path = os.path.join(self.root_repo, 'tuf_repo', 'metadata',
                                 'targets.txt')
    remote_dir = tempfile.mkdtemp(prefix='tmp_tuf_repo_', dir=self.root_repo)

    self.src_push_dict = {'general':{'transfer_module':'scp', 
                                     'metadata_path':metadate_path,
                                     'targets_directory':targets_dir},
                          'scp':{'host':'localhost',
                                 'identity_file':None,
                                 'user':getpass.getuser(),
                                 'remote_directory':remote_dir}}

    # Write the config dictionary into the push configuration file.
    self.write_config_file(self.push_config, self.src_push_dict)

    # Patch 'pushtoolslib.PUSH_CONFIG'.
    pushtoolslib.PUSH_CONFIG = os.path.basename(self.push_config)



  def tearDown(self):
    # Remove tempfile.
    os.remove(self.push_config)

    # Remove TUF repository.
    util_test_tools.cleanup(self.root_repo)

    # Clear 'src_push_dict'.
    self.src_push_dict.clear()

    # # Reassign 'pushtoolslib.PUSH_CONFIG'.
    pushtoolslib.PUSH_CONFIG = self.ORIGINAL_PUSH_CONFIG



  def test_expected_behaviour_of_push_without_scp(self):
    # Patch 'scp.transfer' function.
    ORIGINAL_SCP_TRANSFER_MODULE = scp.transfer
    scp.transfer = self._mock_scp_transfer

    push.push(self.push_config)

    # Restore 'scp.transfer' function.
    scp.transfer = ORIGINAL_SCP_TRANSFER_MODULE



  def test_exceptions_handeling_of_push_without_scp(self):
    # Patch 'scp.transfer' function.
    ORIGINAL_SCP_TRANSFER_MODULE = scp.transfer
    scp.transfer = self._mock_scp_transfer
    
    self.assertRaises(tuf.Error, push.push, self.root_repo)
    self.assertRaises(tuf.FormatError, push.push, None)
    self.assertRaises(tuf.FormatError, push.push, 12345)
    self.assertRaises(tuf.FormatError, push.push, ['test'])
    self.assertRaises(tuf.FormatError, push.push, {'test':'test'})

    # Restore 'scp.transfer' function.
    scp.transfer = ORIGINAL_SCP_TRANSFER_MODULE


  
  # Unit test bellow executes secure copy 'scp' command.  Hence user's
  # password is requered. Comment-out or remove the line bellow to 
  # un-skip the unit test.
  @unittest.skip("Requires user's password!") 
  def test_expected_behaviour_of_push_with_scp(self):
    push.push(self.push_config)





# Run the unittests
if __name__ == '__main__':
  unittest.main()
