"""
<Program Name>
  test_quickstart.py

<Author>
  Konstantin Andrianov

<Started>
  September 6, 2012

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  To test quickstart.py for expected/unexpected input by the user, verifying
  that all unexpected input is caught and an exception is raised.

  Given that all message prompts don't change - this will work pretty well
  for running quickstart without having to manually enter input to prompts
  every time you want to run quickstart.

"""

import os
import shutil
import unittest
import logging

import tuf
import tuf.log
import tuf.repo.quickstart as quickstart
import tuf.util
import tuf.tests.unittest_toolbox as unittest_toolbox

logger = logging.getLogger('tuf.test_quickstart')
unit_tbox = unittest_toolbox.Modified_TestCase


logger.info('from test_quickstart')

class TestQuickstart(unit_tbox):
  def test_1_get_password(self):
    
    # SETUP
    original_getpass = quickstart.getpass.getpass
    
    # A quick test of _get_password.
    password = self.random_string()
    def _mock_getpass(junk1, junk2, pw = password):
      return pw
    # Monkey patch getpass.getpass().
    quickstart.getpass.getpass = _mock_getpass
    # Run _get_password().
    self.assertEqual(quickstart._get_password(), password)

    # RESTORE
    quickstart.getpass.getpass = original_getpass



  def test_2_build_repository(self):

    # SETUP
    original_prompt = quickstart._prompt
    original_get_password = quickstart._get_password
    
    #  Create the project directories.
    repo_dir = os.path.join(os.getcwd(), 'repository')
    keystore_dir = os.path.join(os.getcwd(), 'keystore')
    client_dir = os.path.join(os.getcwd(), 'client')
    
    proj_files = self.make_temp_directory_with_data_files()
    proj_dir = os.path.join(proj_files[0], 'targets')

    input_dict = {'expiration':'12/12/2020',
                  'root':{'threshold':1, 'password':'pass'},
                  'targets':{'threshold':1, 'password':'pass'},
                  'release':{'threshold':1, 'password':'pass'},
                  'timestamp':{'threshold':1, 'password':'pass'}}


    def _mock_prompt(message, confirm=False, input_parameters=input_dict):
      if message.startswith('\nWhen would you like your '+
          '"root.txt" metadata to expire?'):
        return input_parameters['expiration']
      for role in self.role_list:  # role_list=['root', 'targets', ...]
        if message.startswith('\nEnter the desired threshold '+
            'for the role '+repr(role)):
          return input_parameters[role]['threshold']
        elif message.startswith('Enter a password for '+repr(role)):
          for threshold in range(input_parameters[role]['threshold']):
            if message.endswith(repr(role)+' ('+str(threshold+1)+'): '):
              return input_parameters[role]['password']
      print 'Cannot recognize message: '+message

    # Monkey patching quickstart's _prompt() and _get_password.
    quickstart._prompt = _mock_prompt
    quickstart._get_password = _mock_prompt


    def _remove_repository_directories(repo_dir, keystore_dir, client_dir):
      """
        quickstart.py creates the 'client', 'keystore', and 'repository'
        directories in the current working directory.  Remove these
        directories after every quickstart.build_repository() call.
      """
      
      try: 
        shutil.rmtree(repo_dir)
        shutil.rmtree(keystore_dir)
        shutil.rmtree(client_dir)
      except OSError, e:
        pass



    # TESTS

    #  TEST: various input parameters.
    #  Supplying bogus expiration.
    input_dict['expiration'] = '5/8/2011'
    self.assertRaises(tuf.RepositoryError, quickstart.build_repository,
        proj_dir)
    # Random string.
    input_dict['expiration'] = self.random_string()
    self.assertRaises(tuf.RepositoryError, quickstart.build_repository,
        proj_dir)
    _remove_repository_directories(repo_dir, keystore_dir, client_dir) 
    
    #  Restore expiration.
    input_dict['expiration'] = '10/10/2020'

    #  Supplying bogus 'root' threshold.  Doing this for all roles slows
    #  the test significantly.
    input_dict['root']['threshold'] = self.random_string()
    self.assertRaises(tuf.RepositoryError, quickstart.build_repository,
        proj_dir)
    _remove_repository_directories(repo_dir, keystore_dir, client_dir) 

    input_dict['root']['threshold'] = 0
    self.assertRaises(tuf.RepositoryError, quickstart.build_repository,
        proj_dir)
    _remove_repository_directories(repo_dir, keystore_dir, client_dir) 
    
    # Restore keystore directory.
    input_dict['root']['threshold'] = 1

    
    #  TEST: normal case.
    try:
      quickstart.build_repository(proj_dir)
    except Exception, e:
      raise
    
    # Verify the existence of metadata, target, and keystore files.
    meta_dir = os.path.join(repo_dir, 'metadata')
    targets_dir = os.path.join(repo_dir, 'targets')
    client_current_meta_dir = os.path.join(client_dir, 'metadata', 'current')
    client_previous_meta_dir = os.path.join(client_dir, 'metadata', 'previous')
    target_files = os.listdir(targets_dir)

    #  Verify repository, keystore, metadata, and targets directories.
    self.assertTrue(os.path.exists(repo_dir))
    self.assertTrue(os.path.exists(keystore_dir))
    self.assertTrue(os.path.exists(meta_dir))
    self.assertTrue(os.path.exists(targets_dir))
    self.assertTrue(os.path.exists(client_current_meta_dir))
    self.assertTrue(os.path.exists(client_previous_meta_dir))

    # Verify that target_files exist.
    self.assertTrue(target_files)

    for role in self.role_list:
      meta_file = role+'.txt'
      # Verify metadata file for a 'role'.
      self.assertTrue(os.path.isfile(os.path.join(meta_dir, meta_file)))
      # Get the metadata.
      signable = tuf.util.load_json_file(os.path.join(meta_dir, meta_file))
      for signature in range(len(signable['signatures'])):
        # Extract a keyid.
        keyid = signable['signatures'][signature]['keyid']
        key_file = os.path.join(keystore_dir, keyid+'.key')
        # Verify existence of a key for the keyid that belong to the 'role'.
        self.assertTrue(os.path.isfile(key_file))

    _remove_repository_directories(repo_dir, keystore_dir, client_dir) 

    # RESTORE 
    quickstart._prompt = original_prompt
    quickstart._get_password = original_get_password



# Run the unit tests.
if __name__ == '__main__':
  unittest.main()
