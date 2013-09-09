#!/usr/bin/env python

"""
<Program Name>
  test_signercli.py

<Author>
  Konstantin Andrianov

<Started>
  September 20, 2012

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  test_signercli.py provides collection of methods that tries to test all the
  units (methods) of the module under test.

  unittest_toolbox module was created to provide additional testing tools for
  tuf's modules.  For more info see unittest_toolbox.py.


<Methodology>
  Unittests must follow a specific structure i.e. independent methods should
  be tested prior to dependent methods. More accurately: least dependent
  methods are tested before most dependent methods.  There is no reason to
  rewrite or construct other methods that replicate already-tested methods
  solely for testing purposes.  This is possible because 'unittest.TestCase'
  class guarantees the order of unit tests.  So that, 'test_something_A'
  method would be tested before 'test_something_B'.  To ensure the structure
  a number will be placed after 'test' and before methods name like so:
  'test_1_check_directory'.  The number is a measure of dependence, where 1
  is less dependent than 2.

"""


import os
import time
import logging
import unittest

import tuf
import tuf.log
import tuf.formats
import tuf.util
import tuf.repo.keystore as keystore
import tuf.repo.signerlib as signerlib

#  Module to test: signercli.py
import tuf.repo.signercli as signercli

#  Helper module unittest_toolbox.py
import tuf.tests.unittest_toolbox as unittest_toolbox

logger = logging.getLogger('tuf.test_signercli')



class TestSignercli(unittest_toolbox.Modified_TestCase):
  # SETUP 
  original_prompt = signercli._prompt
  signercli._prompt = original_prompt

  original_get_metadata_directory = signercli._get_metadata_directory
  signercli._get_metadata_directory = original_get_metadata_directory
  
  original_get_password = signercli._get_password
  signercli._get_password = original_get_password
  
  #  HELPER METHODS.

  #  Generic patch for signerlib._prompt().
  def mock_prompt(self, output):

    #  Method to patch signercli._prompt().
    def _mock_prompt(junk1, junk2, ret=output):
      return ret

    #  Patch signercli._prompt()
    signercli._prompt = _mock_prompt



  #  Patch signercli._get_metadata_directory()
  def mock_get_metadata_directory(self, directory=None):

    #  Create method to patch signercli._get_metadata_directory()
    def _mock_get_meta_dir(directory=directory):

      #  If directory was specified, return that directory.
      if directory:
        return directory

      #  Else create a temporary directory and return it.
      else:
        return self.make_temp_directory()

    #  Patch signercli._get_metadata_directory()
    signercli._get_metadata_directory = _mock_get_meta_dir



  #  This method patches signercli._prompt() that are called from
  #  make_role_metadata methods (e.g., tuf.signercli.make_root_metadata()).
  def make_metadata_mock_prompts(self, targ_dir, conf_path, expiration):
    def _mock_prompt(msg, junk):
      if msg.startswith('\nInput may be a directory, directories, or'):
        return targ_dir
      elif msg.startswith('\nEnter the configuration file path'):
        return conf_path
      elif msg.startswith('\nCurrent time:'):
        return expiration
      else:
        error_msg = ('Prompt: '+'\''+msg[1:]+'\''+
            ' did not match any predefined mock prompts.')
        self.fail(error_msg)

    #  Patch signercli._prompt().
    signercli._prompt = _mock_prompt



  #  This mock method can be easily modified, by altering unittest_toolbox's
  #  dictionaries.  For instance, if you want to modify password for certain
  #  keyid just save the existing 'self.rsa_passwords[keyid]' and set it
  #  to some other value like self.random_string(), after the test reassign
  #  the saved value back to 'self.rsa_passwords[keyid]'.
  def get_passwords(self):
    #  Mock '_get_password' method.
    def _mock_get_password(msg):
      for role in self.role_list:
        if msg.startswith('\nEnter the password for the '+role):
          for keyid in self.top_level_role_info[role]['keyids']:
            if msg.endswith(keyid+'): '):
              return self.rsa_passwords[keyid]
      error_msg = ('Prompt: '+'\''+msg+'\''+
          ' did not match any predefined mock prompts.')
      raise tuf.Error(error_msg)

    #  Monkey patch '_prompt'.
    signercli._get_password = _mock_get_password





  #  UNIT TESTS.
  #  If a unit test starts with test_# followed by two underscores,
  #  (test_#__method) this means that it's an internal method of signercli.
  #  For instance the unit test for signercli._get_password() would
  #  look like this: test_1__get_password, whereas unit test for
  #  signercli.change_password would look like this:
  #  test_3_change_password().

  def test_1__check_directory(self):

    # SETUP
    directory = self.make_temp_directory()
    no_such_dir = self.random_path()


    # TESTS
    #  Test: normal case.
    self.assertEqual(signercli._check_directory(directory), directory)

    #  Test: invalid directory.
    self.assertRaises(tuf.RepositoryError, signercli._check_directory,
        no_such_dir)

    #  Test: invalid directory type.
    self.assertRaises(tuf.RepositoryError, signercli._check_directory,
                      [no_such_dir])
    self.assertRaises(tuf.RepositoryError, signercli._check_directory,
                      1234)
    self.assertRaises(tuf.RepositoryError, signercli._check_directory,
                      {'directory':no_such_dir})





  def test_1__get_password(self):
    
    # SETUP
    original_getpass = signercli.getpass.getpass

    password = self.random_string()
    def _mock_getpass(junk1, junk2, pw=password):
      return pw

    # Patch getpass.getpass().
    signercli.getpass.getpass = _mock_getpass


    # Test: normal case.
    self.assertEqual(signercli._get_password(), password)
    
    # RESTORE
    signercli.getpass.getpass = original_getpass




  def test_2__get_metadata_directory(self):
    
    # SETUP
    original_prompt = signercli._prompt
    
    meta_directory = self.make_temp_directory()
    self.mock_prompt(meta_directory)


    # TESTS
    self.assertEqual(signercli._get_metadata_directory(), meta_directory)
    self.assertTrue(os.path.exists(signercli._get_metadata_directory()))
    self.mock_prompt(self.random_string())
    self.assertRaises(tuf.RepositoryError, signercli._get_metadata_directory)
    self.mock_prompt([self.random_string()])
    self.assertRaises(tuf.RepositoryError, signercli._get_metadata_directory)
    
    # RESTORE
    signercli._prompt = original_prompt




  def test_4__list_keyids(self):

    # SETUP
    original_get_metadata_directory = signercli._get_metadata_directory
    original_prompt = signercli._prompt
    original_get_password = signercli._get_password
   
    #  Creating root and target metadata requires an expiration date to be set.
    #  Expiration date set to expires 100 seconds from the current time.
    expiration_date = tuf.formats.format_time(time.time()+100)
    expiration_date = expiration_date[0:expiration_date.rfind(' UTC')] 
    
    # The 'root.txt' and 'targets.txt' metadata files are
    # needed for _list_keyids() to determine the roles
    # associated with each keyid.
    keystore_dir = self.create_temp_keystore_directory()
    repo_dir = self.make_temp_directory()
    
    #  Create temp directory for config file.
    config_dir = self.make_temp_directory()

    #  Build a config file.
    config_filepath = signerlib.build_config_file(config_dir, 365,
        self.top_level_role_info)
    
    #  Create the metadata directory needed by _list_keyids().
    meta_dir = self.make_temp_directory()

    #  Patch signercli._get_metadata_directory().
    self.mock_get_metadata_directory(directory=meta_dir)

    #  Patch signercli._prompt().
    self.mock_prompt(config_filepath)

    #  Patch signercli._get_password().
    self.get_passwords()
   
    #  Create the root metadata file that will be loaded by _list_keyids()
    #  to extract the keyids for the top-level roles. 
    signercli.make_root_metadata(keystore_dir)
    
    #  Create a directory containing target files.
    targets_dir, targets_paths =\
        self.make_temp_directory_with_data_files(directory=repo_dir)
   
    #  Mock method for signercli._prompt().
    self.make_metadata_mock_prompts(targ_dir=targets_dir,
                                    conf_path=config_filepath,
                                    expiration=expiration_date)

    #  Create the target metadata file that will be loaded by _list_keyids()
    #  to extract the keyids for all the targets roles.
    signercli.make_targets_metadata(keystore_dir)


    # TESTS
    #  Test: normal case.
    signercli._list_keyids(keystore_dir, meta_dir)

    #  Test: Improperly formatted 'root.txt' file.
    root_filename = os.path.join(meta_dir, 'root.txt')
    root_signable = tuf.util.load_json_file(root_filename)
    saved_roles = root_signable['signed']['roles'] 
    del root_signable['signed']['roles']
    tuf.repo.signerlib.write_metadata_file(root_signable, root_filename)
    
    self.assertRaises(tuf.RepositoryError,
                      signercli._list_keyids, keystore_dir, meta_dir)
    
    # Restore the properly formatted 'root.txt' file.
    root_signable['signed']['roles'] = saved_roles
    tuf.repo.signerlib.write_metadata_file(root_signable, root_filename)

    #  Test:  Improperly formatted 'targets.txt' file.
    targets_filename = os.path.join(meta_dir, 'targets.txt')
    targets_signable = tuf.util.load_json_file(targets_filename)
    saved_targets = targets_signable['signed']['targets']
    del targets_signable['signed']['targets']
    tuf.repo.signerlib.write_metadata_file(targets_signable, targets_filename)

    self.assertRaises(tuf.RepositoryError,
                      signercli._list_keyids, keystore_dir, meta_dir)

    # Restore the properly formatted 'targets.txt' file.
    targets_signable['signed']['targets'] = saved_targets
    tuf.repo.signerlib.write_metadata_file(targets_signable, targets_filename)

    # RESTORE
    signercli._get_password = original_get_password
    signercli._prompt = original_prompt
    signercli._get_metadata_directory = original_get_metadata_directory



  def test_2__get_keyids(self):
    
    # SETUP
    original_prompt = signercli._prompt
    original_get_password = signercli._get_password
    
    #  Create a temp keystore directory.
    keystore_dir = self.create_temp_keystore_directory()

    #  List of keyids including keyword 'quit'.
    keyids = ['quit'] + self.rsa_keyids

    #  Patching signercli._prompt()
    def _mock_prompt(msg, junk):

      #  Pop 'keyids' everytime signercli._prompt() is called.
      keyid = keyids.pop()
      if keyid != 'quit':
        get_password(keyid)
      return keyid

    signercli._prompt = _mock_prompt
    
    #  Patching signercli._get_password().
    def get_password(keyid):
      password = self.rsa_passwords[keyid]
      def _mock_get_password(msg):
        return password

      signercli._get_password = _mock_get_password


    # TESTS
    #  Test: normal case.
    loaded_keyids = signercli._get_keyids(keystore_dir)
    self.assertTrue(tuf.formats.KEYIDS_SCHEMA.matches(loaded_keyids))
    
    #  Check if all the keysids were loaded.
    for keyid in self.rsa_keyids:
      if keyid not in loaded_keyids:
        msg = 'Could not load the keyid: '+repr(keyid)
        self.fail(msg)
   
    #  Test: invalid password.
    keyids = ['quit', self.rsa_keyids[0]]
    saved_pw = self.rsa_passwords[self.rsa_keyids[0]]
    
    #  Invalid password
    self.rsa_passwords[self.rsa_keyids[0]] = self.random_string()
    self.assertEqual(signercli._get_keyids(keystore_dir), [])

    #  Restore the password.
    self.rsa_passwords[self.rsa_keyids[0]] = saved_pw

    #  Test: invalid keyid.
    keyid = self.random_string()
    keyids = ['quit', keyid]

    #  Create an invalid entry in the passwords dictionary.
    self.rsa_passwords[keyid] = self.random_string()
    self.assertEqual(signercli._get_keyids(keystore_dir), [])

    #  Restore passwords dictionary.
    del self.rsa_passwords[keyid]

    # RESTORE
    signercli._get_password = original_get_password
    signercli._prompt = original_prompt



  def test_2__get_all_config_keyids(self):

    # SETUP
    original_get_password = signercli._get_password
    
    #  Create temp directory for config file.
    config_dir = self.make_temp_directory()

    #  Build the config file needed by '_get_all_config_keyids.
    config_filepath = signerlib.build_config_file(config_dir, 365,
                                                  self.top_level_role_info)

    #  Create a temp keystore directory.
    keystore_dir = self.create_temp_keystore_directory()

    #  'sample_keyid' used to test invalid keyid.
    sample_keyid = self.rsa_keyids[0]

    #  Patch signercli._get_password()
    self.get_passwords()


    # TESTS
    #  Test: an incorrect password.
    saved_pw = self.rsa_passwords[sample_keyid]
    self.rsa_passwords[sample_keyid] = self.random_string()
    self.assertRaises(tuf.Error, signercli._get_all_config_keyids,
                      config_filepath, keystore_dir)

    #  Restore the password.
    self.rsa_passwords[sample_keyid] = saved_pw

    #  Test: missing top-level role in the config file.
    #    Clear keystore's dictionaries.
    keystore.clear_keystore()

    #    Remove a role from 'top_level_role_info' which is used to construct
    #    config file.
    targets_holder = self.top_level_role_info['targets']
    del self.top_level_role_info['targets']

    #    Build config file without 'targets' role.
    config_filepath = signerlib.build_config_file(config_dir, 365,
                                                  self.top_level_role_info)
    self.assertRaises(tuf.Error, signercli._get_all_config_keyids,
                      config_filepath, keystore_dir)

    #    Rebuild config file and 'top_level_role_info'.
    self.top_level_role_info['targets'] = targets_holder
    config_filepath = signerlib.build_config_file(config_dir, 365,
                                                  self.top_level_role_info)

    #  Test: non-existing config file path.
    keystore.clear_keystore()
    self.assertRaises(tuf.Error, signercli._get_all_config_keyids,
                      self.random_path(), keystore_dir)

    #  Test: normal case.
    keystore.clear_keystore()
    signercli._get_all_config_keyids(config_filepath, keystore_dir)

    # RESTORE
    signercli._get_password = original_get_password




  def test_2__get_role_config_keyids(self):

    # SETUP
    original_get_password = signercli._get_password
    
    #  Create temp directory for config file.
    config_dir = self.make_temp_directory()

    #  Build a config file.
    config_filepath = signerlib.build_config_file(config_dir, 365,
                                                  self.top_level_role_info)
    #  Create a temp keystore directory.
    keystore_dir = self.create_temp_keystore_directory()

    #  Patch '_get_password' method.
    self.get_passwords()

    # TESTS
    for role in self.role_list:
      #  Test: normal cases.
      keystore.clear_keystore()
      signercli._get_role_config_keyids(config_filepath, keystore_dir, role)
      
      #  Test: incorrect passwords.
      keystore.clear_keystore()
      role_keyids = self.top_level_role_info[role]['keyids']
      for keyid in role_keyids:
        saved_pw = self.rsa_passwords[keyid]
        self.rsa_passwords[keyid] = self.random_string()
        self.assertRaises(tuf.Error, signercli._get_role_config_keyids,
            config_filepath, keystore_dir, role)

        #    Restore the password.
        self.rsa_passwords[keyid] = saved_pw

    #  Test: non-existing config file path.
    keystore.clear_keystore()
    self.assertRaises(tuf.Error, signercli._get_role_config_keyids,
        self.random_path(), keystore_dir, 'release')

    #  Test: non-existing role.
    keystore.clear_keystore()
    self.assertRaises(tuf.Error, signercli._get_role_config_keyids,
                      config_filepath, keystore_dir, 'no_such_role')

    # RESTORE
    signercli._get_password = original_get_password




  def test_1__sign_and_write_metadata(self):

    # SETUP
    #  Role to test.
    role = 'root'

    #  Create temp directory.
    temp_dir = self.make_temp_directory()

    #  File name.
    filename = os.path.join(temp_dir, role+'.txt')

    #  Role's keyids.
    keyids = self.top_level_role_info[role]['keyids']

    #  Create a temp keystore directory.
    keystore_dir =\
        self.create_temp_keystore_directory(keystore_dicts=True)

    #  Create temp directory for config file.
    config_dir = self.make_temp_directory()

    #  Build config file.
    config_filepath = signerlib.build_config_file(config_dir, 365,
                                                  self.top_level_role_info)

    #  Create role's metadata.
    signable_meta = signerlib.generate_root_metadata(config_filepath, 8)


    # TESTS
    #  Test: normal case.
    signercli._sign_and_write_metadata(signable_meta, keyids, filename)

    #  Verify that the root meta file was created.
    self.assertTrue(os.path.exists(filename))

    Errors = (tuf.Error, tuf.FormatError)

    #  Test: invalid metadata.
    self.assertRaises(Errors, signercli._sign_and_write_metadata,
                      self.random_string(), keyids, filename)

    #  Test: invalid keyids
    invalid_keyids = self.random_string()
    self.assertRaises(Errors, signercli._sign_and_write_metadata,
                      signable_meta, invalid_keyids, filename)

    #  Test: invalid filename
    self.assertRaises(Errors, signercli._sign_and_write_metadata,
                      signable_meta, invalid_keyids, True)




  def test_4_change_password(self):

    # SETUP
    original_get_metadata_directory = signercli._get_metadata_directory
    original_prompt = signercli._prompt
    original_get_password = signercli._get_password
    
    #  Creating root and target metadata requires an expiration date to be set.
    #  Expiration date set to expires 100 seconds from the current time.
    expiration_date = tuf.formats.format_time(time.time()+100)
    expiration_date = expiration_date[0:expiration_date.rfind(' UTC')] 
    
    #  Create keystore and repo directories.
    keystore_dir = self.create_temp_keystore_directory()
    repo_dir = self.make_temp_directory()
    
    #  Create temp directory for config file.
    config_dir = self.make_temp_directory()

    #  Build a config file.
    config_filepath = signerlib.build_config_file(config_dir, 365,
        self.top_level_role_info)

    #  Create a temp metadata directory.
    meta_dir = self.make_temp_directory()

    #  Patch signercli._get_metadata_directory().
    self.mock_get_metadata_directory(directory=meta_dir)

    #  Patch signercli._prompt().
    self.mock_prompt(config_filepath)

    #  Patch '_get_password' method.
    self.get_passwords()
    
    signercli.make_root_metadata(keystore_dir)

    #  Create a directory containing target files.
    targets_dir, targets_paths =\
        self.make_temp_directory_with_data_files(directory=repo_dir)
   
    #  Mock method for signercli._prompt().
    self.make_metadata_mock_prompts(targ_dir=targets_dir,
                                    conf_path=config_filepath,
                                    expiration=expiration_date)
    
    signercli.make_targets_metadata(keystore_dir)
    
    test_keyid = self.rsa_keyids[0]
    self.mock_prompt(test_keyid)
    
    #  Specify old password and create a new password.
    old_password = self.rsa_passwords[test_keyid]
    new_password = self.random_string()

    #  Mock method for signercli._get_password()
    def _mock_get_password(msg, confirm=False, old_pw=old_password,
        new_pw=new_password):
      if msg.startswith('\nEnter the old password for the keyid: '):
        return old_pw
      else:
        return new_pw

    #  Patch signercli._get_password.
    signercli._get_password = _mock_get_password


    # TESTS
    #  Test: normal case.
    # Verify that the derived key is modified.  A new salt is generated, so
    # we cannot predict or verify a specific derived key corresponding for
    # the new password.  Save the derived key for 'test_keyid' and check that
    # is updated.
    old_derived_key = keystore._derived_keys[test_keyid]
    signercli.change_password(keystore_dir)

    #  Verify password change.
    self.assertNotEqual(keystore._derived_keys[test_keyid], old_derived_key)

    #  Test: non-existing keyid.
    keystore.clear_keystore()
    self.mock_prompt(self.random_string(15))
    self.assertRaises(tuf.RepositoryError, signercli.change_password,
                      keystore_dir)

    #  Restore the prompt input to existing keyid.
    self.mock_prompt(test_keyid)

    #  Test: non-existing old password.
    keystore.clear_keystore()
    old_password = self.random_string()
    self.assertRaises(tuf.RepositoryError, signercli.change_password,
                      keystore_dir)

    # RESTORE
    signercli._get_password = original_get_password
    signercli._prompt = original_prompt
    signercli._get_metadata_directory = original_get_metadata_directory




  def test_2_generate_rsa_key(self):

    # SETUP
    original_prompt = signercli._prompt
    original_get_password = signercli._get_password
    
    #  Method to patch signercli._get_password()
    def _mock_get_password(junk, confirm=False):
      return self.random_string()

    #  Patch signercli._get_password()
    signercli._get_password = _mock_get_password

    #  Create a temp keystore directory.
    keystore_dir = self.make_temp_directory()


    # TESTS
    #  Test: invalid rsa bits.
    self.mock_prompt(1024)
    self.assertRaises(tuf.RepositoryError, signercli.generate_rsa_key,
                      keystore_dir)
    #  Input appropriate number of rsa bits.
    self.mock_prompt(3072)

    #  Test: normal case.
    signercli.generate_rsa_key(keystore_dir)

    #  Was the key file added to the directory?
    self.assertTrue(os.listdir(keystore_dir))

    # RESTORE
    signercli._get_password = original_get_password
    signercli._prompt = original_prompt




  def test_4_dump_key(self):

    # SETUP
    original_get_metadata_directory = signercli._get_metadata_directory
    original_prompt = signercli._prompt
    original_get_password = signercli._get_password
    
    #  Creating root and target metadata requires an expiration date to be set.
    #  Expiration date set to expires 100 seconds from the current time.
    expiration_date = tuf.formats.format_time(time.time()+100)
    expiration_date = expiration_date[0:expiration_date.rfind(' UTC')] 
    
    #  Create keystore and repo directories.
    keystore_dir = self.create_temp_keystore_directory()
    repo_dir = self.make_temp_directory()
    
    #  Create temp directory for config file.
    config_dir = self.make_temp_directory()

    #  Build a config file.
    config_filepath = signerlib.build_config_file(config_dir, 365,
        self.top_level_role_info)

    #  Create a temp metadata directory.
    meta_dir = self.make_temp_directory()

    #  Patch signercli._get_metadata_directory().
    self.mock_get_metadata_directory(directory=meta_dir)

    #  Patch signercli._get_password().
    self.get_passwords()
    
    #  Patch signercli._prompt().
    self.mock_prompt(config_filepath)

    signercli.make_root_metadata(keystore_dir)
    
    #  Create a directory containing target files.
    targets_dir, targets_paths =\
        self.make_temp_directory_with_data_files(directory=repo_dir)
   
    #  Mock method for signercli._prompt().
    self.make_metadata_mock_prompts(targ_dir=targets_dir,
                                    conf_path=config_filepath,
                                    expiration=expiration_date)

    signercli.make_targets_metadata(keystore_dir)
    

    keyid = self.rsa_keyids[0]
    password = self.rsa_passwords[keyid]
    show_priv = 'private'


    #  Mock method for signercli._get_password().
    def _mock_get_password(msg):
      return password

    #  Mock method for signercli._prompt().
    def _mock_prompt(msg, junk):
       if msg.startswith('\nEnter the keyid'):
         return keyid
       else:
         return show_priv

    #  Patch signercli._get_password().
    signercli._get_password = _mock_get_password

    #  Patch signercli._prompt().
    signercli._prompt = _mock_prompt


    # TESTS
    #  Test: normal case.
    signercli.dump_key(keystore_dir)

    #  Test: incorrect password.
    saved_pw = password
    password = self.random_string()
    self.assertRaises(tuf.RepositoryError, signercli.dump_key,
                      keystore_dir)

    #  Restore the correct password.
    password = saved_pw

    #  Test: non-existing keyid.
    keyid = self.random_string()
    self.assertRaises(tuf.RepositoryError, signercli.dump_key,
                      keystore_dir)
    keyid = self.rsa_keyids[0]

    # RESTORE
    signercli._get_password = original_get_password
    signercli._prompt = original_prompt
    signercli._get_metadata_directory = original_get_metadata_directory




  def test_3_make_root_metadata(self):

    # SETUP
    original_get_metadata_directory = signercli._get_metadata_directory
    original_prompt = signercli._prompt
    original_get_password = signercli._get_password
    
    #  Create temp directory for config file.
    config_dir = self.make_temp_directory()

    #  Build a config file.
    config_filepath = signerlib.build_config_file(config_dir, 365,
        self.top_level_role_info)

    #  Create a temp metadata directory.
    meta_dir = self.make_temp_directory()

    #  Patch signercli._get_metadata_directory().
    self.mock_get_metadata_directory(directory=meta_dir)

    #  Patch signercli._prompt().
    self.mock_prompt(config_filepath)

    #  Patch signercli._get_password().
    self.get_passwords()

    #  Create keystore directory.
    keystore_dir = self.create_temp_keystore_directory()


    # TESTS
    #  Test: normal case.
    signercli.make_root_metadata(keystore_dir)

    #  Verify that the root metadata path was created.
    self.assertTrue(os.path.exists(os.path.join(meta_dir, 'root.txt')))

    #  Test: invalid config path.
    #  Clear keystore's dictionaries.
    keystore.clear_keystore()

    #  Supply a non-existing path to signercli._prompt().
    self.mock_prompt(self.random_path())
    self.assertRaises(tuf.RepositoryError, signercli.make_root_metadata,
                      keystore_dir)

    #  Re-patch signercli._prompt() with valid config path.
    self.mock_prompt(config_filepath)

    #  Test: incorrect 'root' passwords.
    #  Clear keystore's dictionaries.
    keystore.clear_keystore()
    keyids = self.top_level_role_info['root']['keyids']
    for keyid in keyids:
      saved_pw = self.rsa_passwords[keyid]
      self.rsa_passwords[keyid] = self.random_string()
      self.assertRaises(tuf.RepositoryError, signercli.make_root_metadata,
                        keystore_dir)
      self.rsa_passwords[keyid] = saved_pw

    # RESTORE
    signercli._get_password = original_get_password
    signercli._prompt = original_prompt
    signercli._get_metadata_directory = original_get_metadata_directory




  def test_3_make_targets_metadata(self):

    # SETUP
    original_get_metadata_directory = signercli._get_metadata_directory
    original_prompt = signercli._prompt
    original_get_password = signercli._get_password
    
    #  Creating target metadata requires an expiration date to be set.
    #  Expiration date set to expires 100 seconds from the current time.
    expiration_date = tuf.formats.format_time(time.time()+100)
    expiration_date = expiration_date[0:expiration_date.rfind(' UTC')] 

    #  Create a temp repository and metadata directories.
    repo_dir = self.make_temp_directory()
    meta_dir = self.make_temp_directory(directory=repo_dir)

    #  Create a directory containing target files.
    targets_dir, targets_paths =\
        self.make_temp_directory_with_data_files(directory=repo_dir)

    #  Create temp directory for config file.
    config_dir = self.make_temp_directory()

    #  Build a config file.
    config_filepath = signerlib.build_config_file(config_dir, 365,
                                                  self.top_level_role_info)

    #  Patch signercli._get_metadata_directory()
    self.mock_get_metadata_directory(directory=meta_dir)

    #  Patch signercli._get_password().  Used in _get_role_config_keyids()
    self.get_passwords()

    #  Create keystore directory.
    keystore_dir = self.create_temp_keystore_directory()

    #  Mock method for signercli._prompt().
    self.make_metadata_mock_prompts(targ_dir=targets_dir,
                                    conf_path=config_filepath,
                                    expiration=expiration_date)


    # TESTS
    #  Test: normal case.
    signercli.make_targets_metadata(keystore_dir)

    #  Verify that targets metadata file was created.
    self.assertTrue(os.path.exists(os.path.join(meta_dir, 'targets.txt')))

    #  Test: invalid targets path.
    #  Clear keystore's dictionaries.
    keystore.clear_keystore()

    #  Supply a non-existing targets directory.
    """
    self.make_metadata_mock_prompts(targ_dir=self.random_path(),
                                    conf_path=config_filepath,
                                    expiration=expiration_date)
    self.assertRaises(tuf.RepositoryError, signercli.make_targets_metadata,
                      keystore_dir)
    """

    #  Restore the targets directory.
    self.make_metadata_mock_prompts(targ_dir=targets_dir,
                                    conf_path=config_filepath,
                                    expiration=expiration_date)

    #  Test: invalid config path.
    #  Clear keystore's dictionaries.
    keystore.clear_keystore()

    #  Supply a non-existing config path.
    self.make_metadata_mock_prompts(targ_dir=targets_dir,
                                    conf_path=self.random_path(),
                                    expiration=expiration_date)
    self.assertRaises(tuf.RepositoryError, signercli.make_targets_metadata,
                      keystore_dir)

    #  Restore the config file path.
    self.make_metadata_mock_prompts(targ_dir=targets_dir,
                                    conf_path=config_filepath,
                                    expiration=expiration_date)

    #  Test: invalid expiration date.
    #  Clear keystore's dictionaries
    keystore.clear_keystore()

    #  Supply invalid expiration date.
    self.make_metadata_mock_prompts(targ_dir=targets_dir,
                                    conf_path=config_filepath,
                                    expiration=self.random_string())
    self.assertRaises(tuf.RepositoryError, signercli.make_targets_metadata,
                      keystore_dir)

    #  Restore the config file path.
    self.make_metadata_mock_prompts(targ_dir=targets_dir,
                                    conf_path=config_filepath,
                                    expiration=expiration_date)

    #  Test: incorrect 'targets' passwords.
    #  Clear keystore's dictionaries.
    keystore.clear_keystore()
    keyids = self.top_level_role_info['targets']['keyids']
    for keyid in keyids:
      saved_pw = self.rsa_passwords[keyid]
      self.rsa_passwords[keyid] = self.random_string()
      self.assertRaises(tuf.RepositoryError, signercli.make_targets_metadata,
                        keystore_dir)
      self.rsa_passwords[keyid] = saved_pw
    
    # RESTORE
    signercli._get_password = original_get_password
    signercli._prompt = original_prompt
    signercli._get_metadata_directory = original_get_metadata_directory




  def test_4_make_release_metadata(self):

    # SETUP
    original_get_metadata_directory = signercli._get_metadata_directory
    original_prompt = signercli._prompt
    original_get_password = signercli._get_password
    
    #  Creating release metadata requires an expiration date to be set.
    #  Expiration date set to expires 100 seconds from the current time.
    expiration_date = tuf.formats.format_time(time.time()+100)
    expiration_date = expiration_date[0:expiration_date.rfind(' UTC')] 
    
    #  In order to build release metadata file (release.txt),
    #  root and targets metadata files (root.txt, targets.txt)
    #  must exist in the metadata directory.
    #  Create temp directory for config file.
    config_dir = self.make_temp_directory()

    #  Build a config file.
    config_filepath = signerlib.build_config_file(config_dir, 365,
                                                  self.top_level_role_info)

    #  Create a temp repository and metadata directories.
    repo_dir = self.make_temp_directory()
    meta_dir = self.make_temp_directory(repo_dir)

    #  Create a directory containing target files.
    targets_dir, targets_paths = \
        self.make_temp_directory_with_data_files(directory=repo_dir)

    #  Patch signercli._get_metadata_directory().
    self.mock_get_metadata_directory(directory=meta_dir)

    #  Patch signercli._get_password().  Used in _get_role_config_keyids().
    self.get_passwords()

    #  Create keystore directory.
    keystore_dir = self.create_temp_keystore_directory()

    #  Mock method for signercli._prompt().
    self.make_metadata_mock_prompts(targ_dir=targets_dir,
                                    conf_path=config_filepath,
                                    expiration=expiration_date)


    # TESTS
    #  Test: no root.txt in the metadata dir.
    signercli.make_targets_metadata(keystore_dir)

    #  Verify that 'tuf.RepositoryError' is raised due to a missing root.txt.
    keystore.clear_keystore()
    self.assertTrue(os.path.exists(os.path.join(meta_dir, 'targets.txt')))
    self.assertRaises(tuf.RepositoryError, signercli.make_release_metadata,
                      keystore_dir)
    os.remove(os.path.join(meta_dir,'targets.txt'))
    keystore.clear_keystore()

    #  Test: no targets.txt in the metadatadir.
    signercli.make_root_metadata(keystore_dir)
    keystore.clear_keystore()

    #  Verify that 'tuf.RepositoryError' is raised due to a missing targets.txt.
    self.assertTrue(os.path.exists(os.path.join(meta_dir, 'root.txt')))
    self.assertRaises(tuf.RepositoryError, signercli.make_release_metadata,
                      keystore_dir)
    os.remove(os.path.join(meta_dir,'root.txt'))
    keystore.clear_keystore()

    #  Test: normal case.
    signercli.make_root_metadata(keystore_dir)
    keystore.clear_keystore()
    signercli.make_targets_metadata(keystore_dir)
    keystore.clear_keystore()
    signercli.make_release_metadata(keystore_dir)
    keystore.clear_keystore()

    #  Verify if the root, targets and release meta files were created.
    self.assertTrue(os.path.exists(os.path.join(meta_dir, 'root.txt')))
    self.assertTrue(os.path.exists(os.path.join(meta_dir, 'targets.txt')))
    self.assertTrue(os.path.exists(os.path.join(meta_dir, 'release.txt')))

    #  Test: invalid config path.
    #  Supply a non-existing config file path.
    self.make_metadata_mock_prompts(targ_dir=targets_dir,
        conf_path=self.random_path(), expiration=expiration_date)
    self.assertRaises(tuf.RepositoryError, signercli.make_release_metadata,
        keystore_dir)

    #  Restore the config file path.
    self.make_metadata_mock_prompts(targ_dir=targets_dir,
        conf_path=config_filepath, expiration=expiration_date)

    #  Test: incorrect 'release' passwords.
    #  Clear keystore's dictionaries.
    keystore.clear_keystore()
    keyids = self.top_level_role_info['release']['keyids']
    for keyid in keyids:
      saved_pw = self.rsa_passwords[keyid]
      self.rsa_passwords[keyid] = self.random_string()
      self.assertRaises(tuf.RepositoryError, signercli.make_release_metadata,
          keystore_dir)
      self.rsa_passwords[keyid] = saved_pw

    # RESTORE
    signercli._get_password = original_get_password
    signercli._prompt = original_prompt
    signercli._get_metadata_directory = original_get_metadata_directory




  def test_5_make_timestamp_metadata(self):

    # SETUP
    original_get_metadata_directory = signercli._get_metadata_directory
    original_prompt = signercli._prompt
    original_get_password = signercli._get_password

    #  Creating the top-level metadata requires an expiration date to be set.
    #  Expiration date set to expires 100 seconds from the current time.
    expiration_date = tuf.formats.format_time(time.time()+100)
    expiration_date = expiration_date[0:expiration_date.rfind(' UTC')] 
    
    #  In order to build timestamp metadata file (timestamp.txt),
    #  root, targets and release metadata files (root.txt, targets.txt
    #  release.txt) must exist in the metadata directory.
    #  Create temp directory for config file.
    config_dir = self.make_temp_directory()

    #  Build a config file.
    config_filepath = signerlib.build_config_file(config_dir, 365,
                                                  self.top_level_role_info)

    #  Create a temp repository and metadata directories.
    repo_dir = self.make_temp_directory()
    meta_dir = self.make_temp_directory(repo_dir)

    #  Create a directory containing target files.
    targets_dir, targets_paths = \
        self.make_temp_directory_with_data_files(directory=repo_dir)

    #  Patch signercli._get_metadata_directory().
    self.mock_get_metadata_directory(directory=meta_dir)

    #  Patch signercli._get_password().  Used in _get_role_config_keyids().
    self.get_passwords()

    #  Create keystore directory.
    keystore_dir = self.create_temp_keystore_directory()

    #  Mock method for signercli._prompt().
    self.make_metadata_mock_prompts(targ_dir=targets_dir,
                                    conf_path=config_filepath,
                                    expiration=expiration_date)


    # TESTS
    #  Test: no root.txt in the metadata dir.
    signercli.make_targets_metadata(keystore_dir)

    #  Verify if the targets metadata file was created.
    keystore.clear_keystore()
    self.assertTrue(os.path.exists(os.path.join(meta_dir, 'targets.txt')))
    self.assertRaises(tuf.RepositoryError, signercli.make_timestamp_metadata,
                      keystore_dir)
    os.remove(os.path.join(meta_dir,'targets.txt'))
    keystore.clear_keystore()

    #  Test: no targets.txt in the metadatadir.
    signercli.make_root_metadata(keystore_dir)

    #  Verify if the root metadata file was created.
    keystore.clear_keystore()
    self.assertTrue(os.path.exists(os.path.join(meta_dir, 'root.txt')))
    self.assertRaises(tuf.RepositoryError, signercli.make_timestamp_metadata,
                      keystore_dir)
    os.remove(os.path.join(meta_dir,'root.txt'))
    keystore.clear_keystore()

    #  Test: no release.txt in the metadatadir.
    signercli.make_root_metadata(keystore_dir)
    keystore.clear_keystore()
    signercli.make_targets_metadata(keystore_dir)
    keystore.clear_keystore()

    #  Verify that 'tuf.Repository' is raised due to a missing release.txt.
    self.assertTrue(os.path.exists(os.path.join(meta_dir, 'root.txt')))
    self.assertTrue(os.path.exists(os.path.join(meta_dir, 'targets.txt')))
    self.assertRaises(tuf.RepositoryError, signercli.make_timestamp_metadata,
                      keystore_dir)
    os.remove(os.path.join(meta_dir,'root.txt'))
    os.remove(os.path.join(meta_dir,'targets.txt'))
    keystore.clear_keystore()

    #  Test: normal case.
    signercli.make_root_metadata(keystore_dir)
    keystore.clear_keystore()
    signercli.make_targets_metadata(keystore_dir)
    keystore.clear_keystore()
    signercli.make_release_metadata(keystore_dir)
    keystore.clear_keystore()
    signercli.make_timestamp_metadata(keystore_dir)
    keystore.clear_keystore()

    #  Verify if the root, targets and release metadata files were created.
    self.assertTrue(os.path.exists(os.path.join(meta_dir, 'root.txt')))
    self.assertTrue(os.path.exists(os.path.join(meta_dir, 'targets.txt')))
    self.assertTrue(os.path.exists(os.path.join(meta_dir, 'release.txt')))
    self.assertTrue(os.path.exists(os.path.join(meta_dir, 'timestamp.txt')))

    #  Test: invalid config path.
    #  Supply a non-existing config file path.
    self.make_metadata_mock_prompts(targ_dir=targets_dir,
                                    conf_path=self.random_path(),
                                    expiration=expiration_date)
    self.assertRaises(tuf.RepositoryError,
                      signercli.make_release_metadata, keystore_dir)

    #  Restore the config file path.
    self.make_metadata_mock_prompts(targ_dir=targets_dir,
                                    conf_path=config_filepath,
                                    expiration=expiration_date)

    #  Test: incorrect 'release' passwords.

    #  Clear keystore's dictionaries.
    keystore.clear_keystore()

    keyids = self.top_level_role_info['release']['keyids']
    for keyid in keyids:
      saved_pw = self.rsa_passwords[keyid]
      self.rsa_passwords[keyid] = self.random_string()
      self.assertRaises(tuf.RepositoryError,
                        signercli.make_release_metadata, keystore_dir)
      self.rsa_passwords[keyid] = saved_pw

    # RESTORE
    signercli._get_password = original_get_password
    signercli._get_metadata_directory = original_get_metadata_directory




  def test_6_sign_metadata_file(self):

    # SETUP
    original_get_metadata_directory = signercli._get_metadata_directory
    original_prompt = signercli._prompt
    original_get_password = signercli._get_password
    
    #  Creating the top-level metadata requires an expiration date to be set.
    #  Expiration date set to expires 100 seconds from the current time.
    expiration_date = tuf.formats.format_time(time.time()+100)
    expiration_date = expiration_date[0:expiration_date.rfind(' UTC')] 
    
    #  To test this method, an RSA key will be created with
    #  a password in addition to the existing RSA keys.
    #  Create temp directory for config file.
    config_dir = self.make_temp_directory()

    #  Build a config file.
    config_filepath = signerlib.build_config_file(config_dir, 365,
                                                  self.top_level_role_info)

    #  Create a temp repository and metadata directories.
    repo_dir = self.make_temp_directory()
    meta_dir = self.make_temp_directory(repo_dir)

    #  Create a directory containing target files.
    targets_dir, targets_paths = \
        self.make_temp_directory_with_data_files(directory=repo_dir)

    #  Patch signercli._get_metadata_directory().
    self.mock_get_metadata_directory(directory=meta_dir)

    #  Patch signercli._get_password().  Used in _get_role_config_keyids().
    self.get_passwords()

    #  Create keystore directory.
    keystore_dir = self.create_temp_keystore_directory()

    #  Mock method for signercli._prompt().
    self.make_metadata_mock_prompts(targ_dir=targets_dir,
                                    conf_path=config_filepath,
                                    expiration=expiration_date)

    #  Create metadata files.
    signercli.make_root_metadata(keystore_dir)
    keystore.clear_keystore()
    signercli.make_targets_metadata(keystore_dir)
    keystore.clear_keystore()
    signercli.make_release_metadata(keystore_dir)
    keystore.clear_keystore()
    signercli.make_timestamp_metadata(keystore_dir)
    keystore.clear_keystore()

    #  Verify if the root, targets and release meta files were created.
    root_meta_filepath = os.path.join(meta_dir, 'root.txt')
    targets_meta_filepath = os.path.join(meta_dir, 'targets.txt')
    release_meta_filepath = os.path.join(meta_dir, 'release.txt')
    timestamp_meta_filepath = os.path.join(meta_dir, 'timestamp.txt')

    self.assertTrue(os.path.exists(root_meta_filepath))
    self.assertTrue(os.path.exists(targets_meta_filepath))
    self.assertTrue(os.path.exists(release_meta_filepath))
    self.assertTrue(os.path.exists(timestamp_meta_filepath))


    #  Create a new RSA key, indicate metadata filename.
    new_keyid = self.generate_rsakey()
    meta_filename = targets_meta_filepath

    #  Create keystore directory.  New key is untouched.
    keystore_dir = self.create_temp_keystore_directory(keystore_dicts=True)

    #  List of keyids to be returned by _get_keyids()
    signing_keyids = []

    #  Method to patch signercli._get_keyids()
    def _mock_get_keyids(junk):
      return signing_keyids

    #  Method to patch signercli._prompt().
    def _mock_prompt(msg, junk):
      return meta_filename

    #  Patch signercli._get_keyids()
    signercli._get_keyids = _mock_get_keyids

    #  Patch signercli._prompt().
    signercli._prompt = _mock_prompt


    # TESTS
    #  Test: no loaded keyids.
    self.assertRaises(tuf.RepositoryError,
                      signercli.sign_metadata_file, keystore_dir)

    #  Load new keyid.
    signing_keyids = [new_keyid]

    #  Test: normal case.
    signercli.sign_metadata_file(keystore_dir)

    #  Verify the change.
    self.assertTrue(os.path.exists(targets_meta_filepath))

    #  Load targets metadata from the file ('targets.txt').
    targets_metadata = tuf.util.load_json_file(targets_meta_filepath)
    keyid_exists = False
    for signature in targets_metadata['signatures']:
      if new_keyid == signature['keyid']:
        keyid_exists = True
        break

    self.assertTrue(keyid_exists)

    # RESTORE
    signercli._get_password = original_get_password
    signercli._prompt = original_prompt
    signercli._get_metadata_directory = original_get_metadata_directory




  def test_7_make_delegation(self):
    
    # SETUP
    original_get_metadata_directory = signercli._get_metadata_directory
    original_prompt = signercli._prompt
    original_get_password = signercli._get_password

    #  Creating the top-level metadata requires an expiration date to be set.
    #  Expiration date set to expires 100 seconds from the current time.
    expiration_date = tuf.formats.format_time(time.time()+100)
    expiration_date = expiration_date[0:expiration_date.rfind(' UTC')] 

    #  Create a temp repository and metadata directories.
    repo_dir = self.make_temp_directory()
    meta_dir = self.make_temp_directory(directory=repo_dir)

    #  Create targets directories.
    targets_dir, targets_paths =\
        self.make_temp_directory_with_data_files(directory=repo_dir)
    delegated_targets_dir = os.path.join(targets_dir,'targets',
                                         'delegated_level1')

    #  Assign parent role and name of the delegated role.
    parent_role = 'targets'
    delegated_role = 'delegated_role_1'

    #  Create couple new RSA keys for delegation levels 1 and 2.
    new_keyid_1 = self.generate_rsakey()
    new_keyid_2 = self.generate_rsakey()

    #  Create temp directory for config file.
    config_dir = self.make_temp_directory()

    #  Build a config file.
    config_filepath = signerlib.build_config_file(config_dir, 365,
                                                  self.top_level_role_info)

    #  Patch signercli._get_metadata_directory().
    self.mock_get_metadata_directory(directory=meta_dir)

    #  Patch signercli._get_password().  Get passwords for parent's keyids.
    self.get_passwords()

    #  Create keystore directory.
    keystore_dir = self.create_temp_keystore_directory()

    #  Mock method for signercli._prompt() to generate targets.txt file.
    self.make_metadata_mock_prompts(targ_dir=targets_dir,
                                    conf_path=config_filepath,
                                    expiration=expiration_date)

    #  List of keyids to be returned by _get_keyids()
    signing_keyids = [new_keyid_1]

    #  Load keystore.
    load_keystore = keystore.load_keystore_from_keyfiles

    #  Build the root metadata file (root.txt).
    signercli.make_root_metadata(keystore_dir)
    
    #  Build targets metadata file (targets.txt).
    signercli.make_targets_metadata(keystore_dir)

    #  Clear kestore's dictionaries.
    keystore.clear_keystore()

    #  Mock method for signercli._prompt().
    def _mock_prompt(msg, junk):
      if msg.startswith('\nThe paths entered'):
        return delegated_targets_dir
      elif msg.startswith('\nChoose and enter the parent'):
        return parent_role
      elif msg.startswith('\nEnter the delegated role\'s name: '):
        return delegated_role
      elif msg.startswith('\nCurrent time:'):
        return expiration_date
      else:
        error_msg = ('Prompt: '+'\''+msg+'\''+
                     ' did not match any predefined mock prompts.')
        self.fail(error_msg)

    #  Mock method for signercli._get_password().
    def _mock_get_password(msg):
      for keyid in self.rsa_keyids:
        if msg.endswith('('+keyid+'): '):
          return self.rsa_passwords[keyid]

    #  Method to patch signercli._get_keyids()
    def _mock_get_keyids(junk):
      if signing_keyids:
        for keyid in signing_keyids:
          password = self.rsa_passwords[keyid]
          #  Load the keyfile.
          load_keystore(keystore_dir, [keyid], [password])
      return signing_keyids

    #  Patch signercli._prompt().
    signercli._prompt = _mock_prompt

    #  Patch signercli._get_password().
    signercli._get_password = _mock_get_password

    #  Patch signercli._get_keyids().
    signercli._get_keyids = _mock_get_keyids


    # TESTS
    #  Test: invalid parent role.
    #  Assign a non-existing parent role.
    parent_role = self.random_string()
    self.assertRaises(tuf.RepositoryError, signercli.make_delegation,
                      keystore_dir)

    #  Restore parent role.
    parent_role = 'targets'

    #  Test: invalid password(s) for parent's keyids.
    keystore.clear_keystore()
    parent_keyids = self.top_level_role_info[parent_role]['keyids']
    for keyid in parent_keyids:
      saved_pw = self.rsa_passwords[keyid]
      self.rsa_passwords[keyid] = self.random_string()
      self.assertRaises(tuf.RepositoryError, signercli.make_delegation,
                        keystore_dir)
      self.rsa_passwords[keyid] = saved_pw

    #  Test: delegated_keyids == 0.
    keystore.clear_keystore()

    #  Load 0 keyids (== 0).
    signing_keyids = []
    self.assertRaises(tuf.RepositoryError, signercli.make_delegation,
                      keystore_dir)
    keystore.clear_keystore()

    #  Restore signing_keyids (== 1).
    signing_keyids = [new_keyid_1]

    #  Test: normal case 1.
    #  Testing first level delegation.
    signercli.make_delegation(keystore_dir)

    #  Verify delegated metadata file exists.
    delegated_meta_file = os.path.join(meta_dir, parent_role,
                                       delegated_role+'.txt')
    self.assertTrue(os.path.exists(delegated_meta_file))

    #  Test: normal case 2.
    #  Testing second level delegation.
    keystore.clear_keystore()

    #  Make necessary adjustments for the test.
    signing_keyids = [new_keyid_2]
    delegated_targets_dir = os.path.join(delegated_targets_dir,
                                         'delegated_level2')
    parent_role = os.path.join(parent_role, delegated_role)
    delegated_role = 'delegated_role_2'

    signercli.make_delegation(keystore_dir)

    #  Verify delegated metadata file exists.
    delegated_meta_file = os.path.join(meta_dir, parent_role,
                                       delegated_role+'.txt')
    self.assertTrue(os.path.exists(delegated_meta_file))

    # Test: normal case 3.
    #  Testing delegated_keyids > 1.
    #  Ensure make_delegation() sets 'threshold' = 2 for the delegated role.
    keystore.clear_keystore()

    #  Populate 'signing_keyids' with multiple keys, so the
    #  the delegated metadata is set to a threshold > 1.
    signing_keyids = [new_keyid_1, new_keyid_2]
    parent_role = 'targets'
    delegated_role = 'delegated_role_1'
    
    signercli.make_delegation(keystore_dir)

    #  Verify delegated metadata file exists.
    delegated_meta_file = os.path.join(meta_dir, parent_role,
                                       delegated_role+'.txt')
    self.assertTrue(os.path.exists(delegated_meta_file))

    #  Verify the threshold value of the delegated metadata file
    #  by inspecting the parent role's 'delegations' field.
    parent_role_file = os.path.join(meta_dir, parent_role+'.txt')
    signable = signerlib.read_metadata_file(parent_role_file)
    delegated_rolename = parent_role+'/'+delegated_role

    roles = signable['signed']['delegations']['roles']
    role_index = signerlib.find_delegated_role(roles, delegated_rolename)
    self.assertIsNotNone(role_index)
    role = roles[role_index]

    threshold = role['threshold']
    self.assertTrue(threshold == 2)

    # RESTORE
    signercli._get_password = original_get_password
    signercli._prompt = original_prompt
    signercli._get_metadata_directory = original_get_metadata_directory


def setUpModule():
  # setUpModule() is called before any test cases run. 
  # Populating 'rsa_keystore' and 'rsa_passwords' dictionaries.
  # We will need them when creating keystore directories.
  unittest_toolbox.Modified_TestCase.bind_keys_to_roles()


def tearDownModule():
  # tearDownModule() is called after all the test cases have run.
  unittest_toolbox.Modified_TestCase.clear_toolbox()


if __name__ == '__main__':
  unittest.main()
