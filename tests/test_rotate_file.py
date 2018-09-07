#!/usr/bin/env python

# Copyright 2016 - 2017, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
<Program Name>
  test_rotate_file.py

<Author>
  Marina Moore.

<Started>
  August 30, 2018.

<Copyright>
  See LICENSE-MIT OR LICENSE for licensing information.

<Purpose>
"""

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import os
import time
import shutil
import tempfile
import logging
import random
import subprocess
import unittest

import tuf
import tuf.log
import tuf.exceptions
import tuf.roledb
import tuf.keydb
import tuf.repository_tool as repo_tool
import tuf.unittest_toolbox as unittest_toolbox
import tuf.client.updater as updater

logger = logging.getLogger('tuf.test_rotation_file')
repo_tool.disable_console_log_messages()


class TestRotateFile(unittest_toolbox.Modified_TestCase):

  @classmethod
  def setUpClass(cls):
    # setUpClass() is called before tests in an individual class are executed.

    # Create a temporary directory to store the repository, metadata, and target
    # files.  'temporary_directory' must be deleted in TearDownModule() so that
    # temporary files are always removed, even when exceptions occur.
    cls.temporary_directory = tempfile.mkdtemp(dir=os.getcwd())

    # Launch a SimpleHTTPServer (serves files in the current directory).  Test
    # cases will request metadata and target files that have been pre-generated
    # in 'tuf/tests/repository_data', which will be served by the
    # SimpleHTTPServer launched here.  The test cases of
    # 'test_key_revocation.py' assume the pre-generated metadata files have a
    # specific structure, such as a delegated role, three target files, five
    # key files, etc.
    cls.SERVER_PORT = random.randint(30000, 45000)
    command = ['python', 'simple_server.py', str(cls.SERVER_PORT)]
    cls.server_process = subprocess.Popen(command, stderr=subprocess.PIPE)
    logger.info('\n\tServer process started.')
    logger.info('\tServer process id: '+str(cls.server_process.pid))
    logger.info('\tServing on port: '+str(cls.SERVER_PORT))
    cls.url = 'http://localhost:'+str(cls.SERVER_PORT) + os.path.sep

    # NOTE: Following error is raised if a delay is not applied:
    # <urlopen error [Errno 111] Connection refused>
    time.sleep(1)



  @classmethod
  def tearDownClass(cls):
    # tearDownModule() is called after all the tests have run.
    # http://docs.python.org/2/library/unittest.html#class-and-module-fixtures

    # Remove the temporary repository directory, which should contain all the
    # metadata, targets, and key files generated for the test cases.
    shutil.rmtree(cls.temporary_directory)

    # Kill the SimpleHTTPServer process.
    if cls.server_process.returncode is None:
      logger.info('\tServer process '+str(cls.server_process.pid)+' terminated.')
      cls.server_process.kill()



  def setUp(self):
    # We are inheriting from custom class.
    unittest_toolbox.Modified_TestCase.setUp(self)

    self.repository_name = 'test_repository1'

    # Copy the original repository files provided in the test folder so that
    # any modifications made to repository files are restricted to the copies.
    # The 'repository_data' directory is expected to exist in 'tuf.tests/'.
    original_repository_files = os.path.join(os.getcwd(), 'repository_data')
    temporary_repository_root = \
      self.make_temp_directory(directory=self.temporary_directory)

    # The original repository, keystore, and client directories will be copied
    # for each test case.
    original_repository = os.path.join(original_repository_files, 'repository')
    original_keystore = os.path.join(original_repository_files, 'keystore')
    original_client = os.path.join(original_repository_files, 'client')

    # Save references to the often-needed client repository directories.
    # Test cases need these references to access metadata and target files.
    self.repository_directory = \
      os.path.join(temporary_repository_root, 'repository')
    self.keystore_directory = \
      os.path.join(temporary_repository_root, 'keystore')
    self.client_directory = os.path.join(temporary_repository_root, 'client')
    self.client_metadata = os.path.join(self.client_directory,
        self.repository_name, 'metadata')
    self.client_metadata_current = os.path.join(self.client_metadata, 'current')
    self.client_metadata_previous = os.path.join(self.client_metadata, 'previous')

    # Copy the original 'repository', 'client', and 'keystore' directories
    # to the temporary repository the test cases can use.
    shutil.copytree(original_repository, self.repository_directory)
    shutil.copytree(original_client, self.client_directory)
    shutil.copytree(original_keystore, self.keystore_directory)

    # 'path/to/tmp/repository' -> 'localhost:8001/tmp/repository'.
    repository_basepath = self.repository_directory[len(os.getcwd()):]
    url_prefix = \
      'http://localhost:' + str(self.SERVER_PORT) + repository_basepath

    # Setting 'tuf.settings.repository_directory' with the temporary client
    # directory copied from the original repository files.
    tuf.settings.repositories_directory = self.client_directory

    self.repository_mirrors = {'mirror1': {'url_prefix': url_prefix,
                                           'metadata_path': 'metadata',
                                           'targets_path': 'targets',
                                           'confined_target_dirs': ['']}}

    # Creating repository instance.  The test cases will use this client
    # updater to refresh metadata, fetch target files, etc.
    self.repository_updater = updater.Updater(self.repository_name,
                                              self.repository_mirrors)

    # Metadata role keys are needed by the test cases to make changes to the
    # repository (e.g., adding a new target file to 'targets.json' and then
    # requesting a refresh()).
    self.role_keys = _load_role_keys(self.keystore_directory)



  def tearDown(self):
    # We are inheriting from custom class.
    unittest_toolbox.Modified_TestCase.tearDown(self)
    tuf.roledb.clear_roledb(clear_all=True)
    tuf.keydb.clear_keydb(clear_all=True)



  # UNIT TESTS.
  def test_targets_key_rotation(self):
    # First verify that the Targets role is properly signed.  Calling
    # refresh() should not raise an exception.
    self.repository_updater.refresh()

    # There should only be one key for Targets.  Store the keyid to later
    # verify that it has been revoked.
    targets_roleinfo = tuf.roledb.get_roleinfo('targets', self.repository_name)
    targets_keyid = targets_roleinfo['keyids']
    self.assertEqual(len(targets_keyid), 1)

    #add rotate files
    repository = repo_tool.load_repository(self.repository_directory)
    #make new key the timestamp key for testing and keep the threshold at 1
    new_keyids = [self.role_keys['timestamp']['public']['keyid']]
    new_threshold = 1
    rotate_file = repository.targets.add_rotate_file(targets_roleinfo['keyids'], targets_roleinfo['threshold'], new_keyids, new_threshold, [self.role_keys['targets']['private']])

    #should not need to rewrite or update anything else

    # The client performs a refresh of top-level metadata to get the latest
    # changes.
    self.repository_updater.refresh()

    #this is signed with the old key, should no longer be valid
    self.assertFalse(tuf.sig.verify(rotate_file, 'targets', self.repository_name, targets_roleinfo['threshold'], targets_roleinfo['keyids']))



  def test_rotation_cycle(self):
    # First verify that the Targets role is properly signed.  Calling
    # refresh() should not raise an exception.
    self.repository_updater.refresh()

    # There should only be one key for Targets.  Store the keyid to later
    # verify that it has been revoked.
    targets_roleinfo = tuf.roledb.get_roleinfo('targets', self.repository_name)
    targets_keyid = targets_roleinfo['keyids']
    self.assertEqual(len(targets_keyid), 1)

    #add rotate files creating a cycle
    repository = repo_tool.load_repository(self.repository_directory)
    #make new key the timestamp key for testing and keep the threshold at 1
    new_keyids = [self.role_keys['timestamp']['public']['keyid']]
    new_threshold = 1
    rotate_file = repository.targets.add_rotate_file(targets_roleinfo['keyids'], targets_roleinfo['threshold'], new_keyids, new_threshold, [self.role_keys['targets']['private']])
    repository.targets.add_rotate_file(new_keyids, new_threshold, targets_roleinfo['keyids'], targets_roleinfo['threshold'], [self.role_keys['timestamp']['private']])

    #should not need to rewrite or update anything else

    # The client performs a refresh of top-level metadata to get the latest
    # changes.
    self.repository_updater.refresh()

    #ensure that is finds the cycle
    self.assertRaises(tuf.exceptions.InvalidKeyError, tuf.sig.verify, rotate_file, 'targets', self.repository_name, targets_roleinfo['threshold'], targets_roleinfo['keyids'])



  def test_rotate_file_invalid_role(self):
    # First verify that the Targets role is properly signed.  Calling
    # refresh() should not raise an exception.
    self.repository_updater.refresh()

    # There should only be one key for Targets.  Store the keyid to later
    # verify that it has been revoked.
    targets_roleinfo = tuf.roledb.get_roleinfo('targets', self.repository_name)
    targets_keyid = targets_roleinfo['keyids']
    self.assertEqual(len(targets_keyid), 1)

    #add rotate file
    repository = repo_tool.load_repository(self.repository_directory)
    #make new key the timestamp key for testing and keep the threshold at 1
    new_keyids = [self.role_keys['timestamp']['public']['keyid']]
    new_threshold = 1
    rotate_file = repository.targets.add_rotate_file(targets_roleinfo['keyids'], targets_roleinfo['threshold'], new_keyids, new_threshold, [self.role_keys['targets']['private']], "invalid_rolename")

    #should not need to rewrite or update anything else

    # The client performs a refresh of top-level metadata to get the latest
    # changes.
    self.repository_updater.refresh()

    self.assertRaises(tuf.exceptions.InvalidRotateFileError, tuf.sig.verify, rotate_file, 'targets', self.repository_name, targets_roleinfo['threshold'], targets_roleinfo['keyids'])



def _load_role_keys(keystore_directory):

  # Populating 'self.role_keys' by importing the required public and private
  # keys of 'tuf/tests/repository_data/'.  The role keys are needed when
  # modifying the remote repository used by the test cases in this unit test.
  # The pre-generated key files in 'repository_data/keystore' are all encrypted with
  # a 'password' passphrase.
  EXPECTED_KEYFILE_PASSWORD = 'password'

  # Store and return the cryptography keys of the top-level roles, including 1
  # delegated role.
  role_keys = {}

  root_key_file = os.path.join(keystore_directory, 'root_key')
  targets_key_file = os.path.join(keystore_directory, 'targets_key')
  snapshot_key_file = os.path.join(keystore_directory, 'snapshot_key')
  timestamp_key_file = os.path.join(keystore_directory, 'timestamp_key')
  delegation_key_file = os.path.join(keystore_directory, 'delegation_key')

  role_keys = {'root': {}, 'targets': {}, 'snapshot': {}, 'timestamp': {},
               'role1': {}}

  # Import the top-level and delegated role public keys.
  role_keys['root']['public'] = \
    repo_tool.import_rsa_publickey_from_file(root_key_file+'.pub')
  role_keys['targets']['public'] = \
    repo_tool.import_ed25519_publickey_from_file(targets_key_file + '.pub')
  role_keys['snapshot']['public'] = \
    repo_tool.import_ed25519_publickey_from_file(snapshot_key_file + '.pub')
  role_keys['timestamp']['public'] = \
      repo_tool.import_ed25519_publickey_from_file(timestamp_key_file + '.pub')
  role_keys['role1']['public'] = \
      repo_tool.import_ed25519_publickey_from_file(delegation_key_file + '.pub')

  # Import the private keys of the top-level and delegated roles.
  role_keys['root']['private'] = \
    repo_tool.import_rsa_privatekey_from_file(root_key_file,
                                              EXPECTED_KEYFILE_PASSWORD)
  role_keys['targets']['private'] = \
    repo_tool.import_ed25519_privatekey_from_file(targets_key_file,
                                              EXPECTED_KEYFILE_PASSWORD)
  role_keys['snapshot']['private'] = \
    repo_tool.import_ed25519_privatekey_from_file(snapshot_key_file,
                                              EXPECTED_KEYFILE_PASSWORD)
  role_keys['timestamp']['private'] = \
    repo_tool.import_ed25519_privatekey_from_file(timestamp_key_file,
                                              EXPECTED_KEYFILE_PASSWORD)
  role_keys['role1']['private'] = \
    repo_tool.import_ed25519_privatekey_from_file(delegation_key_file,
                                              EXPECTED_KEYFILE_PASSWORD)

  return role_keys



if __name__ == '__main__':
  unittest.main()
