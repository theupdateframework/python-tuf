#!/usr/bin/env python

# Copyright 2016 - 2017, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
<Program Name>
  test_updater_root_rotation_integration.py

<Author>
  Evan Cordell.

<Started>
  August 8, 2016.

<Copyright>
  See LICENSE-MIT OR LICENSE for licensing information.

<Purpose>
  'test_updater_root_rotation.py' provides a collection of methods that test
  root key rotation in the example client.

<Methodology>
  Test cases here should follow a specific order (i.e., independent methods are
  tested before dependent methods). More accurately, least dependent methods
  are tested before most dependent methods.  There is no reason to rewrite or
  construct other methods that replicate already-tested methods solely for
  testing purposes.  This is possible because the 'unittest.TestCase' class
  guarantees the order of unit tests.  The 'test_something_A' method would
  be tested before 'test_something_B'.  To ensure the expected order of tests,
  a number is placed after 'test' and before methods name like so:
  'test_1_check_directory'.  The number is a measure of dependence, where 1 is
  less dependent than 2.
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
import copy
import tempfile
import logging
import random
import subprocess
import sys
import unittest
import filecmp

import tuf
import tuf.log
import tuf.keydb
import tuf.roledb
import tuf.exceptions
import tuf.repository_tool as repo_tool
import tuf.unittest_toolbox as unittest_toolbox
import tuf.client.updater as updater
import tuf.settings

import securesystemslib
import six

logger = logging.getLogger(__name__)
repo_tool.disable_console_log_messages()


class TestUpdater(unittest_toolbox.Modified_TestCase):

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
    # SimpleHTTPServer launched here.  The test cases of 'test_updater.py'
    # assume the pre-generated metadata files have a specific structure, such
    # as a delegated role 'targets/role1', three target files, five key files,
    # etc.
    cls.SERVER_PORT = random.randint(30000, 45000)
    command = ['python', 'simple_server.py', str(cls.SERVER_PORT)]
    cls.server_process = subprocess.Popen(command)
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
      logger.info('\tServer process ' + str(cls.server_process.pid) + ' terminated.')
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

    # Creating a repository instance.  The test cases will use this client
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
  def test_root_rotation(self):
    repository = repo_tool.load_repository(self.repository_directory)
    repository.root.threshold = 2

    repository.snapshot.load_signing_key(self.role_keys['snapshot']['private'])
    repository.timestamp.load_signing_key(self.role_keys['timestamp']['private'])

    # Errors, not enough signing keys to satisfy root's threshold.
    self.assertRaises(tuf.exceptions.UnsignedMetadataError, repository.writeall)

    repository.root.add_verification_key(self.role_keys['role1']['public'])
    repository.root.load_signing_key(self.role_keys['root']['private'])
    repository.root.load_signing_key(self.role_keys['role1']['private'])
    repository.writeall()

    repository.root.add_verification_key(self.role_keys['snapshot']['public'])
    repository.root.load_signing_key(self.role_keys['snapshot']['private'])
    repository.root.threshold = 3
    repository.writeall()

    # Move the staged metadata to the "live" metadata.
    shutil.rmtree(os.path.join(self.repository_directory, 'metadata'))
    shutil.copytree(os.path.join(self.repository_directory, 'metadata.staged'),
                    os.path.join(self.repository_directory, 'metadata'))
    self.repository_updater.refresh()



  def test_root_rotation_full(self):
    """Test that a client whose root is outdated by multiple versions and who
    has none of the latest nor next-to-latest root keys can still update and
    does so by incrementally verifying all roots until the most recent one. """
    # Load initial repository with 1.root.json == root.json, signed by "root"
    # key. This is the root.json that is already on the client.
    repository = repo_tool.load_repository(self.repository_directory)

    # 1st rotation: 1.root.json --> 2.root.json
    # 2.root.json will be signed by previous "root" key and by new "root2" key
    repository.root.load_signing_key(self.role_keys['root']['private'])
    repository.root.add_verification_key(self.role_keys['root2']['public'])
    repository.root.load_signing_key(self.role_keys['root2']['private'])
    repository.writeall()

    # 2nd rotation: 2.root.json --> 3.root.json
    # 3.root.json will be signed by previous "root2" key and by new "root3" key
    repository.root.unload_signing_key(self.role_keys['root']['private'])
    repository.root.remove_verification_key(self.role_keys['root']['public'])
    repository.root.add_verification_key(self.role_keys['root3']['public'])
    repository.root.load_signing_key(self.role_keys['root3']['private'])
    repository.writeall()

    # Move staged metadata to "live" metadata
    shutil.rmtree(os.path.join(self.repository_directory, 'metadata'))
    shutil.copytree(os.path.join(self.repository_directory, 'metadata.staged'),
                    os.path.join(self.repository_directory, 'metadata'))

    # Update on client 1.root.json --> 2.root.json --> 3.root.json
    self.repository_updater.refresh()

    # Assert that client updated to the latest root from the repository
    self.assertTrue(filecmp.cmp(
      os.path.join(self.repository_directory, 'metadata', '3.root.json'),
      os.path.join(self.client_metadata_current, 'root.json')))



  def test_root_rotation_max(self):
    """Test that client does not rotate beyond a configured upper bound, i.e.
    `current_version + MAX_NUMBER_ROOT_ROTATIONS`. """
    # NOTE: The nature of below root changes is irrelevant. Here we only want
    # the client to update but not beyond a configured upper bound.

    # 1.root.json --> 2.root.json (add root2 and root3 keys)
    repository = repo_tool.load_repository(self.repository_directory)
    repository.root.load_signing_key(self.role_keys['root']['private'])
    repository.root.add_verification_key(self.role_keys['root2']['public'])
    repository.root.load_signing_key(self.role_keys['root2']['private'])
    repository.root.add_verification_key(self.role_keys['root3']['public'])
    repository.root.load_signing_key(self.role_keys['root3']['private'])
    repository.writeall()

    # 2.root.json --> 3.root.json (change threshold)
    repository.root.threshold = 2
    repository.writeall()

    # 3.root.json --> 4.root.json (change threshold again)
    repository.root.threshold = 3
    repository.writeall()

    # Move staged metadata to "live" metadata
    shutil.rmtree(os.path.join(self.repository_directory, 'metadata'))
    shutil.copytree(os.path.join(self.repository_directory, 'metadata.staged'),
                    os.path.join(self.repository_directory, 'metadata'))

    # Assert that repo indeed has "4.root.json" and that it's the latest root
    self.assertTrue(filecmp.cmp(
      os.path.join(self.repository_directory, 'metadata', '4.root.json'),
      os.path.join(self.repository_directory, 'metadata', 'root.json')))

    # Lower max root rotation cap so that client stops updating early
    max_rotation_backup = tuf.settings.MAX_NUMBER_ROOT_ROTATIONS
    tuf.settings.MAX_NUMBER_ROOT_ROTATIONS = 2

    # Update on client 1.root.json --> 2.root.json --> 3.root.json,
    # but stop before updating to 4.root.json
    self.repository_updater.refresh()

    # Assert that the client indeed only updated until 3.root.json
    self.assertTrue(filecmp.cmp(
      os.path.join(self.repository_directory, 'metadata', '3.root.json'),
      os.path.join(self.client_metadata_current, 'root.json')))

    # reset
    tuf.settings.MAX_NUMBER_ROOT_ROTATIONS = max_rotation_backup



  def test_root_rotation_missing_keys(self):
    repository = repo_tool.load_repository(self.repository_directory)

    # A partially written root.json (threshold = 1, and not signed in this
    # case) causes an invalid root chain later.
    repository.snapshot.load_signing_key(self.role_keys['snapshot']['private'])
    repository.timestamp.load_signing_key(self.role_keys['timestamp']['private'])
    repository.write('root')
    repository.write('snapshot')
    repository.write('timestamp')

    # Move the staged metadata to the "live" metadata.
    shutil.rmtree(os.path.join(self.repository_directory, 'metadata'))
    shutil.copytree(os.path.join(self.repository_directory, 'metadata.staged'),
                    os.path.join(self.repository_directory, 'metadata'))

    # Create a new, valid root.json.
    repository.root.threshold = 2
    repository.root.add_verification_key(self.role_keys['role1']['public'])
    repository.root.load_signing_key(self.role_keys['root']['private'])
    repository.root.load_signing_key(self.role_keys['role1']['private'])

    repository.writeall()

    repository.root.add_verification_key(self.role_keys['snapshot']['public'])
    repository.root.load_signing_key(self.role_keys['snapshot']['private'])
    repository.root.threshold = 3
    repository.writeall()

    # Move the staged metadata to the "live" metadata.
    shutil.rmtree(os.path.join(self.repository_directory, 'metadata'))
    shutil.copytree(os.path.join(self.repository_directory, 'metadata.staged'),
                    os.path.join(self.repository_directory, 'metadata'))

    try:
      self.repository_updater.refresh()

    except tuf.exceptions.NoWorkingMirrorError as exception:
      for mirror_url, mirror_error in six.iteritems(exception.mirror_errors):
        url_prefix = self.repository_mirrors['mirror1']['url_prefix']
        url_file = os.path.join(url_prefix, 'metadata', '2.root.json')

        # Verify that '2.root.json' is the culprit.
        self.assertEqual(url_file.replace('\\', '/'), mirror_url)
        self.assertTrue(isinstance(mirror_error,
          securesystemslib.exceptions.BadSignatureError))



  def test_root_rotation_unmet_threshold(self):
    repository = repo_tool.load_repository(self.repository_directory)

    # Add verification keys
    repository.root.add_verification_key(self.role_keys['root']['public'])
    repository.root.add_verification_key(self.role_keys['role1']['public'])

    repository.targets.add_verification_key(self.role_keys['targets']['public'])
    repository.snapshot.add_verification_key(self.role_keys['snapshot']['public'])
    repository.timestamp.add_verification_key(self.role_keys['timestamp']['public'])

    repository.snapshot.load_signing_key(self.role_keys['snapshot']['private'])
    repository.timestamp.load_signing_key(self.role_keys['timestamp']['private'])

    # Add signing keys
    repository.root.load_signing_key(self.role_keys['root']['private'])
    repository.root.load_signing_key(self.role_keys['role1']['private'])

    # Set root threshold
    repository.root.threshold = 2
    repository.writeall()

    # Unload Root's previous signing keys to ensure that these keys are not
    # used by mistake.
    repository.root.unload_signing_key(self.role_keys['role1']['private'])
    repository.root.unload_signing_key(self.role_keys['root']['private'])

    # Add new verification key
    repository.root.add_verification_key(self.role_keys['snapshot']['public'])

    # Remove one of the original signing keys
    repository.root.remove_verification_key(self.role_keys['role1']['public'])

    # Set the threshold for the new Root file, but note that the previous
    # threshold of 2 must still be met.
    repository.root.threshold = 1

    repository.root.load_signing_key(self.role_keys['role1']['private'])
    repository.root.load_signing_key(self.role_keys['snapshot']['private'])

    repository.snapshot.load_signing_key(self.role_keys['snapshot']['private'])
    repository.timestamp.load_signing_key(self.role_keys['timestamp']['private'])

    # We use write() rather than writeall() because the latter should fail due
    # to the missing self.role_keys['root'] signature.
    repository.write('root', increment_version_number=True)
    repository.write('snapshot', increment_version_number=True)
    repository.write('timestamp', increment_version_number=True)

    # Move the staged metadata to the "live" metadata.
    shutil.rmtree(os.path.join(self.repository_directory, 'metadata'))
    shutil.copytree(os.path.join(self.repository_directory, 'metadata.staged'),
                    os.path.join(self.repository_directory, 'metadata'))

    # The following refresh should fail because root must be signed by the
    # previous self.role_keys['root'] key, which wasn't loaded.
    self.assertRaises(tuf.exceptions.NoWorkingMirrorError,
        self.repository_updater.refresh)




def _load_role_keys(keystore_directory):

  # Populating 'self.role_keys' by importing the required public and private
  # keys of 'tuf/tests/repository_data/'.  The role keys are needed when
  # modifying the remote repository used by the test cases in this unit test.

  # The pre-generated key files in 'repository_data/keystore' are all encrypted
  # with a 'password' passphrase.
  EXPECTED_KEYFILE_PASSWORD = 'password'

  # Store and return the cryptography keys of the top-level roles, including 1
  # delegated role.
  role_keys = {}

  root_key_file = os.path.join(keystore_directory, 'root_key')
  root2_key_file = os.path.join(keystore_directory, 'root_key2')
  root3_key_file = os.path.join(keystore_directory, 'root_key3')
  targets_key_file = os.path.join(keystore_directory, 'targets_key')
  snapshot_key_file = os.path.join(keystore_directory, 'snapshot_key')
  timestamp_key_file = os.path.join(keystore_directory, 'timestamp_key')
  delegation_key_file = os.path.join(keystore_directory, 'delegation_key')

  role_keys = {'root': {}, 'root2': {}, 'root3': {}, 'targets': {}, 'snapshot':
               {}, 'timestamp': {}, 'role1': {}}

  # Import the top-level and delegated role public keys.
  role_keys['root']['public'] = \
    repo_tool.import_rsa_publickey_from_file(root_key_file+'.pub')
  role_keys['root2']['public'] = \
    repo_tool.import_ed25519_publickey_from_file(root2_key_file+'.pub')
  role_keys['root3']['public'] = \
    repo_tool.import_ed25519_publickey_from_file(root3_key_file+'.pub')
  role_keys['targets']['public'] = \
    repo_tool.import_ed25519_publickey_from_file(targets_key_file+'.pub')
  role_keys['snapshot']['public'] = \
    repo_tool.import_ed25519_publickey_from_file(snapshot_key_file+'.pub')
  role_keys['timestamp']['public'] = \
      repo_tool.import_ed25519_publickey_from_file(timestamp_key_file+'.pub')
  role_keys['role1']['public'] = \
      repo_tool.import_ed25519_publickey_from_file(delegation_key_file+'.pub')

  # Import the private keys of the top-level and delegated roles.
  role_keys['root']['private'] = \
    repo_tool.import_rsa_privatekey_from_file(root_key_file,
                                              EXPECTED_KEYFILE_PASSWORD)
  role_keys['root2']['private'] = \
    repo_tool.import_ed25519_privatekey_from_file(root2_key_file,
                                              EXPECTED_KEYFILE_PASSWORD)
  role_keys['root3']['private'] = \
    repo_tool.import_ed25519_privatekey_from_file(root3_key_file,
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
