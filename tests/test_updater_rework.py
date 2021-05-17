#!/usr/bin/env python

# Copyright 2021, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Test Updater class
"""

import os
import time
import shutil
import copy
import tempfile
import logging
import errno
import sys
import unittest
import json
import tracemalloc

if sys.version_info >= (3, 3):
  import unittest.mock as mock
else:
  import mock

import tuf
import tuf.exceptions
import tuf.log
import tuf.repository_tool as repo_tool
import tuf.unittest_toolbox as unittest_toolbox
import tuf.client_rework.updater_rework as updater

from tests import utils
from tuf.api import metadata

import securesystemslib

logger = logging.getLogger(__name__)


class TestUpdater(unittest_toolbox.Modified_TestCase):

  @classmethod
  def setUpClass(cls):
    # Create a temporary directory to store the repository, metadata, and target
    # files.  'temporary_directory' must be deleted in TearDownModule() so that
    # temporary files are always removed, even when exceptions occur.
    cls.temporary_directory = tempfile.mkdtemp(dir=os.getcwd())

    # Needed because in some tests simple_server.py cannot be found.
    # The reason is that the current working directory
    # has been changed when executing a subprocess.
    cls.SIMPLE_SERVER_PATH = os.path.join(os.getcwd(), 'simple_server.py')

    # Launch a SimpleHTTPServer (serves files in the current directory).
    # Test cases will request metadata and target files that have been
    # pre-generated in 'tuf/tests/repository_data', which will be served
    # by the SimpleHTTPServer launched here.  The test cases of 'test_updater.py'
    # assume the pre-generated metadata files have a specific structure, such
    # as a delegated role 'targets/role1', three target files, five key files,
    # etc.
    cls.server_process_handler = utils.TestServerProcess(log=logger,
        server=cls.SIMPLE_SERVER_PATH)



  @classmethod
  def tearDownClass(cls):
    # Cleans the resources and flush the logged lines (if any).
    cls.server_process_handler.clean()

    # Remove the temporary repository directory, which should contain all the
    # metadata, targets, and key files generated for the test cases
    shutil.rmtree(cls.temporary_directory)



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
    original_client = os.path.join(original_repository_files, 'client', 'test_repository1', 'metadata', 'current')

    # Save references to the often-needed client repository directories.
    # Test cases need these references to access metadata and target files.
    self.repository_directory = \
      os.path.join(temporary_repository_root, 'repository')
    self.keystore_directory = \
      os.path.join(temporary_repository_root, 'keystore')

    self.client_directory = os.path.join(temporary_repository_root, 'client')

    # Copy the original 'repository', 'client', and 'keystore' directories
    # to the temporary repository the test cases can use.
    shutil.copytree(original_repository, self.repository_directory)
    shutil.copytree(original_client, self.client_directory)
    shutil.copytree(original_keystore, self.keystore_directory)

    # 'path/to/tmp/repository' -> 'localhost:8001/tmp/repository'.
    repository_basepath = self.repository_directory[len(os.getcwd()):]
    url_prefix = 'http://' + utils.TEST_HOST_ADDRESS + ':' \
        + str(self.server_process_handler.port) + repository_basepath

    metadata_url = f"{url_prefix}/metadata/"
    targets_url = f"{url_prefix}/targets/"
    # Creating a repository instance.  The test cases will use this client
    # updater to refresh metadata, fetch target files, etc.
    self.repository_updater = updater.Updater(self.client_directory,
                                              metadata_url,
                                              targets_url)

    # Metadata role keys are needed by the test cases to make changes to the
    # repository (e.g., adding a new target file to 'targets.json' and then
    # requesting a refresh()).
    self.role_keys = _load_role_keys(self.keystore_directory)



  def tearDown(self):
    # We are inheriting from custom class.
    unittest_toolbox.Modified_TestCase.tearDown(self)

    # Logs stdout and stderr from the sever subprocess.
    self.server_process_handler.flush_log()



  # UNIT TESTS.
  def test_refresh(self):

    self.repository_updater.refresh()

    for role in ['root', 'timestamp', 'snapshot', 'targets']:
        metadata_obj = metadata.Metadata.from_file(os.path.join(
            self.client_directory, role + '.json'))

        metadata_obj_2 = metadata.Metadata.from_file(os.path.join(
            self.repository_directory, 'metadata', role + '.json'))


        self.assertDictEqual(metadata_obj.to_dict(),
                             metadata_obj_2.to_dict())

    # Get targetinfo for 'file1.txt' listed in targets
    targetinfo1 = self.repository_updater.get_one_valid_targetinfo('file1.txt')
    # Get targetinfo for 'file3.txt' listed in the delegated role1
    targetinfo3= self.repository_updater.get_one_valid_targetinfo('file3.txt')

    destination_directory = self.make_temp_directory()
    updated_targets = self.repository_updater.updated_targets([targetinfo1, targetinfo3],
                                                      destination_directory)

    self.assertListEqual(updated_targets, [targetinfo1, targetinfo3])

    self.repository_updater.download_target(targetinfo1, destination_directory)
    updated_targets = self.repository_updater.updated_targets(updated_targets,
                                                      destination_directory)

    self.assertListEqual(updated_targets, [targetinfo3])


    self.repository_updater.download_target(targetinfo3, destination_directory)
    updated_targets = self.repository_updater.updated_targets(updated_targets,
                                                  destination_directory)

    self.assertListEqual(updated_targets, [])


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
  utils.configure_test_logging(sys.argv)
  unittest.main()
