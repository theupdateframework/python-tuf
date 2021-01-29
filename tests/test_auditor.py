#!/usr/bin/env python

"""
<Program Name>
  test_auditor.py

<Author>
  Marina Moore

<Started>
  January 29, 2021

<Copyright>
  See LICENSE-MIT OR LICENSE for licensing information.

<Purpose>
  'test-auditor.py' provides a collection of methods that test the public /
  non-public methods and functions of 'tuf.client.auditor.py'.

"""

import unittest
import tempfile
import os
import logging
import shutil

import tuf
import tuf.exceptions
import tuf.log
import tuf.keydb
import tuf.roledb
import tuf.repository_tool as repo_tool
import tuf.repository_lib as repo_lib
import tuf.unittest_toolbox as unittest_toolbox
import tuf.client.auditor as auditor

from tests import utils

import securesystemslib

logger = logging.getLogger(__name__)
repo_tool.disable_console_log_messages()


class TestAuditor(unittest_toolbox.Modified_TestCase):

  @classmethod
  def setUpClass(cls):
    # setUpClass is called before tests in an individual class are executed.

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

    tuf.roledb.clear_roledb(clear_all=True)
    tuf.keydb.clear_keydb(clear_all=True)

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

    self.client_directory = os.path.join(temporary_repository_root,
        'client')
    self.client_metadata = os.path.join(self.client_directory,
        self.repository_name, 'metadata')
    self.client_metadata_current = os.path.join(self.client_metadata,
        'current')
    self.client_metadata_previous = os.path.join(self.client_metadata,
        'previous')

    # Copy the original 'repository', 'client', and 'keystore' directories
    # to the temporary repository the test cases can use.
    shutil.copytree(original_repository, self.repository_directory)
    shutil.copytree(original_client, self.client_directory)
    shutil.copytree(original_keystore, self.keystore_directory)

    # 'path/to/tmp/repository' -> 'localhost:8001/tmp/repository'.
    repository_basepath = self.repository_directory[len(os.getcwd()):]
    url_prefix = 'http://localhost:' \
        + str(self.server_process_handler.port) + repository_basepath

    # Setting 'tuf.settings.repository_directory' with the temporary client
    # directory copied from the original repository files.
    tuf.settings.repositories_directory = self.client_directory

    # replace timestamp with a merkle timestamp
    merkle_timestamp = os.path.join(self.repository_directory, 'metadata', 'timestamp-merkle.json')
    timestamp = os.path.join(self.repository_directory, 'metadata', 'timestamp.json')
    shutil.move(merkle_timestamp, timestamp)

    # Metadata role keys are needed by the test cases to make changes to the
    # repository (e.g., adding a new target file to 'targets.json' and then
    # requesting a refresh()).
    self.role_keys = _load_role_keys(self.keystore_directory)

   # The repository must be rewritten with 'consistent_snapshot' set.
    repository = repo_tool.load_repository(self.repository_directory)

    # Write metadata for all the top-level roles , since consistent snapshot
    # is now being set to true (i.e., the pre-generated repository isn't set
    # to support consistent snapshots.  A new version of targets.json is needed
    # to ensure <digest>.filename target files are written to disk.
    repository.targets.load_signing_key(self.role_keys['targets']['private'])
    repository.root.load_signing_key(self.role_keys['root']['private'])
    repository.snapshot.load_signing_key(self.role_keys['snapshot']['private'])
    repository.timestamp.load_signing_key(self.role_keys['timestamp']['private'])

    repository.mark_dirty(['targets', 'root', 'snapshot', 'timestamp'])
    repository.writeall(snapshot_merkle=True, consistent_snapshot=True)

    # Move the staged metadata to the "live" metadata.
    shutil.rmtree(os.path.join(self.repository_directory, 'metadata'))
    shutil.copytree(os.path.join(self.repository_directory, 'metadata.staged'),
                    os.path.join(self.repository_directory, 'metadata'))

    self.repository_mirrors = {'mirror1': {'url_prefix': url_prefix,
                                           'metadata_path': 'metadata',
                                           'targets_path': 'targets'}}




  def tearDown(self):
    # We are inheriting from custom class.
    unittest_toolbox.Modified_TestCase.tearDown(self)
    tuf.roledb.clear_roledb(clear_all=True)
    tuf.keydb.clear_keydb(clear_all=True)

    # Logs stdout and stderr from the sever subprocess.
    self.server_process_handler.flush_log()


  # UNIT TESTS.

  def test_1__init_exceptions(self):
    # Invalid arguments
    self.assertRaises(securesystemslib.exceptions.FormatError, auditor.Auditor,
        5, self.repository_mirrors)
    self.assertRaises(securesystemslib.exceptions.FormatError, auditor.Auditor,
        self.repository_name, 5)



  def test_2__verify_merkle_tree(self):
    repository_auditor = auditor.Auditor(self.repository_name, self.repository_mirrors)
    # skip version 1 as it was written without consistent snapshots
    repository_auditor.last_version_verified = 1

    # The repository must be rewritten with 'consistent_snapshot' set.
    repository = repo_tool.load_repository(self.repository_directory)

    # Write metadata for all the top-level roles , since consistent snapshot
    # is now being set to true (i.e., the pre-generated repository isn't set
    # to support consistent snapshots.  A new version of targets.json is needed
    # to ensure <digest>.filename target files are written to disk.
    repository.targets.load_signing_key(self.role_keys['targets']['private'])
    repository.root.load_signing_key(self.role_keys['root']['private'])
    repository.snapshot.load_signing_key(self.role_keys['snapshot']['private'])
    repository.timestamp.load_signing_key(self.role_keys['timestamp']['private'])

    repository.targets.add_target('file1.txt')

    repository.mark_dirty(['targets', 'root', 'snapshot', 'timestamp'])
    repository.writeall(snapshot_merkle=True, consistent_snapshot=True)

    # Move the staged metadata to the "live" metadata.
    shutil.rmtree(os.path.join(self.repository_directory, 'metadata'))
    shutil.copytree(os.path.join(self.repository_directory, 'metadata.staged'),
                    os.path.join(self.repository_directory, 'metadata'))


    # Normal case, should not error
    repository_auditor.verify()

    self.assertEqual(repository_auditor.version_info['role1.json'], 1)
    self.assertEqual(repository_auditor.version_info['targets.json'], 3)
    self.assertEqual(repository_auditor.last_version_verified, 3)

    # modify targets
    repository.targets.add_target('file2.txt')

    repository.targets.load_signing_key(self.role_keys['targets']['private'])
    repository.root.load_signing_key(self.role_keys['root']['private'])
    repository.snapshot.load_signing_key(self.role_keys['snapshot']['private'])
    repository.timestamp.load_signing_key(self.role_keys['timestamp']['private'])


    repository.mark_dirty(['targets', 'root', 'snapshot', 'timestamp'])
    repository.writeall(snapshot_merkle=True, consistent_snapshot=True)

    # Move the staged metadata to the "live" metadata.
    shutil.rmtree(os.path.join(self.repository_directory, 'metadata'))
    shutil.copytree(os.path.join(self.repository_directory, 'metadata.staged'),
                    os.path.join(self.repository_directory, 'metadata'))

    repository_auditor.verify()

    # Ensure the auditor checked the latest targets
    self.assertEqual(repository_auditor.version_info['targets.json'], 4)

    # Test rollback attack detection
    repository_auditor.version_info['targets.json'] = 5
    repository_auditor.last_version_verified = 3

    self.assertRaises(tuf.exceptions.RepositoryError, repository_auditor.verify)




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
  unittest.main()
