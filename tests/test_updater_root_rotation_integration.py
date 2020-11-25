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
import shutil
import tempfile
import logging
import unittest
import filecmp
import sys

import tuf
import tuf.log
import tuf.keydb
import tuf.roledb
import tuf.exceptions
import tuf.repository_tool as repo_tool
import tuf.unittest_toolbox as unittest_toolbox
import tuf.client.updater as updater
import tuf.settings

from tests import utils

import securesystemslib
import six

logger = logging.getLogger(__name__)
repo_tool.disable_console_log_messages()


class TestUpdater(unittest_toolbox.Modified_TestCase):

  @classmethod
  def setUpClass(cls):
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
    cls.server_process_handler = utils.TestServerProcess(log=logger)




  @classmethod
  def tearDownClass(cls):
    # Cleans the resources and flush the logged lines (if any).
    cls.server_process_handler.clean()

    # Remove the temporary repository directory, which should contain all the
    # metadata, targets, and key files generated for the test cases.
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
    url_prefix = 'http://localhost:' \
        + str(self.server_process_handler.port) + repository_basepath

    # Setting 'tuf.settings.repository_directory' with the temporary client
    # directory copied from the original repository files.
    tuf.settings.repositories_directory = self.client_directory

    self.repository_mirrors = {'mirror1': {'url_prefix': url_prefix,
                                           'metadata_path': 'metadata',
                                           'targets_path': 'targets'}}

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

    # Logs stdout and stderr from the sever subprocess.
    self.server_process_handler.flush_log()


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



  def test_verify_root_with_current_keyids_and_threshold(self):
     """
     Each root file is signed by the current root threshold of keys as well
     as the previous root threshold of keys. Test that a root file which is
     not 'self-signed' with the current root threshold of keys causes the
     update to fail
     """
     # Load repository with root.json == 1.root.json (available on client)
     # Signing key: "root", Threshold: 1
     repository = repo_tool.load_repository(self.repository_directory)

     # Rotate keys and update root: 1.root.json --> 2.root.json
     # Signing key: "root" (previous) and "root2" (current)
     # Threshold (for both): 1
     repository.root.load_signing_key(self.role_keys['root']['private'])
     repository.root.add_verification_key(self.role_keys['root2']['public'])
     repository.root.load_signing_key(self.role_keys['root2']['private'])
     # Remove the previous "root" key from the list of current
     # verification keys
     repository.root.remove_verification_key(self.role_keys['root']['public'])
     repository.writeall()

     # Move staged metadata to "live" metadata
     shutil.rmtree(os.path.join(self.repository_directory, 'metadata'))
     shutil.copytree(os.path.join(self.repository_directory, 'metadata.staged'),
         os.path.join(self.repository_directory, 'metadata'))

     # Intercept 2.root.json and tamper with "root2" (current) key signature
     root2_path_live = os.path.join(
         self.repository_directory, 'metadata', '2.root.json')
     root2 = securesystemslib.util.load_json_file(root2_path_live)

     for idx, sig in enumerate(root2['signatures']):
       if sig['keyid'] == self.role_keys['root2']['public']['keyid']:
         sig_len = len(root2['signatures'][idx]['sig'])
         root2['signatures'][idx]['sig'] = "deadbeef".ljust(sig_len, '0')

     roo2_fobj = tempfile.TemporaryFile()
     roo2_fobj.write(tuf.repository_lib._get_written_metadata(root2))
     securesystemslib.util.persist_temp_file(roo2_fobj, root2_path_live)

     # Update 1.root.json -> 2.root.json
     # Signature verification with current keys should fail because we replaced
     with self.assertRaises(tuf.exceptions.NoWorkingMirrorError) as cm:
       self.repository_updater.refresh()

     for mirror_url, mirror_error in six.iteritems(cm.exception.mirror_errors):
       self.assertTrue(mirror_url.endswith('/2.root.json'))
       self.assertTrue(isinstance(mirror_error,
           securesystemslib.exceptions.BadSignatureError))

     # Assert that the current 'root.json' on the client side is the verified one
     self.assertTrue(filecmp.cmp(
       os.path.join(self.repository_directory, 'metadata', '1.root.json'),
       os.path.join(self.client_metadata_current, 'root.json')))





  def test_verify_root_with_duplicate_current_keyids(self):
     """
     Each root file is signed by the current root threshold of keys as well
     as the previous root threshold of keys. In each case, a keyid must only
     count once towards the threshold. Test that the new root signatures
     specific signature verification implemented in _verify_root_self_signed()
     only counts one signature per keyid towards the threshold.
     """
     # Load repository with root.json == 1.root.json (available on client)
     # Signing key: "root", Threshold: 1
     repository = repo_tool.load_repository(self.repository_directory)

     # Add an additional signing key and bump the threshold to 2
     repository.root.load_signing_key(self.role_keys['root']['private'])
     repository.root.add_verification_key(self.role_keys['root2']['public'])
     repository.root.load_signing_key(self.role_keys['root2']['private'])
     repository.root.threshold = 2
     repository.writeall()

     # Move staged metadata to "live" metadata
     shutil.rmtree(os.path.join(self.repository_directory, 'metadata'))
     shutil.copytree(os.path.join(self.repository_directory, 'metadata.staged'),
         os.path.join(self.repository_directory, 'metadata'))

     # Modify 2.root.json and list two signatures with the same keyid
     root2_path_live = os.path.join(
         self.repository_directory, 'metadata', '2.root.json')
     root2 = securesystemslib.util.load_json_file(root2_path_live)

     signatures = []
     signatures.append(root2['signatures'][0])
     signatures.append(root2['signatures'][0])

     root2['signatures'] = signatures

     root2_fobj = tempfile.TemporaryFile()
     root2_fobj.write(tuf.repository_lib._get_written_metadata(root2))
     securesystemslib.util.persist_temp_file(root2_fobj, root2_path_live)

     # Update 1.root.json -> 2.root.json
     # Signature verification with new keys should fail because the threshold
     # can only be met by two signatures with the same keyid
     with self.assertRaises(tuf.exceptions.NoWorkingMirrorError) as cm:
       self.repository_updater.refresh()

     for mirror_url, mirror_error in six.iteritems(cm.exception.mirror_errors):
       self.assertTrue(mirror_url.endswith('/2.root.json'))
       self.assertTrue(isinstance(mirror_error,
           securesystemslib.exceptions.BadSignatureError))

     # Assert that the current 'root.json' on the client side is the verified one
     self.assertTrue(filecmp.cmp(
       os.path.join(self.repository_directory, 'metadata', '1.root.json'),
       os.path.join(self.client_metadata_current, 'root.json')))





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

    # A partially written root.json (threshold = 2, and signed with only 1 key)
    # causes an invalid root chain later.
    repository.root.threshold = 2
    repository.root.load_signing_key(self.role_keys['root']['private'])
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
    # Still not valid, because it is not written with a threshold of 2
    # previous keys
    repository.root.add_verification_key(self.role_keys['role1']['public'])
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

    with self.assertRaises(tuf.exceptions.NoWorkingMirrorError) as cm:
      self.repository_updater.refresh()

    for mirror_url, mirror_error in six.iteritems(cm.exception.mirror_errors):
      self.assertTrue(mirror_url.endswith('/2.root.json'))
      self.assertTrue(isinstance(mirror_error,
          securesystemslib.exceptions.BadSignatureError))

    # Assert that the current 'root.json' on the client side is the verified one
    self.assertTrue(filecmp.cmp(
        os.path.join(self.repository_directory, 'metadata', '1.root.json'),
        os.path.join(self.client_metadata_current, 'root.json')))




  def test_root_rotation_unmet_last_version_threshold(self):
    """Test that client detects a root.json version that is not signed
     by a previous threshold of signatures """

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
    with self.assertRaises(tuf.exceptions.NoWorkingMirrorError) as cm:
      self.repository_updater.refresh()

    for mirror_url, mirror_error in six.iteritems(cm.exception.mirror_errors):
      self.assertTrue(mirror_url.endswith('/3.root.json'))
      self.assertTrue(isinstance(mirror_error,
          securesystemslib.exceptions.BadSignatureError))

    # Assert that the current 'root.json' on the client side is the verified one
    self.assertTrue(filecmp.cmp(
        os.path.join(self.repository_directory, 'metadata', '2.root.json'),
        os.path.join(self.client_metadata_current, 'root.json')))



  def test_root_rotation_unmet_new_threshold(self):
    """Test that client detects a root.json version that is not signed
     by a current threshold of signatures """
    repository = repo_tool.load_repository(self.repository_directory)

    # Create a new, valid root.json.
    repository.root.threshold = 2
    repository.root.load_signing_key(self.role_keys['root']['private'])
    repository.root.add_verification_key(self.role_keys['root2']['public'])
    repository.root.load_signing_key(self.role_keys['root2']['private'])

    repository.writeall()

    # Increase the threshold and add a new verification key without
    # actually loading the signing key
    repository.root.threshold = 3
    repository.root.add_verification_key(self.role_keys['root3']['public'])

    # writeall fails as expected since the third signature is missing
    self.assertRaises(tuf.exceptions.UnsignedMetadataError, repository.writeall)
    # write an invalid '3.root.json' as partially signed
    repository.write('root')

    # Move the staged metadata to the "live" metadata.
    shutil.rmtree(os.path.join(self.repository_directory, 'metadata'))
    shutil.copytree(os.path.join(self.repository_directory, 'metadata.staged'),
                  os.path.join(self.repository_directory, 'metadata'))


   # The following refresh should fail because root must be signed by the
   # current self.role_keys['root3'] key, which wasn't loaded.
    with self.assertRaises(tuf.exceptions.NoWorkingMirrorError) as cm:
      self.repository_updater.refresh()

    for mirror_url, mirror_error in six.iteritems(cm.exception.mirror_errors):
      self.assertTrue(mirror_url.endswith('/3.root.json'))
      self.assertTrue(isinstance(mirror_error,
          securesystemslib.exceptions.BadSignatureError))

    # Assert that the current 'root.json' on the client side is the verified one
    self.assertTrue(filecmp.cmp(
        os.path.join(self.repository_directory, 'metadata', '2.root.json'),
        os.path.join(self.client_metadata_current, 'root.json')))



  def test_root_rotation_discard_untrusted_version(self):
    """Test that client discards root.json version that failed the
    signature verification """
    repository = repo_tool.load_repository(self.repository_directory)

    # Rotate the root key without signing with the previous version key 'root'
    repository.root.remove_verification_key(self.role_keys['root']['public'])
    repository.root.add_verification_key(self.role_keys['root2']['public'])
    repository.root.load_signing_key(self.role_keys['root2']['private'])

    # 2.root.json
    repository.writeall()

    # Move the staged metadata to the "live" metadata.
    shutil.rmtree(os.path.join(self.repository_directory, 'metadata'))
    shutil.copytree(os.path.join(self.repository_directory, 'metadata.staged'),
                  os.path.join(self.repository_directory, 'metadata'))

    # Refresh on the client side should fail because 2.root.json is not signed
    # with a threshold of prevous keys
    with self.assertRaises(tuf.exceptions.NoWorkingMirrorError) as cm:
      self.repository_updater.refresh()

    for mirror_url, mirror_error in six.iteritems(cm.exception.mirror_errors):
      self.assertTrue(mirror_url.endswith('/2.root.json'))
      self.assertTrue(isinstance(mirror_error,
          securesystemslib.exceptions.BadSignatureError))

    # Assert that the current 'root.json' on the client side is the trusted one
    # and 2.root.json is discarded
    self.assertTrue(filecmp.cmp(
        os.path.join(self.repository_directory, 'metadata', '1.root.json'),
        os.path.join(self.client_metadata_current, 'root.json')))




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
  utils.configure_test_logging(sys.argv)
  unittest.main()
