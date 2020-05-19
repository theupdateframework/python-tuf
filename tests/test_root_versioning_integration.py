#!/usr/bin/env python

# Copyright 2016 - 2017, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
<Program Name>
  test_root_versioning_integration.py

<Author>
  Evan Cordell.

<Started>
  July 21, 2016.

<Copyright>
  See LICENSE-MIT OR LICENSE for licensing information.

<Purpose>
  Test root versioning for efficient root key rotation.
"""

from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import os
import logging
import tempfile
import shutil
import sys
import unittest

import tuf
import tuf.log
import tuf.formats
import tuf.exceptions
import tuf.roledb
import tuf.keydb
import tuf.repository_tool as repo_tool

import securesystemslib
import securesystemslib.storage

logger = logging.getLogger(__name__)

repo_tool.disable_console_log_messages()


class TestRepository(unittest.TestCase):

  @classmethod
  def setUpClass(cls):
    cls.temporary_directory = tempfile.mkdtemp(dir=os.getcwd())

  @classmethod
  def tearDownClass(cls):
    shutil.rmtree(cls.temporary_directory)

  def tearDown(self):
    tuf.roledb.clear_roledb()
    tuf.keydb.clear_keydb()

  def test_init(self):
    # Test normal case.
    storage_backend = securesystemslib.storage.FilesystemBackend()
    repository = repo_tool.Repository('repository_directory/',
                                      'metadata_directory/',
                                      'targets_directory/',
                                      storage_backend)
    self.assertTrue(isinstance(repository.root, repo_tool.Root))
    self.assertTrue(isinstance(repository.snapshot, repo_tool.Snapshot))
    self.assertTrue(isinstance(repository.timestamp, repo_tool.Timestamp))
    self.assertTrue(isinstance(repository.targets, repo_tool.Targets))

    # Test improperly formatted arguments.
    self.assertRaises(securesystemslib.exceptions.FormatError, repo_tool.Repository, 3,
                      'metadata_directory/', 'targets_directory', storage_backend)
    self.assertRaises(securesystemslib.exceptions.FormatError, repo_tool.Repository,
                      'repository_directory', 3, 'targets_directory', storage_backend)
    self.assertRaises(securesystemslib.exceptions.FormatError, repo_tool.Repository,
                      'repository_directory', 'metadata_directory', storage_backend, 3)



  def test_root_role_versioning(self):
    # Test root role versioning
    #
    # 1. Import public and private keys.
    # 2. Add verification keys.
    # 3. Load signing keys.
    # 4. Add target files.
    # 5. Perform delegation.
    # 6. writeall()
    #
    # Copy the target files from 'tuf/tests/repository_data' so that writeall()
    # has target fileinfo to include in metadata.
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)
    targets_directory = os.path.join(temporary_directory, 'repository',
                                     repo_tool.TARGETS_DIRECTORY_NAME)
    original_targets_directory = os.path.join('repository_data',
                                              'repository', 'targets')
    shutil.copytree(original_targets_directory, targets_directory)

    # In this case, create_new_repository() creates the 'repository/'
    # sub-directory in 'temporary_directory' if it does not exist.
    repository_directory = os.path.join(temporary_directory, 'repository')
    metadata_directory = os.path.join(repository_directory,
                                      repo_tool.METADATA_STAGED_DIRECTORY_NAME)
    repository = repo_tool.create_new_repository(repository_directory)




    # (1) Load the public and private keys of the top-level roles, and one
    # delegated role.
    keystore_directory = os.path.join('repository_data', 'keystore')

    # Load the public keys.
    root_pubkey_path = os.path.join(keystore_directory, 'root_key.pub')
    targets_pubkey_path = os.path.join(keystore_directory, 'targets_key.pub')
    snapshot_pubkey_path = os.path.join(keystore_directory, 'snapshot_key.pub')
    timestamp_pubkey_path = os.path.join(keystore_directory, 'timestamp_key.pub')
    role1_pubkey_path = os.path.join(keystore_directory, 'delegation_key.pub')

    root_pubkey = repo_tool.import_rsa_publickey_from_file(root_pubkey_path)
    targets_pubkey = repo_tool.import_ed25519_publickey_from_file(targets_pubkey_path)
    snapshot_pubkey = \
      repo_tool.import_ed25519_publickey_from_file(snapshot_pubkey_path)
    timestamp_pubkey = \
      repo_tool.import_ed25519_publickey_from_file(timestamp_pubkey_path)
    role1_pubkey = repo_tool.import_ed25519_publickey_from_file(role1_pubkey_path)

    # Load the private keys.
    root_privkey_path = os.path.join(keystore_directory, 'root_key')
    targets_privkey_path = os.path.join(keystore_directory, 'targets_key')
    snapshot_privkey_path = os.path.join(keystore_directory, 'snapshot_key')
    timestamp_privkey_path = os.path.join(keystore_directory, 'timestamp_key')
    role1_privkey_path = os.path.join(keystore_directory, 'delegation_key')

    root_privkey = \
      repo_tool.import_rsa_privatekey_from_file(root_privkey_path, 'password')
    targets_privkey = \
      repo_tool.import_ed25519_privatekey_from_file(targets_privkey_path, 'password')
    snapshot_privkey = \
      repo_tool.import_ed25519_privatekey_from_file(snapshot_privkey_path,
                                                'password')
    timestamp_privkey = \
      repo_tool.import_ed25519_privatekey_from_file(timestamp_privkey_path,
                                                'password')
    role1_privkey = \
      repo_tool.import_ed25519_privatekey_from_file(role1_privkey_path,
                                                'password')


    # (2) Add top-level verification keys.
    repository.root.add_verification_key(root_pubkey)
    repository.targets.add_verification_key(targets_pubkey)
    repository.snapshot.add_verification_key(snapshot_pubkey)
    repository.timestamp.add_verification_key(timestamp_pubkey)


    # (3) Load top-level signing keys.
    repository.root.load_signing_key(root_privkey)
    repository.targets.load_signing_key(targets_privkey)
    repository.snapshot.load_signing_key(snapshot_privkey)
    repository.timestamp.load_signing_key(timestamp_privkey)

    # (4) Add target files.
    target1 = 'file1.txt'
    target2 = 'file2.txt'
    target3 = 'file3.txt'
    repository.targets.add_target(target1)
    repository.targets.add_target(target2)


    # (5) Perform delegation.
    repository.targets.delegate('role1', [role1_pubkey], [target3])
    repository.targets('role1').load_signing_key(role1_privkey)

    # (6) Write repository.
    repository.writeall()

    self.assertTrue(os.path.exists(os.path.join(metadata_directory, 'root.json')))
    self.assertTrue(os.path.exists(os.path.join(metadata_directory, '1.root.json')))


    # Verify that the expected metadata is written.
    root_filepath = os.path.join(metadata_directory, 'root.json')
    root_1_filepath = os.path.join(metadata_directory, '1.root.json')
    root_2_filepath = os.path.join(metadata_directory, '2.root.json')
    old_root_signable = securesystemslib.util.load_json_file(root_filepath)
    root_1_signable = securesystemslib.util.load_json_file(root_1_filepath)

    # Make a change to the root keys
    repository.root.add_verification_key(targets_pubkey)
    repository.root.load_signing_key(targets_privkey)
    repository.root.threshold = 2
    repository.writeall()

    new_root_signable = securesystemslib.util.load_json_file(root_filepath)
    root_2_signable = securesystemslib.util.load_json_file(root_2_filepath)

    for role_signable in [old_root_signable, new_root_signable, root_1_signable, root_2_signable]:
      # Raise 'securesystemslib.exceptions.FormatError' if 'role_signable' is an
      # invalid signable.
      tuf.formats.check_signable_object_format(role_signable)

    # Verify contents of versioned roots
    self.assertEqual(old_root_signable, root_1_signable)
    self.assertEqual(new_root_signable, root_2_signable)

    self.assertEqual(root_1_signable['signed']['version'], 1)
    self.assertEqual(root_2_signable['signed']['version'], 2)

    repository.root.remove_verification_key(root_pubkey)
    repository.root.unload_signing_key(root_privkey)
    repository.root.threshold = 2

    # Errors, not enough signing keys to satisfy old threshold
    self.assertRaises(tuf.exceptions.UnsignedMetadataError, repository.writeall)

    # No error, write() ignore's root's threshold and allows it to be written
    # to disk partially signed.
    repository.write('root')



if __name__ == '__main__':
  unittest.main()
