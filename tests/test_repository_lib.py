#!/usr/bin/env python

# Copyright 2014 - 2017, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
<Program Name>
  test_repository_lib.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  June 1, 2014.

<Copyright>
  See LICENSE-MIT OR LICENSE for licensing information.

<Purpose>
  Unit test for 'repository_lib.py'.
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
import datetime
import logging
import tempfile
import json
import shutil
import stat
import sys
import unittest
import platform

import tuf
import tuf.formats
import tuf.log
import tuf.formats
import tuf.roledb
import tuf.keydb
import tuf.settings

import tuf.repository_lib as repo_lib
import tuf.repository_tool as repo_tool

import securesystemslib
import securesystemslib.exceptions
import securesystemslib.rsa_keys
import securesystemslib.interface
import securesystemslib.storage
import six

logger = logging.getLogger(__name__)

repo_lib.disable_console_log_messages()

TOP_LEVEL_METADATA_FILES = ['root.json', 'targets.json', 'timestamp.json',
                            'snapshot.json']


class TestRepositoryToolFunctions(unittest.TestCase):
  @classmethod
  def setUpClass(cls):

    # setUpClass() is called before tests in an individual class are executed.

    # Create a temporary directory to store the repository, metadata, and target
    # files.  'temporary_directory' must be deleted in TearDownClass() so that
    # temporary files are always removed, even when exceptions occur.
    tuf.roledb.clear_roledb(clear_all=True)
    tuf.keydb.clear_keydb(clear_all=True)
    cls.temporary_directory = tempfile.mkdtemp(dir=os.getcwd())



  @classmethod
  def tearDownClass(cls):

    # tearDownModule() is called after all the tests have run.
    # http://docs.python.org/2/library/unittest.html#class-and-module-fixtures

    # Remove the temporary repository directory, which should contain all the
    # metadata, targets, and key files generated for the test cases.
    tuf.roledb.clear_roledb(clear_all=True)
    tuf.keydb.clear_keydb(clear_all=True)

    shutil.rmtree(cls.temporary_directory)


  def setUp(self):
    tuf.roledb.create_roledb('test_repository')
    tuf.keydb.create_keydb('test_repository')


  def tearDown(self):
    tuf.roledb.clear_roledb(clear_all=True)
    tuf.keydb.clear_keydb(clear_all=True)



  def test_import_rsa_privatekey_from_file(self):
    # Test normal case.
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)

    # Load one of the pre-generated key files from 'tuf/tests/repository_data'.
    # 'password' unlocks the pre-generated key files.
    key_filepath = os.path.join('repository_data', 'keystore',
                                'root_key')
    self.assertTrue(os.path.exists(key_filepath))

    imported_rsa_key = repo_lib.import_rsa_privatekey_from_file(key_filepath,
                                                                 'password')
    self.assertTrue(securesystemslib.formats.RSAKEY_SCHEMA.matches(imported_rsa_key))


    # Test improperly formatted argument.
    self.assertRaises(securesystemslib.exceptions.FormatError,
                      repo_lib.import_rsa_privatekey_from_file, 3, 'pw')


    # Test invalid argument.
    # Non-existent key file.
    nonexistent_keypath = os.path.join(temporary_directory,
                                       'nonexistent_keypath')
    self.assertRaises(securesystemslib.exceptions.StorageError,
        repo_lib.import_rsa_privatekey_from_file,
        nonexistent_keypath, 'pw')

    # Invalid key file argument.
    invalid_keyfile = os.path.join(temporary_directory, 'invalid_keyfile')
    with open(invalid_keyfile, 'wb') as file_object:
      file_object.write(b'bad keyfile')
    self.assertRaises(securesystemslib.exceptions.CryptoError, repo_lib.import_rsa_privatekey_from_file,
                      invalid_keyfile, 'pw')



  def test_import_ed25519_privatekey_from_file(self):
    # Test normal case.
    # Generate ed25519 keys that can be imported.
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)
    ed25519_keypath = os.path.join(temporary_directory, 'ed25519_key')
    securesystemslib.interface.generate_and_write_ed25519_keypair(
        ed25519_keypath, password='pw')

    imported_ed25519_key = \
      repo_lib.import_ed25519_privatekey_from_file(ed25519_keypath, 'pw')
    self.assertTrue(securesystemslib.formats.ED25519KEY_SCHEMA.matches(imported_ed25519_key))


    # Test improperly formatted argument.
    self.assertRaises(securesystemslib.exceptions.FormatError,
                      repo_lib.import_ed25519_privatekey_from_file, 3, 'pw')


    # Test invalid argument.
    # Non-existent key file.
    nonexistent_keypath = os.path.join(temporary_directory,
                                       'nonexistent_keypath')
    self.assertRaises(securesystemslib.exceptions.StorageError,
                      repo_lib.import_ed25519_privatekey_from_file,
                      nonexistent_keypath, 'pw')

    # Invalid key file argument.
    invalid_keyfile = os.path.join(temporary_directory, 'invalid_keyfile')
    with open(invalid_keyfile, 'wb') as file_object:
      file_object.write(b'bad keyfile')

    self.assertRaises(securesystemslib.exceptions.Error,
        repo_lib.import_ed25519_privatekey_from_file, invalid_keyfile, 'pw')

    # Invalid private key imported (contains unexpected keytype.)
    imported_ed25519_key['keytype'] = 'invalid_keytype'

    # Use 'rsa_keys.py' to bypass the key format validation performed by
    # 'keys.py'.
    salt, iterations, derived_key = \
        securesystemslib.rsa_keys._generate_derived_key('pw')

    # Store the derived key info in a dictionary, the object expected
    # by the non-public _encrypt() routine.
    derived_key_information = {'salt': salt, 'iterations': iterations,
        'derived_key': derived_key}

    # Convert the key object to json string format and encrypt it with the
    # derived key.
    encrypted_key = securesystemslib.rsa_keys._encrypt(
          json.dumps(imported_ed25519_key), derived_key_information)

    with open(ed25519_keypath, 'wb') as file_object:
        file_object.write(encrypted_key.encode('utf-8'))

    self.assertRaises(securesystemslib.exceptions.FormatError,
        repo_lib.import_ed25519_privatekey_from_file, ed25519_keypath, 'pw')



  def test_get_top_level_metadata_filenames(self):

    # Test normal case.
    metadata_directory = os.path.join('metadata/')
    filenames = {'root.json': metadata_directory + 'root.json',
                 'targets.json': metadata_directory + 'targets.json',
                 'snapshot.json': metadata_directory + 'snapshot.json',
                 'timestamp.json': metadata_directory + 'timestamp.json'}

    self.assertEqual(filenames,
        repo_lib.get_top_level_metadata_filenames('metadata/'))

    # If a directory argument is not specified, the current working directory
    # is used.
    metadata_directory = os.getcwd()
    filenames = {'root.json': os.path.join(metadata_directory, 'root.json'),
                 'targets.json': os.path.join(metadata_directory, 'targets.json'),
                 'snapshot.json': os.path.join(metadata_directory, 'snapshot.json'),
                 'timestamp.json': os.path.join(metadata_directory, 'timestamp.json')}
    self.assertEqual(filenames,
        repo_lib.get_top_level_metadata_filenames(metadata_directory))


    # Test improperly formatted argument.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        repo_lib.get_top_level_metadata_filenames, 3)



  def test_get_targets_metadata_fileinfo(self):
    # Test normal case.
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)
    test_filepath = os.path.join(temporary_directory, 'file.txt')

    with open(test_filepath, 'wt') as file_object:
      file_object.write('test file')

    # Generate test fileinfo object.  It is assumed SHA256 and SHA512 hashes
    # are computed by get_targets_metadata_fileinfo().
    file_length = os.path.getsize(test_filepath)
    sha256_digest_object = securesystemslib.hash.digest_filename(test_filepath)
    sha512_digest_object = securesystemslib.hash.digest_filename(test_filepath, algorithm='sha512')
    file_hashes = {'sha256': sha256_digest_object.hexdigest(),
                   'sha512': sha512_digest_object.hexdigest()}
    fileinfo = {'length': file_length, 'hashes': file_hashes}
    self.assertTrue(tuf.formats.TARGETS_FILEINFO_SCHEMA.matches(fileinfo))

    storage_backend = securesystemslib.storage.FilesystemBackend()

    self.assertEqual(fileinfo, repo_lib.get_targets_metadata_fileinfo(test_filepath,
                                                                      storage_backend))


    # Test improperly formatted argument.
    self.assertRaises(securesystemslib.exceptions.FormatError,
                      repo_lib.get_targets_metadata_fileinfo, 3,
                      storage_backend)


    # Test non-existent file.
    nonexistent_filepath = os.path.join(temporary_directory, 'oops.txt')
    self.assertRaises(securesystemslib.exceptions.Error,
                      repo_lib.get_targets_metadata_fileinfo,
                      nonexistent_filepath, storage_backend)



  def test_get_target_hash(self):
    # Test normal case.
    expected_target_hashes = {
      '/file1.txt': 'e3a3d89eb3b70ce3fbce6017d7b8c12d4abd5635427a0e8a238f53157df85b3d',
      '/README.txt': '8faee106f1bb69f34aaf1df1e3c2e87d763c4d878cb96b91db13495e32ceb0b0',
      '/packages/file2.txt': 'c9c4a5cdd84858dd6a23d98d7e6e6b2aec45034946c16b2200bc317c75415e92'
    }
    for filepath, target_hash in six.iteritems(expected_target_hashes):
      self.assertTrue(tuf.formats.RELPATH_SCHEMA.matches(filepath))
      self.assertTrue(securesystemslib.formats.HASH_SCHEMA.matches(target_hash))
      self.assertEqual(repo_lib.get_target_hash(filepath), target_hash)

    # Test for improperly formatted argument.
    self.assertRaises(securesystemslib.exceptions.FormatError, repo_lib.get_target_hash, 8)



  def test_generate_root_metadata(self):
    # Test normal case.
    # Load the root metadata provided in 'tuf/tests/repository_data/'.
    root_filepath = os.path.join('repository_data', 'repository',
                                 'metadata', 'root.json')
    root_signable = securesystemslib.util.load_json_file(root_filepath)

    # generate_root_metadata() expects the top-level roles and keys to be
    # available in 'tuf.keydb' and 'tuf.roledb'.
    tuf.roledb.create_roledb_from_root_metadata(root_signable['signed'])
    tuf.keydb.create_keydb_from_root_metadata(root_signable['signed'])
    expires = '1985-10-21T01:22:00Z'

    root_metadata = repo_lib.generate_root_metadata(1, expires,
                                                    consistent_snapshot=False)
    self.assertTrue(tuf.formats.ROOT_SCHEMA.matches(root_metadata))

    root_keyids = tuf.roledb.get_role_keyids('root')
    tuf.keydb._keydb_dict['default'][root_keyids[0]]['keytype'] = 'bad_keytype'
    self.assertRaises(securesystemslib.exceptions.Error, repo_lib.generate_root_metadata, 1,
                      expires, consistent_snapshot=False)

    # Reset the root key's keytype, so that we can next verify that a different
    # securesystemslib.exceptions.Error exception is raised for duplicate keyids.
    tuf.keydb._keydb_dict['default'][root_keyids[0]]['keytype'] = 'rsa'

    # Add duplicate keyid to root's roleinfo.
    tuf.roledb._roledb_dict['default']['root']['keyids'].append(root_keyids[0])
    self.assertRaises(securesystemslib.exceptions.Error, repo_lib.generate_root_metadata, 1,
                      expires, consistent_snapshot=False)

    # Test improperly formatted arguments.
    self.assertRaises(securesystemslib.exceptions.FormatError, repo_lib.generate_root_metadata,
                      '3', expires, False)
    self.assertRaises(securesystemslib.exceptions.FormatError, repo_lib.generate_root_metadata,
                      1, '3', False)
    self.assertRaises(securesystemslib.exceptions.FormatError, repo_lib.generate_root_metadata,
                      1, expires, 3)

    # Test for missing required roles and keys.
    tuf.roledb.clear_roledb()
    tuf.keydb.clear_keydb()
    self.assertRaises(securesystemslib.exceptions.Error, repo_lib.generate_root_metadata,
                      1, expires, False)



  def test_generate_targets_metadata(self):
    # Test normal case.
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)
    targets_directory = os.path.join(temporary_directory, 'targets')
    file1_path = os.path.join(targets_directory, 'file.txt')
    securesystemslib.util.ensure_parent_dir(file1_path)

    with open(file1_path, 'wt') as file_object:
      file_object.write('test file.')

    # Set valid generate_targets_metadata() arguments.  Add a custom field for
    # the 'target_files' target set below.
    version = 1
    datetime_object = datetime.datetime(2030, 1, 1, 12, 0)
    expiration_date = datetime_object.isoformat() + 'Z'
    file_permissions = oct(os.stat(file1_path).st_mode)[4:]
    target_files = {'file.txt': {'custom': {'file_permission': file_permissions}}}

    delegations = {"keys": {
      "a394c28384648328b16731f81440d72243c77bb44c07c040be99347f0df7d7bf": {
       "keytype": "ed25519",
       "keyval": {
        "public": "3eb81026ded5af2c61fb3d4b272ac53cd1049a810ee88f4df1fc35cdaf918157"
       }
      }
     },
     "roles": [
      {
       "keyids": [
        "a394c28384648328b16731f81440d72243c77bb44c07c040be99347f0df7d7bf"
       ],
       "name": "targets/warehouse",
       "paths": [
        "/file1.txt", "/README.txt", '/warehouse/'
       ],
       "threshold": 1
      }
     ]
    }

    targets_metadata = \
      repo_lib.generate_targets_metadata(targets_directory, target_files,
                                         version, expiration_date, delegations,
                                         False)
    self.assertTrue(tuf.formats.TARGETS_SCHEMA.matches(targets_metadata))

    # Valid arguments with 'delegations' set to None.
    targets_metadata = \
      repo_lib.generate_targets_metadata(targets_directory, target_files,
                                         version, expiration_date, None,
                                         False)
    self.assertTrue(tuf.formats.TARGETS_SCHEMA.matches(targets_metadata))

    # Verify that 'digest.filename' file is saved to 'targets_directory' if
    # the 'write_consistent_targets' argument is True.
    list_targets_directory = os.listdir(targets_directory)
    targets_metadata = \
      repo_lib.generate_targets_metadata(targets_directory, target_files,
                                          version, expiration_date, delegations,
                                          write_consistent_targets=True)
    new_list_targets_directory = os.listdir(targets_directory)

    # Verify that 'targets_directory' contains only one extra item.
    self.assertTrue(len(list_targets_directory) + 1,
                    len(new_list_targets_directory))

    # Verify that an exception is not raised if the target files already exist.
    repo_lib.generate_targets_metadata(targets_directory, target_files,
                                       version, expiration_date, delegations,
                                       write_consistent_targets=True)


    # Verify that 'targets_metadata' contains a 'custom' entry (optional)
    # for 'file.txt'.
    self.assertTrue('custom' in targets_metadata['targets']['file.txt'])

    # Test improperly formatted arguments.
    self.assertRaises(securesystemslib.exceptions.FormatError, repo_lib.generate_targets_metadata,
                      3, target_files, version, expiration_date)
    self.assertRaises(securesystemslib.exceptions.FormatError, repo_lib.generate_targets_metadata,
                      targets_directory, 3, version, expiration_date)
    self.assertRaises(securesystemslib.exceptions.FormatError, repo_lib.generate_targets_metadata,
                      targets_directory, target_files, '3', expiration_date)
    self.assertRaises(securesystemslib.exceptions.FormatError, repo_lib.generate_targets_metadata,
                      targets_directory, target_files, version, '3')

    # Improperly formatted 'delegations' and 'write_consistent_targets'
    self.assertRaises(securesystemslib.exceptions.FormatError, repo_lib.generate_targets_metadata,
                      targets_directory, target_files, version, expiration_date,
                      3, False)
    self.assertRaises(securesystemslib.exceptions.FormatError, repo_lib.generate_targets_metadata,
                      targets_directory, target_files, version, expiration_date,
                      delegations, 3)

    # Test non-existent target file.
    bad_target_file = \
      {'non-existent.txt': {'file_permission': file_permissions}}

    self.assertRaises(securesystemslib.exceptions.Error, repo_lib.generate_targets_metadata,
                      targets_directory, bad_target_file, version,
                      expiration_date)



  def _setup_generate_snapshot_metadata_test(self):
    # Test normal case.
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)
    original_repository_path = os.path.join('repository_data',
                                            'repository')
    repository_directory = os.path.join(temporary_directory, 'repository')
    shutil.copytree(original_repository_path, repository_directory)
    metadata_directory = os.path.join(repository_directory,
                                      repo_lib.METADATA_STAGED_DIRECTORY_NAME)

    targets_directory = os.path.join(repository_directory, repo_lib.TARGETS_DIRECTORY_NAME)

    version = 1
    expiration_date = '1985-10-21T13:20:00Z'

    # Load a valid repository so that top-level roles exist in roledb and
    # generate_snapshot_metadata() has roles to specify in snapshot metadata.
    storage_backend = securesystemslib.storage.FilesystemBackend()
    repository = repo_tool.Repository(repository_directory, metadata_directory,
                                      targets_directory, storage_backend)
    repository_junk = repo_tool.load_repository(repository_directory)

    # Load a valid repository so that top-level roles exist in roledb and
    # generate_snapshot_metadata() has roles to specify in snapshot metadata.
    storage_backend = securesystemslib.storage.FilesystemBackend()

    # For testing purposes, store an invalid metadata file in the metadata directory
    # to verify that it isn't loaded by generate_snapshot_metadata().  Unknown
    # metadata file extensions should be ignored.
    invalid_metadata_file = os.path.join(metadata_directory, 'role_file.xml')
    with open(invalid_metadata_file, 'w') as file_object:
      file_object.write('bad extension on metadata file')

    return metadata_directory, version, expiration_date, \
      storage_backend


  def test_generate_snapshot_metadata(self):
    metadata_directory, version, expiration_date, storage_backend = \
        self._setup_generate_snapshot_metadata_test()

    snapshot_metadata = \
      repo_lib.generate_snapshot_metadata(metadata_directory, version,
                                          expiration_date,
                                          storage_backend,
                                          consistent_snapshot=False)
    self.assertTrue(tuf.formats.SNAPSHOT_SCHEMA.matches(snapshot_metadata))


    # Test improperly formatted arguments.
    self.assertRaises(securesystemslib.exceptions.FormatError, repo_lib.generate_snapshot_metadata,
                      3, version, expiration_date, consistent_snapshot=False,
                      storage_backend=storage_backend)
    self.assertRaises(securesystemslib.exceptions.FormatError, repo_lib.generate_snapshot_metadata,
                      metadata_directory, '3', expiration_date, storage_backend,
                      consistent_snapshot=False)
    self.assertRaises(securesystemslib.exceptions.FormatError, repo_lib.generate_snapshot_metadata,
                      metadata_directory, version, '3', storage_backend,
                      consistent_snapshot=False)
    self.assertRaises(securesystemslib.exceptions.FormatError, repo_lib.generate_snapshot_metadata,
                      metadata_directory, version, expiration_date, 3,
                      storage_backend)



  def test_generate_snapshot_metadata_with_length(self):
    metadata_directory, version, expiration_date, storage_backend = \
        self._setup_generate_snapshot_metadata_test()

    snapshot_metadata = \
      repo_lib.generate_snapshot_metadata(metadata_directory, version,
                                          expiration_date,
                                          storage_backend,
                                          consistent_snapshot=False,
                                          use_length=True)
    self.assertTrue(tuf.formats.SNAPSHOT_SCHEMA.matches(snapshot_metadata))

    metadata_files_info_dict = snapshot_metadata['meta']
    for metadata_filename in sorted(os.listdir(metadata_directory), reverse=True):

      # In the metadata_directory, there are files with format:
      # 1.root.json. The prefix number should be removed.
      stripped_filename, version = \
        repo_lib._strip_version_number(metadata_filename,
                                       consistent_snapshot=True)

      # In the repository, the file "role_file.xml" have been added to make
      # sure that non-json files aren't loaded. This file should be filtered.
      if stripped_filename.endswith('.json'):
        if stripped_filename not in TOP_LEVEL_METADATA_FILES:
          # Check that length is not calculated but hashes is
          self.assertIn('length', metadata_files_info_dict[stripped_filename])
          self.assertNotIn('hashes', metadata_files_info_dict[stripped_filename])



  def test_generate_snapshot_metadata_with_hashes(self):
    metadata_directory, version, expiration_date, storage_backend = \
        self._setup_generate_snapshot_metadata_test()

    snapshot_metadata = \
      repo_lib.generate_snapshot_metadata(metadata_directory, version,
                                          expiration_date,
                                          storage_backend,
                                          consistent_snapshot=False,
                                          use_hashes=True)
    self.assertTrue(tuf.formats.SNAPSHOT_SCHEMA.matches(snapshot_metadata))

    metadata_files_info_dict = snapshot_metadata['meta']
    for metadata_filename in sorted(os.listdir(metadata_directory), reverse=True):

      # In the metadata_directory, there are files with format:
      # 1.root.json. The prefix number should be removed.
      stripped_filename, version = \
        repo_lib._strip_version_number(metadata_filename,
                                       consistent_snapshot=True)

      # In the repository, the file "role_file.xml" have been added to make
      # sure that non-json files aren't loaded. This file should be filtered.
      if stripped_filename.endswith('.json'):
        if stripped_filename not in TOP_LEVEL_METADATA_FILES:
          # Check that hashes is not calculated but length is
          self.assertNotIn('length', metadata_files_info_dict[stripped_filename])
          self.assertIn('hashes', metadata_files_info_dict[stripped_filename])



  def test_generate_snapshot_metadata_with_hashes_and_length(self):
    metadata_directory, version, expiration_date, storage_backend = \
        self._setup_generate_snapshot_metadata_test()

    snapshot_metadata = \
      repo_lib.generate_snapshot_metadata(metadata_directory, version,
                                          expiration_date,
                                          storage_backend,
                                          consistent_snapshot=False,
                                          use_length=True,
                                          use_hashes=True)
    self.assertTrue(tuf.formats.SNAPSHOT_SCHEMA.matches(snapshot_metadata))

    metadata_files_info_dict = snapshot_metadata['meta']
    for metadata_filename in sorted(os.listdir(metadata_directory), reverse=True):

      # In the metadata_directory, there are files with format:
      # 1.root.json. The prefix number should be removed.
      stripped_filename, version = \
        repo_lib._strip_version_number(metadata_filename,
                                       consistent_snapshot=True)

      # In the repository, the file "role_file.xml" have been added to make
      # sure that non-json files aren't loaded. This file should be filtered.
      if stripped_filename.endswith('.json'):
        if stripped_filename not in TOP_LEVEL_METADATA_FILES:
          # Check that both length and hashes are not are not calculated
          self.assertIn('length', metadata_files_info_dict[stripped_filename])
          self.assertIn('hashes', metadata_files_info_dict[stripped_filename])



  def _setup_generate_timestamp_metadata_test(self):
    # Test normal case.
    repository_name = 'test_repository'
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)
    original_repository_path = os.path.join('repository_data',
                                            'repository')
    repository_directory = os.path.join(temporary_directory, 'repository')
    shutil.copytree(original_repository_path, repository_directory)
    metadata_directory = os.path.join(repository_directory,
                                      repo_lib.METADATA_STAGED_DIRECTORY_NAME)
    targets_directory = os.path.join(repository_directory, repo_lib.TARGETS_DIRECTORY_NAME)

    snapshot_file_path = os.path.join(metadata_directory,
                                      repo_lib.SNAPSHOT_FILENAME)

    # Set valid generate_timestamp_metadata() arguments.
    version = 1
    expiration_date = '1985-10-21T13:20:00Z'

    storage_backend = securesystemslib.storage.FilesystemBackend()
    # Load a valid repository so that top-level roles exist in roledb and
    # generate_snapshot_metadata() has roles to specify in snapshot metadata.
    repository = repo_tool.Repository(repository_directory, metadata_directory,
        targets_directory, repository_name)

    repository_junk = repo_tool.load_repository(repository_directory,
        repository_name)

    return snapshot_file_path, version, expiration_date, storage_backend, \
        repository_name


  def test_generate_timestamp_metadata(self):
    snapshot_file_path, version, expiration_date, storage_backend, \
      repository_name = self._setup_generate_timestamp_metadata_test()

    timestamp_metadata = repo_lib.generate_timestamp_metadata(snapshot_file_path,
        version, expiration_date, storage_backend, repository_name)
    self.assertTrue(tuf.formats.TIMESTAMP_SCHEMA.matches(timestamp_metadata))


    # Test improperly formatted arguments.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        repo_lib.generate_timestamp_metadata, 3, version, expiration_date,
        storage_backend, repository_name)
    self.assertRaises(securesystemslib.exceptions.FormatError,
        repo_lib.generate_timestamp_metadata, snapshot_file_path, '3',
        expiration_date, storage_backend, repository_name)
    self.assertRaises(securesystemslib.exceptions.FormatError,
        repo_lib.generate_timestamp_metadata, snapshot_file_path, version, '3',
        storage_backend, repository_name)



  def test_generate_timestamp_metadata_without_length(self):
    snapshot_file_path, version, expiration_date, storage_backend, \
      repository_name = self._setup_generate_timestamp_metadata_test()

    timestamp_metadata = repo_lib.generate_timestamp_metadata(snapshot_file_path,
        version, expiration_date, storage_backend, repository_name,
        use_length=False)
    self.assertTrue(tuf.formats.TIMESTAMP_SCHEMA.matches(timestamp_metadata))

    # Check that length is not calculated but hashes is
    timestamp_file_info = timestamp_metadata['meta']

    self.assertNotIn('length', timestamp_file_info['snapshot.json'])
    self.assertIn('hashes', timestamp_file_info['snapshot.json'])



  def test_generate_timestamp_metadata_without_hashes(self):
    snapshot_file_path, version, expiration_date, storage_backend, \
      repository_name = self._setup_generate_timestamp_metadata_test()

    timestamp_metadata = repo_lib.generate_timestamp_metadata(snapshot_file_path,
        version, expiration_date, storage_backend, repository_name,
        use_hashes=False)
    self.assertTrue(tuf.formats.TIMESTAMP_SCHEMA.matches(timestamp_metadata))

    # Check that hashes is not calculated but length is
    timestamp_file_info = timestamp_metadata['meta']

    self.assertIn('length', timestamp_file_info['snapshot.json'])
    self.assertNotIn('hashes', timestamp_file_info['snapshot.json'])



  def test_generate_timestamp_metadata_without_length_and_hashes(self):
    snapshot_file_path, version, expiration_date, storage_backend, \
      repository_name = self._setup_generate_timestamp_metadata_test()

    timestamp_metadata = repo_lib.generate_timestamp_metadata(snapshot_file_path,
        version, expiration_date, storage_backend, repository_name,
        use_hashes=False, use_length=False)
    self.assertTrue(tuf.formats.TIMESTAMP_SCHEMA.matches(timestamp_metadata))

    # Check that length and hashes attributes are not added
    timestamp_file_info = timestamp_metadata['meta']
    self.assertNotIn('length', timestamp_file_info['snapshot.json'])
    self.assertNotIn('hashes', timestamp_file_info['snapshot.json'])



  def test_sign_metadata(self):
    # Test normal case.
    repository_name = 'test_repository'
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)
    metadata_path = os.path.join('repository_data', 'repository', 'metadata')
    keystore_path = os.path.join('repository_data', 'keystore')
    root_filename = os.path.join(metadata_path, 'root.json')
    root_metadata = securesystemslib.util.load_json_file(root_filename)['signed']
    targets_filename = os.path.join(metadata_path, 'targets.json')
    targets_metadata = securesystemslib.util.load_json_file(targets_filename)['signed']

    tuf.keydb.create_keydb_from_root_metadata(root_metadata, repository_name)
    tuf.roledb.create_roledb_from_root_metadata(root_metadata, repository_name)
    root_keyids = tuf.roledb.get_role_keyids('root', repository_name)
    targets_keyids = tuf.roledb.get_role_keyids('targets', repository_name)

    root_private_keypath = os.path.join(keystore_path, 'root_key')
    root_private_key = repo_lib.import_rsa_privatekey_from_file(root_private_keypath,
        'password')

    # Sign with a valid, but not a threshold, key.
    targets_public_keypath = os.path.join(keystore_path, 'targets_key.pub')
    targets_public_key = securesystemslib.interface.\
        import_ed25519_publickey_from_file(targets_public_keypath)

    # sign_metadata() expects the private key 'root_metadata' to be in
    # 'tuf.keydb'.  Remove any public keys that may be loaded before
    # adding private key, otherwise a 'tuf.KeyAlreadyExists' exception is
    # raised.
    tuf.keydb.remove_key(root_private_key['keyid'],
        repository_name=repository_name)
    tuf.keydb.add_key(root_private_key, repository_name=repository_name)
    tuf.keydb.remove_key(targets_public_key['keyid'], repository_name=repository_name)
    tuf.keydb.add_key(targets_public_key, repository_name=repository_name)

    # Verify that a valid root signable is generated.
    root_signable = repo_lib.sign_metadata(root_metadata, root_keyids,
        root_filename, repository_name)
    self.assertTrue(tuf.formats.SIGNABLE_SCHEMA.matches(root_signable))

    # Test for an unset private key (in this case, target's).
    repo_lib.sign_metadata(targets_metadata, targets_keyids, targets_filename,
        repository_name)

    # Add an invalid keytype to one of the root keys.
    root_keyid = root_keyids[0]
    tuf.keydb._keydb_dict[repository_name][root_keyid]['keytype'] = 'bad_keytype'
    self.assertRaises(securesystemslib.exceptions.Error, repo_lib.sign_metadata,
        root_metadata, root_keyids, root_filename, repository_name)

    # Test improperly formatted arguments.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        repo_lib.sign_metadata, 3, root_keyids, 'root.json', repository_name)
    self.assertRaises(securesystemslib.exceptions.FormatError,
        repo_lib.sign_metadata, root_metadata, 3, 'root.json', repository_name)
    self.assertRaises(securesystemslib.exceptions.FormatError,
        repo_lib.sign_metadata, root_metadata, root_keyids, 3, repository_name)



  def test_write_metadata_file(self):
    # Test normal case.
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)
    metadata_directory = os.path.join('repository_data', 'repository', 'metadata')
    root_filename = os.path.join(metadata_directory, 'root.json')
    root_signable = securesystemslib.util.load_json_file(root_filename)

    output_filename = os.path.join(temporary_directory, 'root.json')
    version_number = root_signable['signed']['version'] + 1

    self.assertFalse(os.path.exists(output_filename))
    storage_backend = securesystemslib.storage.FilesystemBackend()
    repo_lib.write_metadata_file(root_signable, output_filename, version_number,
        consistent_snapshot=False, storage_backend=storage_backend)
    self.assertTrue(os.path.exists(output_filename))

    # Attempt to over-write the previously written metadata file.  An exception
    # is not raised in this case, only a debug message is logged.
    repo_lib.write_metadata_file(root_signable, output_filename, version_number,
        consistent_snapshot=False, storage_backend=storage_backend)

    # Test improperly formatted arguments.
    self.assertRaises(securesystemslib.exceptions.FormatError, repo_lib.write_metadata_file,
        3, output_filename, version_number, False, storage_backend)
    self.assertRaises(securesystemslib.exceptions.FormatError, repo_lib.write_metadata_file,
        root_signable, 3, version_number, False, storage_backend)
    self.assertRaises(securesystemslib.exceptions.FormatError, repo_lib.write_metadata_file,
        root_signable, output_filename, '3', False, storage_backend)
    self.assertRaises(securesystemslib.exceptions.FormatError, repo_lib.write_metadata_file,
        root_signable, output_filename, storage_backend, version_number, 3)



  def test_create_tuf_client_directory(self):
    # Test normal case.
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)
    repository_directory = os.path.join('repository_data', 'repository')
    client_directory = os.path.join(temporary_directory, 'client')

    repo_lib.create_tuf_client_directory(repository_directory, client_directory)

    self.assertTrue(os.path.exists(client_directory))
    metadata_directory = os.path.join(client_directory, 'metadata')
    current_directory = os.path.join(metadata_directory, 'current')
    previous_directory = os.path.join(metadata_directory, 'previous')
    self.assertTrue(os.path.exists(client_directory))
    self.assertTrue(os.path.exists(metadata_directory))
    self.assertTrue(os.path.exists(current_directory))
    self.assertTrue(os.path.exists(previous_directory))


    # Test improperly formatted arguments.
    self.assertRaises(securesystemslib.exceptions.FormatError,
        repo_lib.create_tuf_client_directory, 3, client_directory)
    self.assertRaises(securesystemslib.exceptions.FormatError,
        repo_lib.create_tuf_client_directory, repository_directory, 3)


    # Test invalid argument (i.e., client directory already exists.)
    self.assertRaises(tuf.exceptions.RepositoryError,
        repo_lib.create_tuf_client_directory, repository_directory,
        client_directory)

    # Test invalid client metadata directory (i.e., non-errno.EEXIST exceptions
    # should be re-raised.)
    shutil.rmtree(metadata_directory)

    # Save the original metadata directory name so that it can be restored
    # after testing.
    metadata_directory_name = repo_lib.METADATA_DIRECTORY_NAME
    repo_lib.METADATA_DIRECTORY_NAME = '/'

    # Creation of the '/' directory is forbidden on all supported OSs.  The '/'
    # argument to create_tuf_client_directory should cause it to re-raise a
    # non-errno.EEXIST exception.
    self.assertRaises((OSError, tuf.exceptions.RepositoryError),
        repo_lib.create_tuf_client_directory, repository_directory, '/')

    # Restore the metadata directory name in repo_lib.
    repo_lib.METADATA_DIRECTORY_NAME = metadata_directory_name



  def test__generate_and_write_metadata(self):
    # Test for invalid, or unsupported, rolename.
    # Load the root metadata provided in 'tuf/tests/repository_data/'.
    repository_name = 'repository_name'
    root_filepath = os.path.join('repository_data', 'repository',
                                 'metadata', 'root.json')
    root_signable = securesystemslib.util.load_json_file(root_filepath)

    # _generate_and_write_metadata() expects the top-level roles
    # (specifically 'snapshot') and keys to be available in 'tuf.roledb'.
    tuf.roledb.create_roledb_from_root_metadata(root_signable['signed'],
        repository_name)
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)
    targets_directory = os.path.join(temporary_directory, 'targets')
    os.mkdir(targets_directory)
    repository_directory = os.path.join(temporary_directory, 'repository')
    metadata_directory = os.path.join(repository_directory,
        repo_lib.METADATA_STAGED_DIRECTORY_NAME)
    targets_metadata = os.path.join('repository_data', 'repository', 'metadata',
        'targets.json')
    obsolete_metadata = os.path.join(metadata_directory, 'obsolete_role.json')
    securesystemslib.util.ensure_parent_dir(obsolete_metadata)
    shutil.copyfile(targets_metadata, obsolete_metadata)

    # Verify that obsolete metadata (a metadata file exists on disk, but the
    # role is unavailable in 'tuf.roledb').  First add the obsolete
    # role to 'tuf.roledb' so that its metadata file can be written to disk.
    targets_roleinfo = tuf.roledb.get_roleinfo('targets', repository_name)
    targets_roleinfo['version'] = 1
    expiration = \
      tuf.formats.unix_timestamp_to_datetime(int(time.time() + 86400))
    expiration = expiration.isoformat() + 'Z'
    targets_roleinfo['expires'] = expiration
    tuf.roledb.add_role('obsolete_role', targets_roleinfo,
        repository_name=repository_name)

    storage_backend = securesystemslib.storage.FilesystemBackend()
    repo_lib._generate_and_write_metadata('obsolete_role', obsolete_metadata,
        targets_directory, metadata_directory, storage_backend,
        consistent_snapshot=False, filenames=None,
        repository_name=repository_name)

    snapshot_filepath = os.path.join('repository_data', 'repository',
                                     'metadata', 'snapshot.json')
    snapshot_signable = securesystemslib.util.load_json_file(snapshot_filepath)
    tuf.roledb.remove_role('obsolete_role', repository_name)
    self.assertTrue(os.path.exists(os.path.join(metadata_directory,
                                                'obsolete_role.json')))
    tuf.repository_lib._delete_obsolete_metadata(metadata_directory,
        snapshot_signable['signed'], False, repository_name,
        storage_backend)
    self.assertFalse(os.path.exists(metadata_directory + 'obsolete_role.json'))
    shutil.copyfile(targets_metadata, obsolete_metadata)



  def test__delete_obsolete_metadata(self):
    repository_name = 'test_repository'
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)
    repository_directory = os.path.join(temporary_directory, 'repository')
    metadata_directory = os.path.join(repository_directory,
        repo_lib.METADATA_STAGED_DIRECTORY_NAME)
    os.makedirs(metadata_directory)
    snapshot_filepath = os.path.join('repository_data', 'repository',
        'metadata', 'snapshot.json')
    snapshot_signable = securesystemslib.util.load_json_file(snapshot_filepath)
    storage_backend = securesystemslib.storage.FilesystemBackend()

    # Create role metadata that should not exist in snapshot.json.
    role1_filepath = os.path.join('repository_data', 'repository', 'metadata',
        'role1.json')
    shutil.copyfile(role1_filepath, os.path.join(metadata_directory, 'role2.json'))

    repo_lib._delete_obsolete_metadata(metadata_directory,
        snapshot_signable['signed'], True, repository_name, storage_backend)

    # _delete_obsolete_metadata should never delete root.json.
    root_filepath = os.path.join('repository_data', 'repository', 'metadata',
        'root.json')
    shutil.copyfile(root_filepath, os.path.join(metadata_directory, 'root.json'))
    repo_lib._delete_obsolete_metadata(metadata_directory,
        snapshot_signable['signed'], True, repository_name, storage_backend)
    self.assertTrue(os.path.exists(os.path.join(metadata_directory, 'root.json')))

    # Verify what happens for a non-existent metadata directory (a debug
    # message is logged).
    self.assertRaises(securesystemslib.exceptions.StorageError,
        repo_lib._delete_obsolete_metadata, 'non-existent',
        snapshot_signable['signed'], True, repository_name, storage_backend)


  def test__load_top_level_metadata(self):
    repository_name = 'test_repository'

    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)
    repository_directory = os.path.join(temporary_directory, 'repository')
    metadata_directory = os.path.join(repository_directory,
        repo_lib.METADATA_STAGED_DIRECTORY_NAME)
    targets_directory = os.path.join(repository_directory,
        repo_lib.TARGETS_DIRECTORY_NAME)
    shutil.copytree(os.path.join('repository_data', 'repository', 'metadata'),
        metadata_directory)
    shutil.copytree(os.path.join('repository_data', 'repository', 'targets'),
        targets_directory)

    # Add a duplicate signature to the Root file for testing purposes).
    root_file = os.path.join(metadata_directory, 'root.json')
    signable = securesystemslib.util.load_json_file(os.path.join(metadata_directory, 'root.json'))
    signable['signatures'].append(signable['signatures'][0])

    storage_backend = securesystemslib.storage.FilesystemBackend()
    repo_lib.write_metadata_file(signable, root_file, 8, False, storage_backend)

    filenames = repo_lib.get_top_level_metadata_filenames(metadata_directory)
    repository = repo_tool.create_new_repository(repository_directory, repository_name)
    repo_lib._load_top_level_metadata(repository, filenames, repository_name)

    # Partially write all top-level roles (we increase the threshold of each
    # top-level role so that they are flagged as partially written.
    repository.root.threshold = repository.root.threshold + 1
    repository.snapshot.threshold = repository.snapshot.threshold + 1
    repository.targets.threshold = repository.targets.threshold + 1
    repository.timestamp.threshold = repository.timestamp.threshold + 1
    repository.write('root', )
    repository.write('snapshot')
    repository.write('targets')
    repository.write('timestamp')

    repo_lib._load_top_level_metadata(repository, filenames, repository_name)

    # Attempt to load a repository with missing top-level metadata.
    for role_file in os.listdir(metadata_directory):
      if role_file.endswith('.json') and not role_file.startswith('root'):
        role_filename = os.path.join(metadata_directory, role_file)
        os.remove(role_filename)
    self.assertRaises(tuf.exceptions.RepositoryError,
        repo_lib._load_top_level_metadata, repository, filenames,
        repository_name)

    # Remove the required Root file and verify that an exception is raised.
    os.remove(os.path.join(metadata_directory, 'root.json'))
    self.assertRaises(tuf.exceptions.RepositoryError,
        repo_lib._load_top_level_metadata, repository, filenames,
        repository_name)



  def test__remove_invalid_and_duplicate_signatures(self):
    # Remove duplicate PSS signatures (same key generates valid, but different
    # signatures).  First load a valid signable (in this case, the root role).
    repository_name = 'test_repository'
    root_filepath = os.path.join('repository_data', 'repository',
        'metadata', 'root.json')
    root_signable = securesystemslib.util.load_json_file(root_filepath)
    key_filepath = os.path.join('repository_data', 'keystore', 'root_key')
    root_rsa_key = repo_lib.import_rsa_privatekey_from_file(key_filepath,
        'password')

    # Add 'root_rsa_key' to tuf.keydb, since
    # _remove_invalid_and_duplicate_signatures() checks for unknown keys in
    # tuf.keydb.
    tuf.keydb.add_key(root_rsa_key, repository_name=repository_name)

    # Append the new valid, but duplicate PSS signature, and test that
    # duplicates are removed.  create_signature() generates a key for the
    # key type of the first argument (i.e., root_rsa_key).
    data = securesystemslib.formats.encode_canonical(root_signable['signed']).encode('utf-8')
    new_pss_signature = securesystemslib.keys.create_signature(root_rsa_key,
        data)
    root_signable['signatures'].append(new_pss_signature)

    expected_number_of_signatures = len(root_signable['signatures'])
    tuf.repository_lib._remove_invalid_and_duplicate_signatures(root_signable,
        repository_name)
    self.assertEqual(len(root_signable), expected_number_of_signatures)

    # Test for an invalid keyid.
    root_signable['signatures'][0]['keyid'] = '404'
    tuf.repository_lib._remove_invalid_and_duplicate_signatures(root_signable,
        repository_name)

    # Re-add a valid signature for the following test condition.
    root_signable['signatures'].append(new_pss_signature)

    # Test that an exception is not raised if an invalid sig is present,
    # and that the duplicate key is removed 'root_signable'.
    root_signable['signatures'][0]['sig'] = '4040'
    invalid_keyid = root_signable['signatures'][0]['keyid']
    tuf.repository_lib._remove_invalid_and_duplicate_signatures(root_signable,
        repository_name)

    for signature in root_signable['signatures']:
      self.assertFalse(invalid_keyid == signature['keyid'])



# Run the test cases.
if __name__ == '__main__':
  unittest.main()
