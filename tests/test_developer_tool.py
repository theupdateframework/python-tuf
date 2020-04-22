#!/usr/bin/env python

# Copyright 2014 - 2017, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
<Program Name>
  test_developer_tool.py.

<Authors>
  Santiago Torres Arias <torresariass@gmail.com>
  Zane Fisher <zanefisher@gmail.com>

<Started>
  January 22, 2014.

<Copyright>
  See LICENSE-MIT OR LICENSE for licensing information.

<Purpose>
  Unit test for the 'developer_tool.py' module.
"""

import os
import time
import datetime
import unittest
import logging
import tempfile
import shutil
import unittest

import tuf
import tuf.log
import tuf.roledb
import tuf.keydb
import tuf.developer_tool as developer_tool
import tuf.exceptions

import securesystemslib
import securesystemslib.exceptions

from tuf.developer_tool import METADATA_DIRECTORY_NAME
from tuf.developer_tool import TARGETS_DIRECTORY_NAME

logger = logging.getLogger(__name__)

developer_tool.disable_console_log_messages()

class TestProject(unittest.TestCase):

  tmp_dir = None

  @classmethod
  def setUpClass(cls):
    cls.tmp_dir = tempfile.mkdtemp(dir = os.getcwd())

  @classmethod
  def tearDownClass(cls):
    shutil.rmtree(cls.tmp_dir)

  def setUp(self):
    # called before every test case
    pass

  def tearDown(self):
    # called after every test case
    tuf.roledb.clear_roledb(clear_all=True)
    tuf.keydb.clear_keydb(clear_all=True)


  def test_create_new_project(self):
    # Test cases for the create_new_project function. In this test we will
    # check input, correct file creation and format. We also check
    # that a proper object is generated. We will use the normal layout for this
    # test suite.

    # Create a local subfolder for this test.
    local_tmp = tempfile.mkdtemp(dir = self.tmp_dir)

    # These are the usual values we will be throwing to the function, however
    # we will swap these for nulls or malformed values every now and then to
    # test input.
    project_name = 'test_suite'
    metadata_directory = local_tmp
    location_in_repository = '/prefix'
    targets_directory = None
    key = None

    # Create a blank project.
    project = developer_tool.create_new_project(project_name, metadata_directory,
        location_in_repository)

    self.assertTrue(isinstance(project, developer_tool.Project))
    self.assertTrue(project.layout_type == 'repo-like')
    self.assertTrue(project.prefix == location_in_repository)
    self.assertTrue(project.project_name == project_name)
    self.assertTrue(project.metadata_directory ==
        os.path.join(metadata_directory,METADATA_DIRECTORY_NAME))
    self.assertTrue(project.targets_directory ==
        os.path.join(metadata_directory,TARGETS_DIRECTORY_NAME))

    # Create a blank project without a prefix.
    project = developer_tool.create_new_project(project_name, metadata_directory)
    self.assertTrue(isinstance(project, developer_tool.Project))
    self.assertTrue(project.layout_type == 'repo-like')
    self.assertTrue(project.prefix == '')
    self.assertTrue(project.project_name == project_name)
    self.assertTrue(project.metadata_directory ==
        os.path.join(metadata_directory,METADATA_DIRECTORY_NAME))
    self.assertTrue(project.targets_directory ==
        os.path.join(metadata_directory,TARGETS_DIRECTORY_NAME))

    # Create a blank project without a valid metadata directory.
    self.assertRaises(securesystemslib.exceptions.FormatError, developer_tool.create_new_project,
       0, metadata_directory, location_in_repository)
    self.assertRaises(securesystemslib.exceptions.FormatError, developer_tool.create_new_project,
       project_name, 0, location_in_repository)
    self.assertRaises(securesystemslib.exceptions.FormatError, developer_tool.create_new_project,
       project_name, metadata_directory, 0)


    # Create a new project with a flat layout.
    targets_directory = tempfile.mkdtemp(dir = local_tmp)
    metadata_directory = tempfile.mkdtemp(dir = local_tmp)
    project = developer_tool.create_new_project(project_name, metadata_directory,
        location_in_repository, targets_directory)
    self.assertTrue(isinstance(project, developer_tool.Project))
    self.assertTrue(project.layout_type == 'flat')
    self.assertTrue(project.prefix == location_in_repository)
    self.assertTrue(project.project_name == project_name)
    self.assertTrue(project.metadata_directory == metadata_directory)
    self.assertTrue(project.targets_directory == targets_directory)

    # Finally, check that if targets_directory is set, it is valid.
    self.assertRaises(securesystemslib.exceptions.FormatError, developer_tool.create_new_project,
        project_name, metadata_directory, location_in_repository, 0)

    # Copy a key to our workspace and create a new project with it.
    keystore_path = os.path.join('repository_data','keystore')

    # I will use the same key as the one provided in the repository
    # tool tests for the root role, but this is not a root role...
    root_key_path = os.path.join(keystore_path,'root_key.pub')
    project_key = developer_tool.import_rsa_publickey_from_file(root_key_path)

    # Test create new project with a key added by default.
    project = developer_tool.create_new_project(project_name, metadata_directory,
        location_in_repository, targets_directory, project_key)

    self.assertTrue(isinstance(project, developer_tool.Project))
    self.assertTrue(project.layout_type == 'flat')
    self.assertTrue(project.prefix == location_in_repository)
    self.assertTrue(project.project_name == project_name)
    self.assertTrue(project.metadata_directory == metadata_directory)
    self.assertTrue(project.targets_directory == targets_directory)
    self.assertTrue(len(project.keys) == 1)
    self.assertTrue(project.keys[0] == project_key['keyid'])

    # Try to write to an invalid location.  The OSError should be re-raised by
    # create_new_project().
    shutil.rmtree(targets_directory)
    tuf.roledb.clear_roledb()
    tuf.keydb.clear_keydb()

    metadata_directory = '/'
    valid_metadata_directory_name = developer_tool.METADATA_DIRECTORY_NAME
    developer_tool.METADATA_DIRECTORY_NAME = '/'

    try:
      developer_tool.create_new_project(project_name, metadata_directory,
          location_in_repository, targets_directory, project_key)

    except (OSError, tuf.exceptions.RepositoryError):
      pass

    developer_tool.METADATA_DIRECTORY_NAME = valid_metadata_directory_name



  def test_load_project(self):
    # This test case will first try to load an existing project and test for
    # verify the loaded object.  It will next try to load a nonexisting project
    # and expect a correct error handler.  Finally, it will try to overwrite the
    # existing prefix of the loaded project.

    # Create a local subfolder for this test.
    local_tmp = tempfile.mkdtemp(dir = self.tmp_dir)

    # Test non-existent project filepath.
    nonexistent_path = os.path.join(local_tmp, 'nonexistent')
    self.assertRaises(securesystemslib.exceptions.StorageError,
        developer_tool.load_project, nonexistent_path)

    # Copy the pregenerated metadata.
    project_data_filepath = os.path.join('repository_data', 'project')
    target_project_data_filepath = os.path.join(local_tmp, 'project')
    shutil.copytree('repository_data/project', target_project_data_filepath)

    # Properly load a project.
    repo_filepath = os.path.join(local_tmp, 'project', 'test-flat')
    new_targets_path = os.path.join(local_tmp, 'project', 'targets')
    project = developer_tool.load_project(repo_filepath,
        new_targets_location = new_targets_path)
    self.assertTrue(project._targets_directory == new_targets_path)
    self.assertTrue(project.layout_type == 'flat')

    # Load a project overwriting the prefix.
    project = developer_tool.load_project(repo_filepath, prefix='new')
    self.assertTrue(project.prefix == 'new')

    # Load a project with a file missing.
    file_to_corrupt = os.path.join(repo_filepath, 'test-flat.json')
    with open(file_to_corrupt, 'wt') as fp:
      fp.write('this is not a json file')

    self.assertRaises(securesystemslib.exceptions.Error, developer_tool.load_project, repo_filepath)




  def test_add_verification_keys(self):
    # Create a new project instance.
    project = developer_tool.Project('test_verification_keys', 'somepath',
        'someotherpath', 'prefix')

    # Add invalid verification key.
    self.assertRaises(securesystemslib.exceptions.FormatError, project.add_verification_key, 'invalid')

    # Add verification key.
    #  - load it first
    keystore_path = os.path.join('repository_data', 'keystore')
    first_verification_key_path = os.path.join(keystore_path,'root_key.pub')
    first_verification_key = \
      developer_tool.import_rsa_publickey_from_file(first_verification_key_path)

    project.add_verification_key(first_verification_key)


    # Add another verification key (should expect exception.)
    second_verification_key_path = os.path.join(keystore_path, 'snapshot_key.pub')
    second_verification_key = \
      developer_tool.import_ed25519_publickey_from_file(second_verification_key_path)

    self.assertRaises(securesystemslib.exceptions.Error,
        project.add_verification_key,(second_verification_key))



    # Add a verification key for the delegation.
    project.delegate('somedelegation', [], [])
    project('somedelegation').add_verification_key(first_verification_key)
    project('somedelegation').add_verification_key(second_verification_key)


    # Add another delegation of the delegation.
    project('somedelegation').delegate('somesubdelegation', [], [])
    project('somesubdelegation').add_verification_key(first_verification_key)
    project('somesubdelegation').add_verification_key(second_verification_key)


  def test_write(self):

    # Create tmp directory.
    local_tmp = tempfile.mkdtemp(dir=self.tmp_dir)

    # Create new project inside tmp directory.
    project = developer_tool.create_new_project('new_project', local_tmp,
        'prefix');

    # Create some target files inside the tmp directory.
    target_filepath = os.path.join(local_tmp, 'targets', 'test_target')
    with open(target_filepath, 'wt') as fp:
      fp.write('testing file')


    # Add the targets.
    project.add_target(os.path.basename(target_filepath))

    # Add verification keys.
    keystore_path = os.path.join('repository_data', 'keystore')
    project_key_path = os.path.join(keystore_path, 'root_key.pub')
    project_key = \
      developer_tool.import_rsa_publickey_from_file(project_key_path)


    # Call status (for the sake of doing it and to improve test coverage by
    # executing its statements.)
    project.status()

    project.add_verification_key(project_key)


    # Add another verification key (should expect exception.)
    delegation_key_path = os.path.join(keystore_path, 'snapshot_key.pub')
    delegation_key = \
      developer_tool.import_ed25519_publickey_from_file(delegation_key_path)

    # Add a subdelegation.
    subdelegation_key_path = os.path.join(keystore_path, 'timestamp_key.pub')
    subdelegation_key = \
        developer_tool.import_ed25519_publickey_from_file(subdelegation_key_path)

    # Add a delegation.
    project.delegate('delegation', [delegation_key], [])
    project('delegation').delegate('subdelegation', [subdelegation_key], [])

    # call write (except)
    self.assertRaises(securesystemslib.exceptions.Error, project.write, ())

    # Call status (for the sake of doing it and executing its statements.)
    project.status()

    # Load private keys.
    project_private_key_path = os.path.join(keystore_path, 'root_key')
    project_private_key = \
        developer_tool.import_rsa_privatekey_from_file(project_private_key_path,
            'password')

    delegation_private_key_path = os.path.join(keystore_path, 'snapshot_key')
    delegation_private_key = \
        developer_tool.import_ed25519_privatekey_from_file(delegation_private_key_path,
            'password')

    subdelegation_private_key_path =  \
        os.path.join(keystore_path, 'timestamp_key')
    subdelegation_private_key = \
        developer_tool.import_ed25519_privatekey_from_file(subdelegation_private_key_path,
            'password')

    # Test partial write.
    # backup everything (again)
    # + backup targets.
    targets_backup = project.target_files

    # + backup delegations.
    delegations_backup = \
        tuf.roledb.get_delegated_rolenames(project.project_name)

    # + backup layout type.
    layout_type_backup = project.layout_type

    # + backup keyids.
    keys_backup = project.keys
    delegation_keys_backup = project('delegation').keys

    # + backup the prefix.
    prefix_backup = project.prefix

    # + backup the name.
    name_backup = project.project_name

    # Write and reload.
    self.assertRaises(securesystemslib.exceptions.Error, project.write)
    project.write(write_partial=True)

    project = developer_tool.load_project(local_tmp)

    # Check against backup.
    self.assertEqual(list(project.target_files.keys()), list(targets_backup.keys()))
    new_delegations = tuf.roledb.get_delegated_rolenames(project.project_name)
    self.assertEqual(new_delegations, delegations_backup)
    self.assertEqual(project.layout_type, layout_type_backup)
    self.assertEqual(project.keys, keys_backup)

    self.assertEqual(project('delegation').keys, delegation_keys_backup)

    self.assertEqual(project.prefix, prefix_backup)
    self.assertEqual(project.project_name, name_backup)

    roleinfo = tuf.roledb.get_roleinfo(project.project_name)

    self.assertEqual(roleinfo['partial_loaded'], True)



    # Load_signing_keys.
    project('delegation').load_signing_key(delegation_private_key)

    project.status()

    project.load_signing_key(project_private_key)

    # Backup everything.
    # + backup targets.
    targets_backup = project.target_files

    # + backup delegations.
    delegations_backup = \
        tuf.roledb.get_delegated_rolenames(project.project_name)

    # + backup layout type.
    layout_type_backup = project.layout_type

    # + backup keyids
    keys_backup = project.keys
    delegation_keys_backup = project('delegation').keys

    # + backup the prefix.
    prefix_backup = project.prefix

    # + backup the name.
    name_backup = project.project_name

    # Call status (for the sake of doing it.)
    project.status()

    # Call write.
    project.write()

    # Call load.
    project = developer_tool.load_project(local_tmp)


    # Check against backup.
    self.assertEqual(list(project.target_files.keys()), list(targets_backup.keys()))

    new_delegations = tuf.roledb.get_delegated_rolenames(project.project_name)
    self.assertEqual(new_delegations, delegations_backup)
    self.assertEqual(project.layout_type, layout_type_backup)
    self.assertEqual(project.keys, keys_backup)
    self.assertEqual(project('delegation').keys, delegation_keys_backup)
    self.assertEqual(project.prefix, prefix_backup)
    self.assertEqual(project.project_name, name_backup)



if __name__ == '__main__':
  unittest.main()
