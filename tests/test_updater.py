#!/usr/bin/env python

"""
<Program Name>
  test_updater.py

<Author>
  Konstantin Andrianov.

<Started>
  October 15, 2012.

  March 11, 2014.
    Refactored to remove mocked modules and old repository tool dependence, use
    exact repositories, and add realistic retrieval of files. -vladimir.v.diaz

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  'test_updater.py' provides a collection of methods that test the public /
  non-public methods and functions of 'tuf.client.updater.py'.

  The 'unittest_toolbox.py' module was created to provide additional testing
  tools, such as automatically deleting temporary files created in test cases.
  For more information, see 'tests/unittest_toolbox.py'.

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
import errno
import unittest

import tuf
import tuf.exceptions
import tuf.log
import tuf.formats
import tuf.keydb
import tuf.roledb
import tuf.repository_tool as repo_tool
import tuf.repository_lib as repo_lib
import tuf.unittest_toolbox as unittest_toolbox
import tuf.client.updater as updater

import securesystemslib
import six

logger = logging.getLogger('tuf.test_updater')
repo_tool.disable_console_log_messages()


class TestUpdater(unittest_toolbox.Modified_TestCase):

  @classmethod
  def setUpClass(cls):
    # setUpClass() is called before tests in an individual class are executed.

    # Create a temporary directory to store the repository, metadata, and target
    # files.  'temporary_directory' must be deleted in TearDownModule() so that
    # temporary files are always removed, even when exceptions occur.
    cls.temporary_directory = tempfile.mkdtemp(dir=os.getcwd())

    # Launch a SimpleHTTPServer (serves files in the current directory).
    # Test cases will request metadata and target files that have been
    # pre-generated in 'tuf/tests/repository_data', which will be served
    # by the SimpleHTTPServer launched here.  The test cases of 'test_updater.py'
    # assume the pre-generated metadata files have a specific structure, such
    # as a delegated role 'targets/role1', three target files, five key files,
    # etc.
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
      logger.info('\tServer process ' + str(cls.server_process.pid) + ' terminated.')
      cls.server_process.kill()



  def setUp(self):
    # We are inheriting from custom class.
    unittest_toolbox.Modified_TestCase.setUp(self)
    tuf.roledb.clear_roledb(clear_all=True)
    tuf.keydb.clear_keydb(clear_all=True)

    self.repository_name = 'test_repository'

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

  def test_1__init__exceptions(self):
    # The client's repository requires a metadata directory (and the 'current'
    # and 'previous' sub-directories), and at least the 'root.json' file.
    # setUp(), called before each test case, instantiates the required updater
    # objects and keys.  The needed objects/data is available in
    # 'self.repository_updater', 'self.client_directory', etc.


    # Test: Invalid arguments.
    # Invalid 'updater_name' argument.  String expected.
    self.assertRaises(securesystemslib.exceptions.FormatError, updater.Updater, 8,
                      self.repository_mirrors)

    # Invalid 'repository_mirrors' argument.  'tuf.formats.MIRRORDICT_SCHEMA'
    # expected.
    self.assertRaises(securesystemslib.exceptions.FormatError, updater.Updater, updater.Updater, 8)


    # 'tuf.client.updater.py' requires that the client's repositories directory
    # be configured in 'tuf.settings.py'.
    tuf.settings.repositories_directory = None
    self.assertRaises(tuf.exceptions.RepositoryError, updater.Updater, 'test_repository',
                      self.repository_mirrors)
    # Restore 'tuf.settings.repositories_directory' to the original client
    # directory.
    tuf.settings.repositories_directory = self.client_directory


    # Test: empty client repository (i.e., no metadata directory).
    metadata_backup = self.client_metadata + '.backup'
    shutil.move(self.client_metadata, metadata_backup)
    self.assertRaises(tuf.exceptions.RepositoryError, updater.Updater, 'test_repository',
                      self.repository_mirrors)
    # Restore the client's metadata directory.
    shutil.move(metadata_backup, self.client_metadata)


    # Test: repository with only a '{repository_directory}/metadata' directory.
    # (i.e., missing the required 'current' and 'previous' sub-directories).
    current_backup = self.client_metadata_current + '.backup'
    previous_backup = self.client_metadata_previous + '.backup'

    shutil.move(self.client_metadata_current, current_backup)
    shutil.move(self.client_metadata_previous, previous_backup)
    self.assertRaises(tuf.exceptions.RepositoryError, updater.Updater, 'test_repository',
                      self.repository_mirrors)

    # Restore the client's previous directory.  The required 'current' directory
    # is still missing.
    shutil.move(previous_backup, self.client_metadata_previous)

    # Test: repository with only a '{repository_directory}/metadata/previous'
    # directory.
    self.assertRaises(tuf.exceptions.RepositoryError, updater.Updater, 'test_repository',
                      self.repository_mirrors)
    # Restore the client's current directory.
    shutil.move(current_backup, self.client_metadata_current)

    # Test: repository with a '{repository_directory}/metadata/current'
    # directory, but the 'previous' directory is missing.
    shutil.move(self.client_metadata_previous, previous_backup)
    self.assertRaises(tuf.exceptions.RepositoryError, updater.Updater, 'test_repository',
                      self.repository_mirrors)
    shutil.move(previous_backup, self.client_metadata_previous)

    # Test:  repository missing the required 'root.json' file.
    client_root_file = os.path.join(self.client_metadata_current, 'root.json')
    backup_root_file = client_root_file + '.backup'
    shutil.move(client_root_file, backup_root_file)
    self.assertRaises(tuf.exceptions.RepositoryError, updater.Updater, 'test_repository',
                      self.repository_mirrors)
    # Restore the client's 'root.json file.
    shutil.move(backup_root_file, client_root_file)

    # Test: Normal 'tuf.client.updater.Updater' instantiation.
    updater.Updater('test_repository', self.repository_mirrors)





  def test_1__load_metadata_from_file(self):

    # Setup
    # Get the 'role1.json' filepath.  Manually load the role metadata, and
    # compare it against the loaded metadata by '_load_metadata_from_file()'.
    role1_filepath = \
      os.path.join(self.client_metadata_current, 'role1.json')
    role1_meta = securesystemslib.util.load_json_file(role1_filepath)

    # Load the 'role1.json' file with _load_metadata_from_file, which should
    # store the loaded metadata in the 'self.repository_updater.metadata'
    # store.
    self.assertEqual(len(self.repository_updater.metadata['current']), 4)
    self.repository_updater._load_metadata_from_file('current', 'role1')

    # Verify that the correct number of metadata objects has been loaded
    # (i.e., only the 'root.json' file should have been loaded.
    self.assertEqual(len(self.repository_updater.metadata['current']), 5)

    # Verify that the content of root metadata is valid.
    self.assertEqual(self.repository_updater.metadata['current']['role1'],
                     role1_meta['signed'])

    # Verify that _load_metadata_from_file() doesn't raise an exception for
    # improperly formatted metadata, and doesn't load the bad file.
    with open(role1_filepath, 'ab') as file_object:
      file_object.write(b'bad JSON data')

    self.repository_updater._load_metadata_from_file('current', 'role1')
    self.assertEqual(len(self.repository_updater.metadata['current']), 5)

    # Test if we fail gracefully if we can't deserialize a meta file
    self.repository_updater._load_metadata_from_file('current', 'empty_file')
    self.assertFalse('empty_file' in self.repository_updater.metadata['current'])

    # Test invalid metadata set argument (must be either
    # 'current' or 'previous'.)
    self.assertRaises(securesystemslib.exceptions.Error,
                      self.repository_updater._load_metadata_from_file,
                      'bad_metadata_set', 'role1')




  def test_1__rebuild_key_and_role_db(self):
    # Setup
    root_roleinfo = tuf.roledb.get_roleinfo('root', self.repository_name)
    root_metadata = self.repository_updater.metadata['current']['root']
    root_threshold = root_metadata['roles']['root']['threshold']
    number_of_root_keys = len(root_metadata['keys'])

    self.assertEqual(root_roleinfo['threshold'], root_threshold)

    # Ensure we add 2 to the number of root keys (actually, the number of root
    # keys multiplied by the number of keyid hash algorithms), to include the
    # delegated targets key (+1 for its sha512 keyid).  The delegated roles of
    # 'targets.json' are also loaded when the repository object is
    # instantiated.

    self.assertEqual(number_of_root_keys * 2 + 2, len(tuf.keydb._keydb_dict[self.repository_name]))

    # Test: normal case.
    self.repository_updater._rebuild_key_and_role_db()

    root_roleinfo = tuf.roledb.get_roleinfo('root', self.repository_name)
    self.assertEqual(root_roleinfo['threshold'], root_threshold)

    # _rebuild_key_and_role_db() will only rebuild the keys and roles specified
    # in the 'root.json' file, unlike __init__().  Instantiating an updater
    # object calls both _rebuild_key_and_role_db() and _import_delegations().
    self.assertEqual(number_of_root_keys * 2, len(tuf.keydb._keydb_dict[self.repository_name]))

    # Test: properly updated roledb and keydb dicts if the Root role changes.
    root_metadata = self.repository_updater.metadata['current']['root']
    root_metadata['roles']['root']['threshold'] = 8
    root_metadata['keys'].popitem()

    self.repository_updater._rebuild_key_and_role_db()

    root_roleinfo = tuf.roledb.get_roleinfo('root', self.repository_name)
    self.assertEqual(root_roleinfo['threshold'], 8)
    self.assertEqual(number_of_root_keys * 2 - 2, len(tuf.keydb._keydb_dict[self.repository_name]))




  def test_1__update_versioninfo(self):
    # Tests
    # Verify that the 'self.versioninfo' dictionary is empty (it starts off
    # empty and is only populated if _update_versioninfo() is called.
    versioninfo_dict = self.repository_updater.versioninfo
    self.assertEqual(len(versioninfo_dict), 0)

    # Load the versioninfo of the top-level Targets role.  This action
    # populates the 'self.versioninfo' dictionary.
    self.repository_updater._update_versioninfo('targets.json')
    self.assertEqual(len(versioninfo_dict), 1)
    self.assertTrue(tuf.formats.FILEINFODICT_SCHEMA.matches(versioninfo_dict))

    # The Snapshot role stores the version numbers of all the roles available
    # on the repository.  Load Snapshot to extract Root's version number
    # and compare it against the one loaded by 'self.repository_updater'.
    snapshot_filepath = os.path.join(self.client_metadata_current, 'snapshot.json')
    snapshot_signable = securesystemslib.util.load_json_file(snapshot_filepath)
    targets_versioninfo = snapshot_signable['signed']['meta']['targets.json']

    # Verify that the manually loaded version number of root.json matches
    # the one loaded by the updater object.
    self.assertTrue('targets.json' in versioninfo_dict)
    self.assertEqual(versioninfo_dict['targets.json'], targets_versioninfo)

    # Verify that 'self.versioninfo' is incremented if another role is updated.
    self.repository_updater._update_versioninfo('role1.json')
    self.assertEqual(len(versioninfo_dict), 2)

    # Verify that 'self.versioninfo' is incremented if a non-existent role is
    # requested, and has its versioninfo entry set to 'None'.
    self.repository_updater._update_versioninfo('bad_role.json')
    self.assertEqual(len(versioninfo_dict), 3)
    self.assertEqual(versioninfo_dict['bad_role.json'], None)

    # Verify that the versioninfo specified in Timestamp is used if the Snapshot
    # role hasn't been downloaded yet.
    del self.repository_updater.metadata['current']['snapshot']
    #self.assertRaises(self.repository_updater._update_versioninfo('snapshot.json'))
    self.repository_updater._update_versioninfo('snapshot.json')
    self.assertEqual(versioninfo_dict['snapshot.json']['version'], 1)




  def test_1__update_fileinfo(self):
      # Tests
      # Verify that the 'self.fileinfo' dictionary is empty (its starts off empty
      # and is only populated if _update_fileinfo() is called.
      fileinfo_dict = self.repository_updater.fileinfo
      self.assertEqual(len(fileinfo_dict), 0)

      # Load the fileinfo of the top-level root role.  This populates the
      # 'self.fileinfo' dictionary.
      self.repository_updater._update_fileinfo('root.json')
      self.assertEqual(len(fileinfo_dict), 1)
      self.assertTrue(tuf.formats.FILEDICT_SCHEMA.matches(fileinfo_dict))
      root_filepath = os.path.join(self.client_metadata_current, 'root.json')
      length, hashes = securesystemslib.util.get_file_details(root_filepath)
      root_fileinfo = tuf.formats.make_fileinfo(length, hashes)
      self.assertTrue('root.json' in fileinfo_dict)
      self.assertEqual(fileinfo_dict['root.json'], root_fileinfo)

      # Verify that 'self.fileinfo' is incremented if another role is updated.
      self.repository_updater._update_fileinfo('targets.json')
      self.assertEqual(len(fileinfo_dict), 2)

      # Verify that 'self.fileinfo' is inremented if a non-existent role is
      # requested, and has its fileinfo entry set to 'None'.
      self.repository_updater._update_fileinfo('bad_role.json')
      self.assertEqual(len(fileinfo_dict), 3)
      self.assertEqual(fileinfo_dict['bad_role.json'], None)




  def test_2__fileinfo_has_changed(self):
      #  Verify that the method returns 'False' if file info was not changed.
      root_filepath = os.path.join(self.client_metadata_current, 'root.json')
      length, hashes = securesystemslib.util.get_file_details(root_filepath)
      root_fileinfo = tuf.formats.make_fileinfo(length, hashes)
      self.assertFalse(self.repository_updater._fileinfo_has_changed('root.json',
                                                             root_fileinfo))

      # Verify that the method returns 'True' if length or hashes were changed.
      new_length = 8
      new_root_fileinfo = tuf.formats.make_fileinfo(new_length, hashes)
      self.assertTrue(self.repository_updater._fileinfo_has_changed('root.json',
                                                             new_root_fileinfo))
      # Hashes were changed.
      new_hashes = {'sha256': self.random_string()}
      new_root_fileinfo = tuf.formats.make_fileinfo(length, new_hashes)
      self.assertTrue(self.repository_updater._fileinfo_has_changed('root.json',
                                                             new_root_fileinfo))

      # Verify that _fileinfo_has_changed() returns True if no fileinfo (or set
      # to None) exists for some role.
      self.assertTrue(self.repository_updater._fileinfo_has_changed('bad.json',
          new_root_fileinfo))

      saved_fileinfo = self.repository_updater.fileinfo['root.json']
      self.repository_updater.fileinfo['root.json'] = None
      self.assertTrue(self.repository_updater._fileinfo_has_changed('root.json',
          new_root_fileinfo))


      self.repository_updater.fileinfo['root.json'] = saved_fileinfo
      new_root_fileinfo['hashes']['sha666'] = '666'
      self.repository_updater._fileinfo_has_changed('root.json',
          new_root_fileinfo)



  def test_2__import_delegations(self):
    # Setup.
    # In order to test '_import_delegations' the parent of the delegation
    # has to be in Repository.metadata['current'], but it has to be inserted
    # there without using '_load_metadata_from_file()' since it calls
    # '_import_delegations()'.
    repository_name = self.repository_updater.repository_name
    tuf.keydb.clear_keydb(repository_name)
    tuf.roledb.clear_roledb(repository_name)

    self.assertEqual(len(tuf.roledb._roledb_dict[repository_name]), 0)
    self.assertEqual(len(tuf.keydb._keydb_dict[repository_name]), 0)

    self.repository_updater._rebuild_key_and_role_db()

    self.assertEqual(len(tuf.roledb._roledb_dict[repository_name]), 4)

    # Take into account the number of keyids algorithms supported by default,
    # which this test condition expects to be two (sha256 and sha512).
    self.assertEqual(4 * 2, len(tuf.keydb._keydb_dict[repository_name]))

    # Test: pass a role without delegations.
    self.repository_updater._import_delegations('root')

    # Verify that there was no change to the roledb and keydb dictionaries by
    # checking the number of elements in the dictionaries.
    self.assertEqual(len(tuf.roledb._roledb_dict[repository_name]), 4)
    # Take into account the number of keyid hash algorithms, which this
    # test condition expects to be two (for sha256 and sha512).
    self.assertEqual(len(tuf.keydb._keydb_dict[repository_name]), 4 * 2)

    # Test: normal case, first level delegation.
    self.repository_updater._import_delegations('targets')

    self.assertEqual(len(tuf.roledb._roledb_dict[repository_name]), 5)
    # The number of root keys (times the number of key hash algorithms) +
    # delegation's key (+1 for its sha512 keyid).
    self.assertEqual(len(tuf.keydb._keydb_dict[repository_name]), 4 * 2 + 2)

    # Verify that roledb dictionary was added.
    self.assertTrue('role1' in tuf.roledb._roledb_dict[repository_name])

    # Verify that keydb dictionary was updated.
    role1_signable = \
      securesystemslib.util.load_json_file(os.path.join(self.client_metadata_current,
                                           'role1.json'))
    keyids = []
    for signature in role1_signable['signatures']:
      keyids.append(signature['keyid'])

    for keyid in keyids:
      self.assertTrue(keyid in tuf.keydb._keydb_dict[repository_name])

    # Verify that _import_delegations() ignores invalid keytypes in the 'keys'
    # field of parent role's 'delegations'.
    existing_keyid = keyids[0]

    self.repository_updater.metadata['current']['targets']\
      ['delegations']['keys'][existing_keyid]['keytype'] = 'bad_keytype'
    self.repository_updater._import_delegations('targets')

    # Restore the keytype of 'existing_keyid'.
    self.repository_updater.metadata['current']['targets']\
      ['delegations']['keys'][existing_keyid]['keytype'] = 'ed25519'

    # Verify that _import_delegations() raises an exception if one of the
    # delegated keys is malformed.
    valid_keyval = self.repository_updater.metadata['current']['targets']\
      ['delegations']['keys'][existing_keyid]['keyval']

    self.repository_updater.metadata['current']['targets']\
      ['delegations']['keys'][existing_keyid]['keyval'] = 1
    self.assertRaises(securesystemslib.exceptions.FormatError, self.repository_updater._import_delegations, 'targets')

    self.repository_updater.metadata['current']['targets']\
      ['delegations']['keys'][existing_keyid]['keyval'] = valid_keyval

    # Verify that _import_delegations() raises an exception if one of the
    # delegated roles is malformed.
    self.repository_updater.metadata['current']['targets']\
      ['delegations']['roles'][0]['name'] = 1
    self.assertRaises(securesystemslib.exceptions.FormatError, self.repository_updater._import_delegations, 'targets')



  def test_2__versioninfo_has_been_updated(self):
    # Verify that the method returns 'False' if a versioninfo was not changed.
    snapshot_filepath = os.path.join(self.client_metadata_current, 'snapshot.json')
    snapshot_signable = securesystemslib.util.load_json_file(snapshot_filepath)
    targets_versioninfo = snapshot_signable['signed']['meta']['targets.json']

    self.assertFalse(self.repository_updater._versioninfo_has_been_updated('targets.json',
                                                           targets_versioninfo))

    # Verify that the method returns 'True' if Root's version number changes.
    targets_versioninfo['version'] = 8
    self.assertTrue(self.repository_updater._versioninfo_has_been_updated('targets.json',
                                                           targets_versioninfo))





  def test_2__move_current_to_previous(self):
    # Test case will consist of removing a metadata file from client's
    # '{client_repository}/metadata/previous' directory, executing the method
    # and then verifying that the 'previous' directory contains the snapshot
    # file.
    previous_snapshot_filepath = os.path.join(self.client_metadata_previous,
                                              'snapshot.json')
    os.remove(previous_snapshot_filepath)
    self.assertFalse(os.path.exists(previous_snapshot_filepath))

    # Verify that the current 'snapshot.json' is moved to the previous directory.
    self.repository_updater._move_current_to_previous('snapshot')
    self.assertTrue(os.path.exists(previous_snapshot_filepath))





  def test_2__delete_metadata(self):
    # This test will verify that 'root' metadata is never deleted.  When a role
    # is deleted verify that the file is not present in the
    # 'self.repository_updater.metadata' dictionary.
    self.repository_updater._delete_metadata('root')
    self.assertTrue('root' in self.repository_updater.metadata['current'])

    self.repository_updater._delete_metadata('timestamp')
    self.assertFalse('timestamp' in self.repository_updater.metadata['current'])





  def test_2__ensure_not_expired(self):
    # This test condition will verify that nothing is raised when a metadata
    # file has a future expiration date.
    root_metadata = self.repository_updater.metadata['current']['root']
    self.repository_updater._ensure_not_expired(root_metadata, 'root')

    # 'tuf.exceptions.ExpiredMetadataError' should be raised in this next test condition,
    # because the expiration_date has expired by 10 seconds.
    expires = tuf.formats.unix_timestamp_to_datetime(int(time.time() - 10))
    expires = expires.isoformat() + 'Z'
    root_metadata['expires'] = expires

    # Ensure the 'expires' value of the root file is valid by checking the
    # the formats of the 'root.json' object.
    self.assertTrue(tuf.formats.ROOT_SCHEMA.matches(root_metadata))
    self.assertRaises(tuf.exceptions.ExpiredMetadataError,
                      self.repository_updater._ensure_not_expired,
                      root_metadata, 'root')





  def test_3__update_metadata(self):
    # Setup
    # _update_metadata() downloads, verifies, and installs the specified
    # metadata role.  Remove knowledge of currently installed metadata and
    # verify that they are re-installed after calling _update_metadata().

    # This is the default metadata that we would create for the timestamp role,
    # because it has no signed metadata for itself.
    DEFAULT_TIMESTAMP_FILELENGTH = tuf.settings.DEFAULT_TIMESTAMP_REQUIRED_LENGTH

    # This is the the upper bound length for Targets metadata.
    DEFAULT_TARGETS_FILELENGTH = tuf.settings.DEFAULT_TARGETS_REQUIRED_LENGTH

    # Save the versioninfo of 'targets.json,' needed later when re-installing
    # with _update_metadata().
    targets_versioninfo = \
      self.repository_updater.metadata['current']['snapshot']['meta']\
                                      ['targets.json']

    # Remove the currently installed metadata from the store and disk.  Verify
    # that the metadata dictionary is re-populated after calling
    # _update_metadata().
    del self.repository_updater.metadata['current']['timestamp']
    del self.repository_updater.metadata['current']['targets']

    timestamp_filepath = \
      os.path.join(self.client_metadata_current, 'timestamp.json')
    targets_filepath = os.path.join(self.client_metadata_current, 'targets.json')
    root_filepath = os.path.join(self.client_metadata_current, 'root.json')
    os.remove(timestamp_filepath)
    os.remove(targets_filepath)

    # Test: normal case.
    # Verify 'timestamp.json' is properly installed.
    self.assertFalse('timestamp' in self.repository_updater.metadata)

    logger.info('\nroleinfo: ' + repr(tuf.roledb.get_rolenames(self.repository_name)))
    self.repository_updater._update_metadata('timestamp',
                                             DEFAULT_TIMESTAMP_FILELENGTH)
    self.assertTrue('timestamp' in self.repository_updater.metadata['current'])
    os.path.exists(timestamp_filepath)

    # Verify 'targets.json' is properly installed.
    self.assertFalse('targets' in self.repository_updater.metadata['current'])
    self.repository_updater._update_metadata('targets',
                                DEFAULT_TARGETS_FILELENGTH,
                                targets_versioninfo['version'])
    self.assertTrue('targets' in self.repository_updater.metadata['current'])

    targets_signable = securesystemslib.util.load_json_file(targets_filepath)
    loaded_targets_version = targets_signable['signed']['version']
    self.assertEqual(targets_versioninfo['version'], loaded_targets_version)

    # Remove the 'targets.json' metadata so that the compressed version may be
    # tested next.
    del self.repository_updater.metadata['current']['targets']
    os.remove(targets_filepath)

    # Verify 'targets.json.gz' is properly intalled.  Note: The uncompressed
    # version is installed if the compressed one is downloaded.
    self.assertFalse('targets' in self.repository_updater.metadata['current'])
    self.repository_updater._update_metadata('targets',
        DEFAULT_TARGETS_FILELENGTH, targets_versioninfo['version'])
    self.assertTrue('targets' in self.repository_updater.metadata['current'])
    self.assertEqual(targets_versioninfo['version'],
        self.repository_updater.metadata['current']['targets']['version'])

    # Test: Invalid / untrusted version numbers.
    # Invalid version number for 'targets.json'.
    self.assertRaises(tuf.exceptions.NoWorkingMirrorError,
        self.repository_updater._update_metadata,
        'targets', DEFAULT_TARGETS_FILELENGTH, 88)

    # Verify that the specific exception raised is correct for the previous
    # case.
    try:
      self.repository_updater._update_metadata('targets',
                                               DEFAULT_TARGETS_FILELENGTH, 88)

    except tuf.exceptions.NoWorkingMirrorError as e:
      for mirror_error in six.itervalues(e.mirror_errors):
        assert isinstance(mirror_error, securesystemslib.exceptions.BadVersionNumberError)

    # Verify that the specific exception raised is correct for the previous
    # case.  The version number is checked, so the specific error in
    # this case should be 'securesystemslib.exceptions.BadVersionNumberError'.
    try:
      self.repository_updater._update_metadata('targets',
                                               DEFAULT_TARGETS_FILELENGTH,
                                               88)

    except tuf.exceptions.NoWorkingMirrorError as e:
      for mirror_error in six.itervalues(e.mirror_errors):
        assert isinstance(mirror_error, securesystemslib.exceptions.BadVersionNumberError)





  def test_3__get_metadata_file(self):

    valid_tuf_version = tuf.formats.TUF_VERSION_NUMBER
    tuf.formats.TUF_VERSION_NUMBER = '2'

    repository = repo_tool.load_repository(self.repository_directory)
    repository.timestamp.load_signing_key(self.role_keys['timestamp']['private'])
    repository.writeall()

    # Move the staged metadata to the "live" metadata.
    shutil.rmtree(os.path.join(self.repository_directory, 'metadata'))
    shutil.copytree(os.path.join(self.repository_directory, 'metadata.staged'),
                    os.path.join(self.repository_directory, 'metadata'))

    upperbound_filelength = tuf.settings.DEFAULT_TIMESTAMP_REQUIRED_LENGTH
    try:
      self.repository_updater._get_metadata_file('timestamp', 'timestamp.json',
      upperbound_filelength, 1)

    except tuf.exceptions.NoWorkingMirrorError as e:
      for mirror_error in six.itervalues(e.mirror_errors):
        assert isinstance(mirror_error, securesystemslib.exceptions.BadVersionNumberError)

    # Test for an improperly formatted TUF version number.
    tuf.formats.TUF_VERSION_NUMBER = 'BAD'
    repository = repo_tool.load_repository(self.repository_directory)
    repository.timestamp.load_signing_key(self.role_keys['timestamp']['private'])
    repository.writeall()

    # Move the staged metadata to the "live" metadata.
    shutil.rmtree(os.path.join(self.repository_directory, 'metadata'))
    shutil.copytree(os.path.join(self.repository_directory, 'metadata.staged'),
                    os.path.join(self.repository_directory, 'metadata'))

    try:
      self.repository_updater._get_metadata_file('timestamp', 'timestamp.json',
      upperbound_filelength, 1)

    except tuf.exceptions.NoWorkingMirrorError as e:
      for mirror_error in six.itervalues(e.mirror_errors):
        assert isinstance(mirror_error, securesystemslib.exceptions.FormatError)

    # Reset the TUF_VERSION_NUMBER so that subsequent unit tests use the
    # expected value.
    tuf.formats.TUF_VERSION_NUMBER = valid_tuf_version





  def test_3__update_metadata_if_changed(self):
    # Setup.
    # The client repository is initially loaded with only four top-level roles.
    # Verify that the metadata store contains the metadata of only these four
    # roles before updating the metadata of 'targets.json'.
    self.assertEqual(len(self.repository_updater.metadata['current']), 4)
    self.assertTrue('targets' in self.repository_updater.metadata['current'])
    targets_path = os.path.join(self.client_metadata_current, 'targets.json')
    self.assertTrue(os.path.exists(targets_path))
    self.assertEqual(self.repository_updater.metadata['current']['targets']['version'], 1)

    # Test: normal case.  Update 'targets.json'.  The version number should not
    # change.
    self.repository_updater._update_metadata_if_changed('targets')

    # Verify the current version of 'targets.json' has not changed.
    self.assertEqual(self.repository_updater.metadata['current']['targets']['version'], 1)

    # Modify one target file on the remote repository.
    repository = repo_tool.load_repository(self.repository_directory)
    target3 = os.path.join(self.repository_directory, 'targets', 'file3.txt')

    repository.targets.add_target(target3)
    repository.root.version = repository.root.version + 1
    repository.root.load_signing_key(self.role_keys['root']['private'])
    repository.targets.load_signing_key(self.role_keys['targets']['private'])
    repository.snapshot.load_signing_key(self.role_keys['snapshot']['private'])
    repository.timestamp.load_signing_key(self.role_keys['timestamp']['private'])
    repository.writeall()

    # Move the staged metadata to the "live" metadata.
    shutil.rmtree(os.path.join(self.repository_directory, 'metadata'))
    shutil.copytree(os.path.join(self.repository_directory, 'metadata.staged'),
                    os.path.join(self.repository_directory, 'metadata'))

    # Update 'targets.json' and verify that the client's current 'targets.json'
    # has been updated.  'timestamp' and 'snapshot' must be manually updated
    # so that new 'targets' can be recognized.
    DEFAULT_TIMESTAMP_FILELENGTH = tuf.settings.DEFAULT_TIMESTAMP_REQUIRED_LENGTH

    self.repository_updater._update_metadata('timestamp', DEFAULT_TIMESTAMP_FILELENGTH)
    self.repository_updater._update_metadata_if_changed('snapshot', 'timestamp')
    self.repository_updater._update_metadata_if_changed('targets')
    self.repository_updater._update_metadata_if_changed('root')
    targets_path = os.path.join(self.client_metadata_current, 'targets.json')
    self.assertTrue(os.path.exists(targets_path))
    self.assertTrue(self.repository_updater.metadata['current']['targets'])
    self.assertEqual(self.repository_updater.metadata['current']['targets']['version'], 2)

    # Test for an invalid 'referenced_metadata' argument.
    self.assertRaises(tuf.exceptions.RepositoryError,
        self.repository_updater._update_metadata_if_changed, 'snapshot', 'bad_role')



  def test_3__targets_of_role(self):
    # Setup.
    # Extract the list of targets from 'targets.json', to be compared to what
    # is returned by _targets_of_role('targets').
    targets_in_metadata = \
      self.repository_updater.metadata['current']['targets']['targets']

    # Test: normal case.
    targetinfos_list = self.repository_updater._targets_of_role('targets')

    # Verify that the list of targets was returned, and that it contains valid
    # target files.
    self.assertTrue(tuf.formats.TARGETINFOS_SCHEMA.matches(targetinfos_list))
    for targetinfo in targetinfos_list:
      self.assertTrue((targetinfo['filepath'], targetinfo['fileinfo']) in six.iteritems(targets_in_metadata))





  def test_4_refresh(self):
    # This unit test is based on adding an extra target file to the
    # server and rebuilding all server-side metadata.  All top-level metadata
    # should be updated when the client calls refresh().

    # First verify that an expired root metadata is updated.
    expired_date = '1960-01-01T12:00:00Z'
    self.repository_updater.metadata['current']['root']['expires'] = expired_date
    self.repository_updater.refresh()

    # Second, verify that expired root metadata is not updated if
    # 'unsafely_update_root_if_necessary' is explictly set to 'False'.
    expired_date = '1960-01-01T12:00:00Z'
    self.repository_updater.metadata['current']['root']['expires'] = expired_date
    self.assertRaises(tuf.exceptions.ExpiredMetadataError,
                      self.repository_updater.refresh,
                      unsafely_update_root_if_necessary=False)

    repository = repo_tool.load_repository(self.repository_directory)
    target3 = os.path.join(self.repository_directory, 'targets', 'file3.txt')

    repository.targets.add_target(target3)
    repository.targets.load_signing_key(self.role_keys['targets']['private'])
    repository.snapshot.load_signing_key(self.role_keys['snapshot']['private'])
    repository.timestamp.load_signing_key(self.role_keys['timestamp']['private'])
    repository.writeall()

    # Move the staged metadata to the "live" metadata.
    shutil.rmtree(os.path.join(self.repository_directory, 'metadata'))
    shutil.copytree(os.path.join(self.repository_directory, 'metadata.staged'),
                    os.path.join(self.repository_directory, 'metadata'))

    # Reference 'self.Repository.metadata['current']['targets']'.  Ensure
    # 'target3' is not already specified.
    targets_metadata = self.repository_updater.metadata['current']['targets']
    self.assertFalse(target3 in targets_metadata['targets'])

    # Verify the expected version numbers of the roles to be modified.
    self.assertEqual(self.repository_updater.metadata['current']['targets']\
                                                    ['version'], 1)
    self.assertEqual(self.repository_updater.metadata['current']['snapshot']\
                                                    ['version'], 1)
    self.assertEqual(self.repository_updater.metadata['current']['timestamp']\
                                                    ['version'], 1)

    # Test: normal case.  'targes.json' should now specify 'target3', and the
    # following top-level metadata should have also been updated:
    # 'snapshot.json' and 'timestamp.json'.
    self.repository_updater.refresh()

    # Verify that the client's metadata was updated.
    targets_metadata = self.repository_updater.metadata['current']['targets']
    targets_directory = os.path.join(self.repository_directory, 'targets')
    target3 = target3[len(targets_directory):]
    self.assertTrue(target3 in targets_metadata['targets'])

    # Verify the expected version numbers of the updated roles.
    self.assertEqual(self.repository_updater.metadata['current']['targets']\
                                                    ['version'], 2)
    self.assertEqual(self.repository_updater.metadata['current']['snapshot']\
                                                    ['version'], 2)
    self.assertEqual(self.repository_updater.metadata['current']['timestamp']\
                                                    ['version'], 2)





  def test_4__refresh_targets_metadata(self):
    # Setup.
    # It is assumed that the client repository has only loaded the top-level
    # metadata.  Refresh the 'targets.json' metadata, including all delegated
    # roles (i.e., the client should add the missing 'role1.json' metadata.
    self.assertEqual(len(self.repository_updater.metadata['current']), 4)

    # Test: normal case.
    self.repository_updater._refresh_targets_metadata(refresh_all_delegated_roles=True)

    # Verify that client's metadata files were refreshed successfully.
    self.assertEqual(len(self.repository_updater.metadata['current']), 6)

    # Test for non-existing rolename.
    self.repository_updater._refresh_targets_metadata('bad_rolename',
        refresh_all_delegated_roles=False)

    # Test that non-json metadata in Snapshot is ignored.
    self.repository_updater.metadata['current']['snapshot']['meta']['bad_role.xml'] = {}
    self.repository_updater._refresh_targets_metadata(refresh_all_delegated_roles=True)



  def test_5_all_targets(self):
   # Setup
   # As with '_refresh_targets_metadata()',

   # Update top-level metadata before calling one of the "targets" methods, as
   # recommended by 'updater.py'.
   self.repository_updater.refresh()

   # Test: normal case.
   all_targets = self.repository_updater.all_targets()

   # Verify format of 'all_targets', it should correspond to
   # 'TARGETINFOS_SCHEMA'.
   self.assertTrue(tuf.formats.TARGETINFOS_SCHEMA.matches(all_targets))

   # Verify that there is a correct number of records in 'all_targets' list,
   # and the expected filepaths specified in the metadata.  On the targets
   # directory of the repository, there should be 3 target files (2 of
   # which are specified by 'targets.json'.)  The delegated role 'role1'
   # specifies 1 target file.  The expected total number targets in
   # 'all_targets' should be 3.
   self.assertEqual(len(all_targets), 3)

   target_filepaths = []
   for target in all_targets:
    target_filepaths.append(target['filepath'])

   self.assertTrue('/file1.txt' in target_filepaths)
   self.assertTrue('/file2.txt' in target_filepaths)
   self.assertTrue('/file3.txt' in target_filepaths)





  def test_5_targets_of_role(self):
    # Setup
    # Remove knowledge of 'targets.json' from the metadata store.
    self.repository_updater.metadata['current']['targets']

    # Remove the metadata of the delegated roles.
    #shutil.rmtree(os.path.join(self.client_metadata, 'targets'))
    os.remove(os.path.join(self.client_metadata_current, 'targets.json'))

    # Extract the target files specified by the delegated role, 'role1.json',
    # as available on the server-side version of the role.
    role1_filepath = os.path.join(self.repository_directory, 'metadata',
                                  'role1.json')
    role1_signable = securesystemslib.util.load_json_file(role1_filepath)
    expected_targets = role1_signable['signed']['targets']


    # Test: normal case.
    targetinfos = self.repository_updater.targets_of_role('role1')

    # Verify that the expected role files were downloaded and installed.
    os.path.exists(os.path.join(self.client_metadata_current, 'targets.json'))
    os.path.exists(os.path.join(self.client_metadata_current, 'targets',
                   'role1.json'))
    self.assertTrue('targets' in self.repository_updater.metadata['current'])
    self.assertTrue('role1' in self.repository_updater.metadata['current'])

    #  Verify that list of targets was returned and that it contains valid
    # target files.
    self.assertTrue(tuf.formats.TARGETINFOS_SCHEMA.matches(targetinfos))
    for targetinfo in targetinfos:
      self.assertTrue((targetinfo['filepath'], targetinfo['fileinfo']) in six.iteritems(expected_targets))

    # Test: Invalid arguments.
    # targets_of_role() expected a string rolename.
    self.assertRaises(securesystemslib.exceptions.FormatError, self.repository_updater.targets_of_role,
                      8)
    self.assertRaises(tuf.exceptions.UnknownRoleError, self.repository_updater.targets_of_role,
                      'unknown_rolename')





  def test_6_get_one_valid_targetinfo(self):
    # Setup
    # Extract the file information of the targets specified in 'targets.json'.
    self.repository_updater.refresh()
    targets_metadata = self.repository_updater.metadata['current']['targets']

    target_files = targets_metadata['targets']
    # Extract random target from 'target_files', which will be compared to what
    # is returned by get_one_valid_targetinfo().  Restore the popped target
    # (dict value stored in the metadata store) so that it can be found later.
    filepath, fileinfo = target_files.popitem()
    target_files[filepath] = fileinfo

    target_targetinfo = self.repository_updater.get_one_valid_targetinfo(filepath)
    self.assertTrue(tuf.formats.TARGETINFO_SCHEMA.matches(target_targetinfo))
    self.assertEqual(target_targetinfo['filepath'], filepath)
    self.assertEqual(target_targetinfo['fileinfo'], fileinfo)

    # Test: invalid target path.
    self.assertRaises(tuf.exceptions.UnknownTargetError,
                      self.repository_updater.get_one_valid_targetinfo,
                      self.random_path())

    # Test updater.get_one_valid_targetinfo() backtracking behavior (enabled by
    # default.)
    targets_directory = os.path.join(self.repository_directory, 'targets')
    foo_directory = os.path.join(targets_directory, 'foo')
    foo_pattern = os.path.join(foo_directory, 'foo*.tar.gz')
    os.makedirs(foo_directory)

    foo_package = os.path.join(foo_directory, 'foo1.1.tar.gz')
    with open(foo_package, 'wb') as file_object:
      file_object.write(b'new release')

    # Modify delegations on the remote repository to test backtracking behavior.
    repository = repo_tool.load_repository(self.repository_directory)


    repository.targets.delegate('role3', [self.role_keys['targets']['public']],
                                [], restricted_paths=[foo_pattern])

    repository.targets.delegate('role4', [self.role_keys['targets']['public']],
                                [foo_package], restricted_paths=[foo_pattern])

    repository.targets.load_signing_key(self.role_keys['targets']['private'])
    repository.targets('role3').load_signing_key(self.role_keys['targets']['private'])
    repository.targets('role4').load_signing_key(self.role_keys['targets']['private'])
    repository.snapshot.load_signing_key(self.role_keys['snapshot']['private'])
    repository.timestamp.load_signing_key(self.role_keys['timestamp']['private'])
    repository.writeall()

    # Move the staged metadata to the "live" metadata.
    shutil.rmtree(os.path.join(self.repository_directory, 'metadata'))
    shutil.copytree(os.path.join(self.repository_directory, 'metadata.staged'),
                    os.path.join(self.repository_directory, 'metadata'))


    # updater.get_one_valid_targetinfo() should find 'foo1.1.tar.gz' by
    # backtracking to 'role3'.  'role2' allows backtracking.
    self.repository_updater.refresh()
    self.repository_updater.get_one_valid_targetinfo('foo/foo1.1.tar.gz')


    # Test when 'role2' does *not* allow backtracking.  If 'foo/foo1.1.tar.gz'
    # is not provided by the authoritative 'role2',
    # updater.get_one_valid_targetinfo() should return a
    # 'tuf.exceptions.UnknownTargetError' exception.
    repository = repo_tool.load_repository(self.repository_directory)

    repository.targets.revoke('role3')
    repository.targets.revoke('role4')

    # Ensure we delegate in trusted order (i.e., 'role2' has higher priority.)
    repository.targets.delegate('role3', [self.role_keys['targets']['public']],
                                [], terminating=True, restricted_paths=[foo_pattern])
    repository.targets.delegate('role4', [self.role_keys['targets']['public']],
                                [foo_package], restricted_paths=[foo_pattern])

    repository.targets('role3').load_signing_key(self.role_keys['targets']['private'])
    repository.targets('role4').load_signing_key(self.role_keys['targets']['private'])
    repository.targets.load_signing_key(self.role_keys['targets']['private'])
    repository.snapshot.load_signing_key(self.role_keys['snapshot']['private'])
    repository.timestamp.load_signing_key(self.role_keys['timestamp']['private'])
    repository.writeall()

    # Move the staged metadata to the "live" metadata.
    shutil.rmtree(os.path.join(self.repository_directory, 'metadata'))
    shutil.copytree(os.path.join(self.repository_directory, 'metadata.staged'),
                    os.path.join(self.repository_directory, 'metadata'))

    # Verify that 'tuf.exceptions.UnknownTargetError' is raised by
    # updater.get_one_valid_targetinfo().
    self.repository_updater.refresh()
    self.assertRaises(tuf.exceptions.UnknownTargetError,
                      self.repository_updater.get_one_valid_targetinfo,
                      'foo/foo1.1.tar.gz')





  def test_6_download_target(self):
    # Create temporary directory (destination directory of downloaded targets)
    # that will be passed as an argument to 'download_target()'.
    destination_directory = self.make_temp_directory()
    target_filepaths = \
      list(self.repository_updater.metadata['current']['targets']['targets'].keys())

    # Test: normal case.
    # Get the target info, which is an argument to 'download_target()'.

    # 'target_filepaths' is expected to have at least two targets.  The first
    # target will be used to test against download_target().  The second
    # will be used to test against download_target() and a repository with
    # 'consistent_snapshot' set to True.
    target_filepath1 = target_filepaths.pop()
    targetinfo = self.repository_updater.get_one_valid_targetinfo(target_filepath1)
    self.repository_updater.download_target(targetinfo,
                                            destination_directory)

    download_filepath = \
      os.path.join(destination_directory, target_filepath1.lstrip('/'))
    self.assertTrue(os.path.exists(download_filepath))
    length, hashes = \
      securesystemslib.util.get_file_details(download_filepath,
        securesystemslib.settings.HASH_ALGORITHMS)
    download_targetfileinfo = tuf.formats.make_fileinfo(length, hashes)

    # Add any 'custom' data from the repository's target fileinfo to the
    # 'download_targetfileinfo' object being tested.
    if 'custom' in targetinfo['fileinfo']:
      download_targetfileinfo['custom'] = targetinfo['fileinfo']['custom']

    self.assertEqual(targetinfo['fileinfo'], download_targetfileinfo)

    # Test when consistent snapshots is set.  First, create a valid
    # repository with consistent snapshots set (root.json contains a
    # "consistent_snapshot" entry that the updater uses to correctly fetch
    # snapshots.  The updater expects the existence of
    # '<version_number>.filename' files if root.json sets 'consistent_snapshot
    # = True'.

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

    repository.writeall(consistent_snapshot=True)

    # Move the staged metadata to the "live" metadata.
    shutil.rmtree(os.path.join(self.repository_directory, 'metadata'))
    shutil.copytree(os.path.join(self.repository_directory, 'metadata.staged'),
                    os.path.join(self.repository_directory, 'metadata'))

    # And ensure the client has the latest top-level metadata.
    self.repository_updater.refresh()

    target_filepath2 = target_filepaths.pop()
    targetinfo2 = self.repository_updater.get_one_valid_targetinfo(target_filepath2)
    self.repository_updater.download_target(targetinfo2,
                                            destination_directory)

    # Test for a destination that cannot be written to (apart from a target
    # file that already exists at the destination) and which raises an
    # exception.
    bad_destination_directory = 'bad' * 2000

    try:
      self.repository_updater.download_target(targetinfo, bad_destination_directory)

    except OSError as e:
      self.assertTrue(e.errno == errno.ENAMETOOLONG)

    # Test: Invalid arguments.
    self.assertRaises(securesystemslib.exceptions.FormatError,
                      self.repository_updater.download_target,
                      8, destination_directory)

    self.assertRaises(securesystemslib.exceptions.FormatError,
                      self.repository_updater.download_target,
                      targetinfo, 8)

    # Test:
    # Attempt a file download of a valid target, however, a download exception
    # occurs because the target is not within the mirror's confined target
    # directories.  Adjust mirrors dictionary, so that 'confined_target_dirs'
    # field contains at least one confined target and excludes needed target
    # file.
    mirrors = self.repository_updater.mirrors
    for mirror_name, mirror_info in six.iteritems(mirrors):
      mirrors[mirror_name]['confined_target_dirs'] = [self.random_path()]

    try:
      self.repository_updater.download_target(targetinfo,
                                              destination_directory)

    except tuf.exceptions.NoWorkingMirrorError as exception:
      # Ensure that no mirrors were found due to mismatch in confined target
      # directories.  get_list_of_mirrors() returns an empty list in this case,
      # which does not generate specific exception errors.
      self.assertEqual(len(exception.mirror_errors), 0)



  def test_7_updated_targets(self):
    # Verify that the list of targets returned by updated_targets() contains
    # all the files that need to be updated, these files include modified and
    # new target files.  Also, confirm that files that need not to be updated
    # are absent from the list.
    # Setup
    # Create temporary directory which will hold client's target files.
    destination_directory = self.make_temp_directory()

    # Get the list of target files.  It will be used as an argument to the
    # 'updated_targets()' function.
    all_targets = self.repository_updater.all_targets()

    # Test for duplicates and targets in the root directory of the repository.
    additional_target = all_targets[0].copy()
    all_targets.append(additional_target)
    additional_target_in_root_directory = additional_target.copy()
    additional_target_in_root_directory['filepath'] = 'file1.txt'
    all_targets.append(additional_target_in_root_directory)

    #  At this point client needs to update and download all targets.
    # Test: normal cases.
    updated_targets = \
      self.repository_updater.updated_targets(all_targets, destination_directory)

    all_targets = self.repository_updater.all_targets()

    # Assumed the pre-generated repository specifies two target files in
    # 'targets.json' and one delegated target file in 'role1.json'.
    self.assertEqual(len(updated_targets), 3)

    # Test: download one of the targets.
    download_target = copy.deepcopy(updated_targets).pop()
    self.repository_updater.download_target(download_target,
                                            destination_directory)

    updated_targets = \
      self.repository_updater.updated_targets(all_targets, destination_directory)

    self.assertEqual(len(updated_targets), 2)

    # Test: download all the targets.
    for download_target in all_targets:
      self.repository_updater.download_target(download_target,
                                              destination_directory)
    updated_targets = \
      self.repository_updater.updated_targets(all_targets, destination_directory)

    self.assertEqual(len(updated_targets), 0)


    # Test: Invalid arguments.
    self.assertRaises(securesystemslib.exceptions.FormatError,
                      self.repository_updater.updated_targets,
                      8, destination_directory)

    self.assertRaises(securesystemslib.exceptions.FormatError,
                      self.repository_updater.updated_targets,
                      all_targets, 8)

    # Modify one target file on the remote repository.
    repository = repo_tool.load_repository(self.repository_directory)
    target1 = os.path.join(self.repository_directory, 'targets', 'file1.txt')

    repository.targets.remove_target(target1)

    length, hashes = securesystemslib.util.get_file_details(target1)

    repository.targets.add_target(target1)
    repository.targets.load_signing_key(self.role_keys['targets']['private'])
    repository.snapshot.load_signing_key(self.role_keys['snapshot']['private'])

    with open(target1, 'ab') as file_object:
      file_object.write(b'append extra text')

    length, hashes = securesystemslib.util.get_file_details(target1)

    repository.targets.add_target(target1)
    repository.targets.load_signing_key(self.role_keys['targets']['private'])
    repository.snapshot.load_signing_key(self.role_keys['snapshot']['private'])
    repository.timestamp.load_signing_key(self.role_keys['timestamp']['private'])
    repository.writeall()

    # Move the staged metadata to the "live" metadata.
    shutil.rmtree(os.path.join(self.repository_directory, 'metadata'))
    shutil.copytree(os.path.join(self.repository_directory, 'metadata.staged'),
                    os.path.join(self.repository_directory, 'metadata'))

    # Ensure the client has up-to-date metadata.
    self.repository_updater.refresh()

    # Verify that the new target file is considered updated.
    all_targets = self.repository_updater.all_targets()
    updated_targets = \
      self.repository_updater.updated_targets(all_targets, destination_directory)
    self.assertEqual(len(updated_targets), 1)





  def test_8_remove_obsolete_targets(self):
    # Setup.
    # Create temporary directory that will hold the client's target files.
    destination_directory = self.make_temp_directory()

    #  Populate 'destination_direction' with all target files.
    all_targets = self.repository_updater.all_targets()

    self.assertEqual(len(os.listdir(destination_directory)), 0)

    for target in all_targets:
      self.repository_updater.download_target(target, destination_directory)

    self.assertEqual(len(os.listdir(destination_directory)), 3)

    # Remove two target files from the server's repository.
    repository = repo_tool.load_repository(self.repository_directory)
    target1 = os.path.join(self.repository_directory, 'targets', 'file1.txt')
    repository.targets.remove_target(target1)

    repository.targets.load_signing_key(self.role_keys['targets']['private'])
    repository.snapshot.load_signing_key(self.role_keys['snapshot']['private'])
    repository.timestamp.load_signing_key(self.role_keys['timestamp']['private'])
    repository.writeall()

    # Move the staged metadata to the "live" metadata.
    shutil.rmtree(os.path.join(self.repository_directory, 'metadata'))
    shutil.copytree(os.path.join(self.repository_directory, 'metadata.staged'),
                    os.path.join(self.repository_directory, 'metadata'))

    # Update client's metadata.
    self.repository_updater.refresh()

    # Test: normal case.
    # Verify number of target files in 'destination_directory' (should be 1
    # after the update made to the remote repository), and call
    # 'remove_obsolete_targets()'.
    all_targets = self.repository_updater.all_targets()

    updated_targets = \
      self.repository_updater.updated_targets(all_targets,
                                              destination_directory)

    for updated_target in updated_targets:
      self.repository_updater.download_target(updated_target,
                                              destination_directory)

    self.assertEqual(len(os.listdir(destination_directory)), 3)
    self.repository_updater.remove_obsolete_targets(destination_directory)
    self.assertEqual(len(os.listdir(destination_directory)), 2)

    #  Verify that, if there are no obsolete files, the number of files
    #  in 'destination_directory' remains the same.
    self.repository_updater.remove_obsolete_targets(destination_directory)
    self.assertEqual(len(os.listdir(destination_directory)), 2)

    # Test coverage for a destination path that causes an exception not due
    # to an already removed target.
    bad_destination_directory = 'bad' * 2000
    self.repository_updater.remove_obsolete_targets(bad_destination_directory)

    # Test coverage for a target that is not specified in current metadata.
    del self.repository_updater.metadata['current']['targets']['targets']['/file2.txt']
    self.repository_updater.remove_obsolete_targets(destination_directory)

    # Test coverage for a role that doesn't exist in the previously trusted set
    # of metadata.
    del self.repository_updater.metadata['previous']['targets']
    self.repository_updater.remove_obsolete_targets(destination_directory)



  def test_9__get_target_hash(self):
    # Test normal case.
    # Test target filepaths with ascii and non-ascii characters.
    expected_target_hashes = {
      '/file1.txt': 'e3a3d89eb3b70ce3fbce6017d7b8c12d4abd5635427a0e8a238f53157df85b3d',
      '/Jalape\xc3\xb1o': '78bfd5c314680545eb48ecad508aceb861f8d6e680f4fe1b791da45c298cda88'
    }
    for filepath, target_hash in six.iteritems(expected_target_hashes):
      self.assertTrue(securesystemslib.formats.RELPATH_SCHEMA.matches(filepath))
      self.assertTrue(securesystemslib.formats.HASH_SCHEMA.matches(target_hash))
      self.assertEqual(self.repository_updater._get_target_hash(filepath), target_hash)

    # Test for improperly formatted argument.
    #self.assertRaises(securesystemslib.exceptions.FormatError, self.repository_updater._get_target_hash, 8)




  def test_10__hard_check_file_length(self):
    # Test for exception if file object is not equal to trusted file length.
    temp_file_object = securesystemslib.util.TempFile()
    temp_file_object.write(b'X')
    temp_file_object.seek(0)
    self.assertRaises(tuf.exceptions.DownloadLengthMismatchError,
                     self.repository_updater._hard_check_file_length,
                     temp_file_object, 10)





  def test_10__soft_check_file_length(self):
    # Test for exception if file object is not equal to trusted file length.
    temp_file_object = securesystemslib.util.TempFile()
    temp_file_object.write(b'XXX')
    temp_file_object.seek(0)
    self.assertRaises(tuf.exceptions.DownloadLengthMismatchError,
                     self.repository_updater._soft_check_file_length,
                     temp_file_object, 1)

    # Verify that an exception is not raised if the file length <= the observed
    # file length.
    temp_file_object.seek(0)
    self.repository_updater._soft_check_file_length(temp_file_object, 3)
    temp_file_object.seek(0)
    self.repository_updater._soft_check_file_length(temp_file_object, 4)




  def test_10__targets_of_role(self):
    # Test for non-existent role.
    self.assertRaises(tuf.exceptions.UnknownRoleError,
                      self.repository_updater._targets_of_role,
                      'non-existent-role')

    # Test for role that hasn't been loaded yet.
    del self.repository_updater.metadata['current']['targets']
    self.assertEqual(len(self.repository_updater._targets_of_role('targets',
                                                        skip_refresh=True)), 0)

    # 'targets.json' tracks two targets.
    self.assertEqual(len(self.repository_updater._targets_of_role('targets')),
                     2)



  def test_10__preorder_depth_first_walk(self):

    # Test that infinit loop is prevented if the target file is not found and
    # the max number of delegations is reached.
    valid_max_number_of_delegations = tuf.settings.MAX_NUMBER_OF_DELEGATIONS
    tuf.settings.MAX_NUMBER_OF_DELEGATIONS = 0
    self.assertEqual(None, self.repository_updater._preorder_depth_first_walk('unknown.txt'))

    # Reset the setting for max number of delegations so that subsequent unit
    # tests reference the expected setting.
    tuf.settings.MAX_NUMBER_OF_DELEGATIONS = valid_max_number_of_delegations

    # Attempt to create a circular delegation, where role1 performs a
    # delegation to the top-level Targets role.  The updater should ignore the
    # delegation and not raise an exception.
    targets_path = os.path.join(self.client_metadata_current, 'targets.json')
    targets_metadata = securesystemslib.util.load_json_file(targets_path)
    targets_metadata['signed']['delegations']['roles'][0]['paths'] = ['/file8.txt']
    with open(targets_path, 'wb') as file_object:
      file_object.write(repo_lib._get_written_metadata(targets_metadata))

    role1_path = os.path.join(self.client_metadata_current, 'role1.json')
    role1_metadata = securesystemslib.util.load_json_file(role1_path)
    role1_metadata['signed']['delegations']['roles'][0]['name'] = 'targets'
    role1_metadata['signed']['delegations']['roles'][0]['paths'] = ['/file8.txt']
    with open(role1_path, 'wb') as file_object:
      file_object.write(repo_lib._get_written_metadata(role1_metadata))

    role2_path = os.path.join(self.client_metadata_current, 'role2.json')
    role2_metadata = securesystemslib.util.load_json_file(role2_path)
    role2_metadata['signed']['delegations']['roles'] = role1_metadata['signed']['delegations']['roles']
    role2_metadata['signed']['delegations']['roles'][0]['paths'] = ['/file8.txt']
    with open(role2_path, 'wb') as file_object:
      file_object.write(repo_lib._get_written_metadata(role2_metadata))

    logger.debug('attempting circular delegation')
    self.assertEqual(None, self.repository_updater._preorder_depth_first_walk('/file8.txt'))






  def test_10__visit_child_role(self):
    # Call _visit_child_role and test the dict keys: 'paths',
    # 'path_hash_prefixes', and if both are missing.

    targets_role = self.repository_updater.metadata['current']['targets']
    targets_role['delegations']['roles'][0]['paths'] = ['/*.txt', '/target.exe']
    child_role = targets_role['delegations']['roles'][0]

    role1_path = os.path.join(self.client_metadata_current, 'role1.json')
    role1_metadata = securesystemslib.util.load_json_file(role1_path)
    role1_metadata['signed']['delegations']['roles'][0]['paths'] = ['/*.exe']
    with open(role1_path, 'wb') as file_object:
      file_object.write(repo_lib._get_written_metadata(role1_metadata))

    self.assertEqual(self.repository_updater._visit_child_role(child_role,
        '/target.exe'), child_role['name'])

    # Test for a valid path hash prefix...
    child_role['path_hash_prefixes'] = ['8baf']
    self.assertEqual(self.repository_updater._visit_child_role(child_role,
        '/file3.txt'), child_role['name'])

    # ... and an invalid one, as well.
    child_role['path_hash_prefixes'] = ['badd']
    self.assertEqual(self.repository_updater._visit_child_role(child_role,
        '/file3.txt'), None)

    # Test for a forbidden target.
    del child_role['path_hash_prefixes']
    self.repository_updater._visit_child_role(child_role, '/forbidden.tgz')

    # Verify that unequal path_hash_prefixes are skipped.
    child_role['path_hash_prefixes'] = ['bad', 'bad']
    self.assertEqual(None, self.repository_updater._visit_child_role(child_role,
        '/unknown.exe'))

    # Test if both 'path' and 'path_hash_prefixes' are missing.
    del child_role['paths']
    del child_role['path_hash_prefixes']
    self.assertRaises(securesystemslib.exceptions.FormatError, self.repository_updater._visit_child_role,
        child_role, child_role['name'])



  def test_11__verify_uncompressed_metadata_file(self):
    # Test for invalid metadata content.
    metadata_file_object = securesystemslib.util.TempFile()
    metadata_file_object.write(b'X')
    metadata_file_object.seek(0)

    self.assertRaises(tuf.exceptions.InvalidMetadataJSONError,
        self.repository_updater._verify_uncompressed_metadata_file,
        metadata_file_object, 'root')



  def test_12__verify_root_chain_link(self):
    # Test for an invalid signature in the chain link.
    # current = (i.e., 1.root.json)
    # next = signable for the next metadata in the chain (i.e., 2.root.json)
    rolename = 'root'
    current_root = self.repository_updater.metadata['current']['root']

    targets_path = os.path.join(self.repository_directory, 'metadata', 'targets.json')

    # 'next_invalid_root' is a Targets signable, as written to disk.
    # We use the Targets metadata here to ensure the signatures are invalid.
    next_invalid_root = securesystemslib.util.load_json_file(targets_path)

    self.assertRaises(securesystemslib.exceptions.BadSignatureError,
        self.repository_updater._verify_root_chain_link, rolename, current_root,
        next_invalid_root)



  def test_13__get_file(self):
    # Test for an "unsafe" download, where the file is downloaded up to
    # a required length (and no more).  The "safe" download approach
    # downloads an exact required length.
    targets_path = os.path.join(self.repository_directory, 'metadata', 'targets.json')

    file_size, file_hashes = securesystemslib.util.get_file_details(targets_path)
    file_type = 'meta'

    def verify_target_file(targets_path):
      # Every target file must have its length and hashes inspected.
      self.repository_updater._hard_check_file_length(targets_path, file_size)
      self.repository_updater._check_hashes(targets_path, file_hashes)

    self.repository_updater._get_file('targets.json', verify_target_file,
        file_type, file_size, download_safely=True)

    self.repository_updater._get_file('targets.json', verify_target_file,
        file_type, file_size, download_safely=False)



  def test_14__targets_of_role(self):
    # Test case where a list of targets is given.  By default, the 'targets'
    # parameter is None.
    targets = [{'filepath': 'file1.txt', 'fileinfo': {'length': 1, 'hashes': {'sha256': 'abc'}}}]
    self.repository_updater._targets_of_role('targets',
        targets=targets, skip_refresh=False)



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
