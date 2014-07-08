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

# 'unittest2' required for testing under Python < 2.7.
if sys.version_info >= (2, 7):
  import unittest

else:
  import unittest2 as unittest 

import tuf
import tuf.util
import tuf.conf
import tuf.log
import tuf.formats
import tuf.keydb
import tuf.roledb
import tuf.repository_tool as repo_tool
import tuf.unittest_toolbox as unittest_toolbox
import tuf.client.updater as updater
import tuf._vendor.six as six

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
      logger.info('\tServer process '+str(cls.server_process.pid)+' terminated.')
      cls.server_process.kill()



  def setUp(self):
    # We are inheriting from custom class.
    unittest_toolbox.Modified_TestCase.setUp(self)
  
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
    self.client_metadata = os.path.join(self.client_directory, 'metadata')
    self.client_metadata_current = os.path.join(self.client_metadata, 'current')
    self.client_metadata_previous = \
      os.path.join(self.client_metadata, 'previous')

    # Copy the original 'repository', 'client', and 'keystore' directories
    # to the temporary repository the test cases can use.
    shutil.copytree(original_repository, self.repository_directory)
    shutil.copytree(original_client, self.client_directory)
    shutil.copytree(original_keystore, self.keystore_directory)

    # 'path/to/tmp/repository' -> 'localhost:8001/tmp/repository'. 
    repository_basepath = self.repository_directory[len(os.getcwd()):]
    url_prefix = \
      'http://localhost:' + str(self.SERVER_PORT) + repository_basepath 
    
    # Setting 'tuf.conf.repository_directory' with the temporary client
    # directory copied from the original repository files.
    tuf.conf.repository_directory = self.client_directory 
    
    self.repository_mirrors = {'mirror1': {'url_prefix': url_prefix,
                                           'metadata_path': 'metadata',
                                           'targets_path': 'targets',
                                           'confined_target_dirs': ['']}}

    # Creating repository instance.  The test cases will use this client
    # updater to refresh metadata, fetch target files, etc.
    self.repository_updater = updater.Updater('test_repository',
                                              self.repository_mirrors)

    # Metadata role keys are needed by the test cases to make changes to the
    # repository (e.g., adding a new target file to 'targets.json' and then
    # requesting a refresh()).
    self.role_keys = _load_role_keys(self.keystore_directory)



  def tearDown(self):
    # We are inheriting from custom class.
    unittest_toolbox.Modified_TestCase.tearDown(self)
    




  # UNIT TESTS.
  
  def test_1__init__exceptions(self):
    # The client's repository requires a metadata directory (and the 'current'
    # and 'previous' sub-directories), and at least the 'root.json' file.
    # setUp(), called before each test case, instantiates the required updater
    # objects and keys.  The needed objects/data is available in
    # 'self.repository_updater', 'self.client_directory', etc.


    # Test: Invalid arguments.
    # Invalid 'updater_name' argument.  String expected. 
    self.assertRaises(tuf.FormatError, updater.Updater, 8,
                      self.repository_mirrors)
   
    # Invalid 'repository_mirrors' argument.  'tuf.formats.MIRRORDICT_SCHEMA'
    # expected.
    self.assertRaises(tuf.FormatError, updater.Updater, updater.Updater, 8)


    # 'tuf.client.updater.py' requires that the client's repository directory
    # be configured in 'tuf.conf.py'.
    tuf.conf.repository_directory = None
    self.assertRaises(tuf.RepositoryError, updater.Updater, 'test_repository',
                      self.repository_mirrors)
    # Restore 'tuf.conf.repository_directory' to the original client directory.
    tuf.conf.repository_directory = self.client_directory
    

    # Test: empty client repository (i.e., no metadata directory).
    metadata_backup = self.client_metadata + '.backup'
    shutil.move(self.client_metadata, metadata_backup)
    self.assertRaises(tuf.RepositoryError, updater.Updater, 'test_repository',
                      self.repository_mirrors)
    # Restore the client's metadata directory.
    shutil.move(metadata_backup, self.client_metadata)


    # Test: repository with only a '{repository_directory}/metadata' directory.
    # (i.e., missing the required 'current' and 'previous' sub-directories). 
    current_backup = self.client_metadata_current + '.backup'
    previous_backup = self.client_metadata_previous + '.backup'
    
    shutil.move(self.client_metadata_current, current_backup)
    shutil.move(self.client_metadata_previous, previous_backup)
    self.assertRaises(tuf.RepositoryError, updater.Updater, 'test_repository',
                      self.repository_mirrors)
    # Restore the client's previous directory.  The required 'current' directory
    # is still missing.
    shutil.move(previous_backup, self.client_metadata_previous)


    # Test: repository with only a '{repository_directory/metadata/previous'
    # directory.
    self.assertRaises(tuf.RepositoryError, updater.Updater, 'test_repository',
                      self.repository_mirrors)
    # Restore the client's current directory.
    shutil.move(current_backup, self.client_metadata_current)
   
    # Test:  repository missing the required 'root.json' file.
    client_root_file = os.path.join(self.client_metadata_current, 'root.json')
    backup_root_file = client_root_file + '.backup'
    shutil.move(client_root_file, backup_root_file)
    self.assertRaises(tuf.RepositoryError, updater.Updater, 'test_repository',
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
      os.path.join(self.client_metadata_current, 'targets', 'role1.json')
    role1_meta = tuf.util.load_json_file(role1_filepath)
 
    # Load the 'role1.json' file with _load_metadata_from_file, which should
    # store the loaded metadata in the 'self.repository_updater.metadata'
    # store.
    self.assertEqual(len(self.repository_updater.metadata['current']), 4)
    self.repository_updater._load_metadata_from_file('current', 'targets/role1')
    
    # Verify that the correct number of metadata objects has been loaded
    # (i.e., only the 'root.json' file should have been loaded.
    self.assertEqual(len(self.repository_updater.metadata['current']), 5)

    #  Verify that the content of root metadata is valid.
    self.assertEqual(self.repository_updater.metadata['current']['targets/role1'],
                     role1_meta['signed'])





  def test_1__rebuild_key_and_role_db(self):    
    # Setup
    root_roleinfo = tuf.roledb.get_roleinfo('root')
    root_metadata = self.repository_updater.metadata['current']['root']
    root_threshold = root_metadata['roles']['root']['threshold']
    number_of_root_keys = len(root_metadata['keys'])

    self.assertEqual(root_roleinfo['threshold'], root_threshold)
    # Ensure we add 1 to the number of root keys, to include the delegated
    # targets key.  The delegated roles of 'targets.json' are also loaded
    # when the repository object is instantiated.
    self.assertEqual(number_of_root_keys + 1, len(tuf.keydb._keydb_dict))

    # Test: normal case.
    self.repository_updater._rebuild_key_and_role_db()

    root_roleinfo = tuf.roledb.get_roleinfo('root')
    self.assertEqual(root_roleinfo['threshold'], root_threshold)
    # _rebuild_key_and_role_db() will only rebuild the keys and roles specified
    # in the 'root.json' file, unlike __init__().  Instantiating an updater
    # object calls both _rebuild_key_and_role_db() and _import_delegations().
    self.assertEqual(number_of_root_keys, len(tuf.keydb._keydb_dict))
   
    # Test: properly updated roledb and keydb dicts if the Root role changes.
    root_metadata = self.repository_updater.metadata['current']['root']
    root_metadata['roles']['root']['threshold'] = 8
    root_metadata['keys'].popitem()

    self.repository_updater._rebuild_key_and_role_db()
    
    root_roleinfo = tuf.roledb.get_roleinfo('root')
    self.assertEqual(root_roleinfo['threshold'], 8)
    self.assertEqual(number_of_root_keys - 1, len(tuf.keydb._keydb_dict))

    



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
    length, hashes = tuf.util.get_file_details(root_filepath)
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





  def test_2__import_delegations(self):
    # Setup.
    # In order to test '_import_delegations' the parent of the delegation
    # has to be in Repository.metadata['current'], but it has to be inserted
    # there without using '_load_metadata_from_file()' since it calls
    # '_import_delegations()'.
    tuf.keydb.clear_keydb()
    tuf.roledb.clear_roledb()

    self.assertEqual(len(tuf.roledb._roledb_dict), 0)
    self.assertEqual(len(tuf.keydb._keydb_dict), 0)
    
    self.repository_updater._rebuild_key_and_role_db()
    
    self.assertEqual(len(tuf.roledb._roledb_dict), 4)
    self.assertEqual(len(tuf.keydb._keydb_dict), 4)

    # Test: pass a role without delegations.
    self.repository_updater._import_delegations('root')

    # Verify that there was no change in roledb and keydb dictionaries
    # by checking the number of elements in the dictionaries.
    self.assertEqual(len(tuf.roledb._roledb_dict), 4)       
    self.assertEqual(len(tuf.keydb._keydb_dict), 4)

    # Test: normal case, first level delegation.
    self.repository_updater._import_delegations('targets')

    self.assertEqual(len(tuf.roledb._roledb_dict), 5)
    self.assertEqual(len(tuf.keydb._keydb_dict), 5)

    # Verify that roledb dictionary was added.
    self.assertTrue('targets/role1' in tuf.roledb._roledb_dict)
    
    # Verify that keydb dictionary was updated.
    role1_signable = \
      tuf.util.load_json_file(os.path.join(self.client_metadata_current,
                                           'targets', 'role1.json'))
    keyids = []
    for signature in role1_signable['signatures']:
      keyids.append(signature['keyid'])
      
    for keyid in keyids:
      self.assertTrue(keyid in tuf.keydb._keydb_dict)





  def test_2__fileinfo_has_changed(self):
    #  Verify that the method returns 'False' if file info was not changed.
    root_filepath = os.path.join(self.client_metadata_current, 'root.json')
    length, hashes = tuf.util.get_file_details(root_filepath)
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
    
    # 'tuf.ExpiredMetadataError' should be raised in this next test condition,
    # because the expiration_date has expired by 10 seconds.
    expires = tuf.formats.unix_timestamp_to_datetime(int(time.time() - 10))
    expires = expires.isoformat() + 'Z'
    root_metadata['expires'] = expires
    
    # Ensure the 'expires' value of the root file is valid by checking the
    # the formats of the 'root.json' object.
    self.assertTrue(tuf.formats.ROOT_SCHEMA.matches(root_metadata))
    self.assertRaises(tuf.ExpiredMetadataError,
                      self.repository_updater._ensure_not_expired,
                      root_metadata, 'root')





  def test_3__update_metadata(self):
    # Setup 
    # _update_metadata() downloads, verifies, and installs the specified
    # metadata role.  Remove knowledge of currently installed metadata and
    # verify that they are re-installed after calling _update_metadata().
    
    # This is the default metadata that we would create for the timestamp role,
    # because it has no signed metadata for itself.
    DEFAULT_TIMESTAMP_FILEINFO = {
    'hashes': {},
    'length': tuf.conf.DEFAULT_TIMESTAMP_REQUIRED_LENGTH
    }
   
    # Save the fileinfo of 'targets.json' and 'targets.json.gz', needed later
    # when re-installing with _update_metadata().
    targets_fileinfo = \
      self.repository_updater.metadata['current']['snapshot']['meta']\
                                      ['targets.json']
    targets_compressed_fileinfo = \
      self.repository_updater.metadata['current']['snapshot']['meta']\
                                      ['targets.json.gz']
   
    # Remove the currently installed metadata from the store, and disk.  Verify
    # that the metadata dictionary is re-populated after calling
    # _update_metadata().
    self.repository_updater.metadata['current'].clear()
    timestamp_filepath = \
      os.path.join(self.client_metadata_current, 'timestamp.json')
    targets_filepath = os.path.join(self.client_metadata_current, 'targets.json')
    root_filepath = os.path.join(self.client_metadata_current, 'root.json')
    os.remove(timestamp_filepath)
    os.remove(targets_filepath)

    # Test: normal case.
    # Verify 'timestamp.json' is properly installed.
    self.assertFalse('timestamp' in self.repository_updater.metadata)
    self.repository_updater._update_metadata('timestamp',
                                             DEFAULT_TIMESTAMP_FILEINFO)
    self.assertTrue('timestamp' in self.repository_updater.metadata['current'])
    os.path.exists(timestamp_filepath)
  
    # Verify 'targets.json' is properly installed.
    self.assertFalse('targets' in self.repository_updater.metadata['current'])
    self.repository_updater._update_metadata('targets', targets_fileinfo)
    self.assertTrue('targets' in self.repository_updater.metadata['current'])
    length, hashes = tuf.util.get_file_details(targets_filepath)
    self.assertEqual(targets_fileinfo, tuf.formats.make_fileinfo(length, hashes))
    
    # Remove the 'targets.json' metadata so that the compressed version may be
    # tested next.
    del self.repository_updater.metadata['current']['targets']
    os.remove(targets_filepath)

    # Verify 'targets.json.gz' is properly intalled.  Note: The uncompressed
    # version is installed if the compressed one is downloaded.
    self.assertFalse('targets' in self.repository_updater.metadata['current'])
    self.repository_updater._update_metadata('targets', targets_fileinfo, 'gzip',
                                             targets_compressed_fileinfo)
    self.assertTrue('targets' in self.repository_updater.metadata['current'])
    length, hashes = tuf.util.get_file_details(targets_filepath)
    self.assertEqual(targets_fileinfo, tuf.formats.make_fileinfo(length, hashes))
    
    # Test: Invalid fileinfo.
    # Invalid fileinfo for the uncompressed version of 'targets.json'.
    self.assertRaises(tuf.NoWorkingMirrorError,
                      self.repository_updater._update_metadata,
                      'targets', targets_compressed_fileinfo)
    
    # Verify that the specific exception raised is correct for the previous
    # case.
    try:
      self.repository_updater._update_metadata('targets',
                                               targets_compressed_fileinfo)
    
    except tuf.NoWorkingMirrorError as e:
      for mirror_error in six.itervalues(e.mirror_errors):
        assert isinstance(mirror_error, tuf.BadHashError)
    
    # Invalid fileinfo for the compressed version of 'targets.json' 
    self.assertRaises(tuf.NoWorkingMirrorError,
                      self.repository_updater._update_metadata,
                      'targets', targets_compressed_fileinfo, 'gzip',
                      targets_fileinfo)
    
    # Verify that the specific exception raised is correct for the previous
    # case.  The length is checked before the hashes, so the specific error in
    # this case should be 'tuf.DownloadLengthMismatchError'.
    try:
      self.repository_updater._update_metadata('targets',
                                               targets_compressed_fileinfo,
                                               'gzip', targets_fileinfo)
    
    except tuf.NoWorkingMirrorError as e:
      for mirror_error in six.itervalues(e.mirror_errors):
        assert isinstance(mirror_error, tuf.DownloadLengthMismatchError)





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
    repository.targets.load_signing_key(self.role_keys['targets']['private'])
    repository.snapshot.load_signing_key(self.role_keys['snapshot']['private'])
    repository.timestamp.load_signing_key(self.role_keys['timestamp']['private'])
    repository.write()
    
    # Move the staged metadata to the "live" metadata.
    shutil.rmtree(os.path.join(self.repository_directory, 'metadata'))
    shutil.copytree(os.path.join(self.repository_directory, 'metadata.staged'),
                    os.path.join(self.repository_directory, 'metadata'))


    # Update 'targets.json' and verify that the client's current 'targets.json'
    # has been updated.  'timestamp' and 'snapshot' must be manually updated
    # so that new 'targets' may be recognized.
    DEFAULT_TIMESTAMP_FILEINFO = {
    'hashes': {},
    'length': tuf.conf.DEFAULT_TIMESTAMP_REQUIRED_LENGTH
    }

    self.repository_updater._update_metadata('timestamp', DEFAULT_TIMESTAMP_FILEINFO)
    self.repository_updater._update_metadata_if_changed('snapshot', 'timestamp')
    self.repository_updater._update_metadata_if_changed('targets')
    targets_path = os.path.join(self.client_metadata_current, 'targets.json')
    self.assertTrue(os.path.exists(targets_path))
    self.assertTrue(self.repository_updater.metadata['current']['targets'])
    self.assertEqual(self.repository_updater.metadata['current']['targets']['version'], 2)

    


  def test_3__targets_of_role(self):
    # Setup.
    # Extract the list of targets from 'targets.json', to be compared to what
    # is returned by _targets_of_role('targets').
    targets_in_metadata = \
      self.repository_updater.metadata['current']['targets']['targets']
    
    # Test: normal case.
    targets_list = self.repository_updater._targets_of_role('targets')
    
    # Verify that the list of targets was returned, and that it contains valid
    # target files.
    self.assertTrue(tuf.formats.TARGETFILES_SCHEMA.matches(targets_list))
    for target in targets_list:
      self.assertTrue((target['filepath'], target['fileinfo']) in six.iteritems(targets_in_metadata))
   




  def test_4_refresh(self):
    # This unit test is based on adding an extra target file to the
    # server and rebuilding all server-side metadata.  All top-level metadata
    # should be updated when the client calls refresh().
    
    # First verify that an expired root metadata is updated.
    expired_date = '1960-01-01T12:00:00Z' 
    self.repository_updater.metadata['current']['root']['expires'] = expired_date
    self.repository_updater.refresh() 

    repository = repo_tool.load_repository(self.repository_directory)
    target3 = os.path.join(self.repository_directory, 'targets', 'file3.txt')

    repository.targets.add_target(target3)
    repository.targets.load_signing_key(self.role_keys['targets']['private'])
    repository.snapshot.load_signing_key(self.role_keys['snapshot']['private'])
    repository.timestamp.load_signing_key(self.role_keys['timestamp']['private'])
    repository.write()
    
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
    # Assumed the client repository has only loaded the top-level metadata.
    # refresh the 'targets.json' metadata, including delegations. 
    self.assertEqual(len(self.repository_updater.metadata['current']), 4)

    # Test: normal case.
    self.repository_updater._refresh_targets_metadata(include_delegations=True)

    # Verify that client's metadata files were refreshed successfully.
    self.assertEqual(len(self.repository_updater.metadata['current']), 5)





  def test_5_all_targets(self):
   # Setup
   # As with '_refresh_targets_metadata()',

   # Update top-level metadata before calling one of the "targets" methods, as
   # recommended by 'updater.py'.
   self.repository_updater.refresh()

   # Test: normal case.
   all_targets = self.repository_updater.all_targets()

   # Verify format of 'all_targets', it should correspond to 
   # 'TARGETFILES_SCHEMA'.
   self.assertTrue(tuf.formats.TARGETFILES_SCHEMA.matches(all_targets))

   # Verify that there is a correct number of records in 'all_targets' list,
   # and the expected filepaths specified in the metadata.  On the targets
   # directory of the repository, there should be 3 target files (2 of
   # which are specified by 'targets.json'.)  The delegated role 'targets/role1'
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
                                    'targets', 'role1.json')
    role1_signable = tuf.util.load_json_file(role1_filepath)
    expected_targets = role1_signable['signed']['targets']


    # Test: normal case.
    targets_list = self.repository_updater.targets_of_role('targets/role1')

    # Verify that the expected role files were downloaded and installed.
    os.path.exists(os.path.join(self.client_metadata_current, 'targets.json'))
    os.path.exists(os.path.join(self.client_metadata_current, 'targets',
                                'role1.json'))
    self.assertTrue('targets' in self.repository_updater.metadata['current'])
    self.assertTrue('targets/role1' in self.repository_updater.metadata['current'])

    #  Verify that list of targets was returned and that it contains valid
    # target files.
    self.assertTrue(tuf.formats.TARGETFILES_SCHEMA.matches(targets_list))
    for target in targets_list:
      self.assertTrue((target['filepath'], target['fileinfo']) in six.iteritems(expected_targets))


    # Test: Invalid arguments.
    # targets_of_role() expected a string rolename.
    self.assertRaises(tuf.FormatError, self.repository_updater.targets_of_role,
                      8)
    self.assertRaises(tuf.UnknownRoleError, self.repository_updater.targets_of_role,
                      'unknown_rolename')




  def test_6_target(self):
    # Setup
    # Extract the file information of the targets specified in 'targets.json'.
    self.repository_updater.refresh()
    targets_metadata = self.repository_updater.metadata['current']['targets']
   
    target_files = targets_metadata['targets']
    # Extract random target from 'target_files', which will be compared to what
    # is returned by target().  Restore the popped target (dict value stored in
    # the metadata store) so that it can be found later.
    filepath, fileinfo = target_files.popitem()
    target_files[filepath] = fileinfo

    target_fileinfo = self.repository_updater.target(filepath)
    self.assertTrue(tuf.formats.TARGETFILE_SCHEMA.matches(target_fileinfo))
    self.assertEqual(target_fileinfo['filepath'], filepath)
    self.assertEqual(target_fileinfo['fileinfo'], fileinfo)
    
    # Test: invalid target path.    
    self.assertRaises(tuf.UnknownTargetError, self.repository_updater.target,
                      self.random_path())
    
    # Test updater.target() backtracking behavior (enabled by default.)
    targets_directory = os.path.join(self.repository_directory, 'targets')
    foo_directory = os.path.join(targets_directory, 'foo')
    os.makedirs(foo_directory)

    foo_package = os.path.join(foo_directory, 'foo1.1.tar.gz')
    with open(foo_package, 'wb') as file_object:
      file_object.write(b'new release')
    
    # Modify delegations on the remote repository to test backtracking behavior.
    repository = repo_tool.load_repository(self.repository_directory)
  
     
    repository.targets.delegate('role2', [self.role_keys['targets']['public']],
                                [], restricted_paths=[foo_directory])
    
    repository.targets.delegate('role3', [self.role_keys['targets']['public']],
                                [foo_package], restricted_paths=[foo_directory])
    repository.targets.load_signing_key(self.role_keys['targets']['private'])
    repository.targets('role2').load_signing_key(self.role_keys['targets']['private']) 
    repository.targets('role3').load_signing_key(self.role_keys['targets']['private']) 
    repository.snapshot.load_signing_key(self.role_keys['snapshot']['private'])
    repository.timestamp.load_signing_key(self.role_keys['timestamp']['private'])
    repository.write()
    
    # Move the staged metadata to the "live" metadata.
    shutil.rmtree(os.path.join(self.repository_directory, 'metadata'))
    shutil.copytree(os.path.join(self.repository_directory, 'metadata.staged'),
                    os.path.join(self.repository_directory, 'metadata'))

    # updater.target() should find 'foo1.1.tar.gz' by backtracking to
    # 'targets/role3'.  'targets/role2' allows backtracking.
    self.repository_updater.refresh()
    self.repository_updater.target('foo/foo1.1.tar.gz')


    # Test when 'targets/role2' does *not* allow backtracking.  If
    # 'foo/foo1.1.tar.gz' is not provided by the authoritative 'target/role2',
    # updater.target() should return a 'tuf.UnknownTargetError' exception.
    repository = repo_tool.load_repository(self.repository_directory)
    
    repository.targets.revoke('role2')
    repository.targets.revoke('role3')
   
    # Ensure we delegate in trusted order (i.e., 'role2' has higher priority.)
    repository.targets.delegate('role2', [self.role_keys['targets']['public']],
                                [], backtrack=False, restricted_paths=[foo_directory])
    repository.targets.delegate('role3', [self.role_keys['targets']['public']],
                                [foo_package], restricted_paths=[foo_directory])
    
    repository.targets('role2').load_signing_key(self.role_keys['targets']['private']) 
    repository.targets('role3').load_signing_key(self.role_keys['targets']['private']) 
    repository.targets.load_signing_key(self.role_keys['targets']['private'])
    repository.snapshot.load_signing_key(self.role_keys['snapshot']['private'])
    repository.timestamp.load_signing_key(self.role_keys['timestamp']['private'])
    repository.write()
    
    # Move the staged metadata to the "live" metadata.
    shutil.rmtree(os.path.join(self.repository_directory, 'metadata'))
    shutil.copytree(os.path.join(self.repository_directory, 'metadata.staged'),
                    os.path.join(self.repository_directory, 'metadata'))

    # Verify that 'tuf.UnknownTargetError' is raised by updater.target().
    self.repository_updater.refresh()
    self.assertRaises(tuf.UnknownTargetError, self.repository_updater.target,
                      'foo/foo1.1.tar.gz')





  def test_6_download_target(self):
    # Create temporary directory (destination directory of downloaded targets)
    # that will be passed as an argument to 'download_target()'.
    destination_directory = self.make_temp_directory()
    target_filepaths = \
      list(self.repository_updater.metadata['current']['targets']['targets'].keys())


    # Test: normal case.
    # Get the target info, which is an argument to 'download_target()'.
    for target_filepath in target_filepaths:
      target_fileinfo = self.repository_updater.target(target_filepath)
      self.repository_updater.download_target(target_fileinfo,
                                              destination_directory)
      download_filepath = \
        os.path.join(destination_directory, target_filepath.lstrip('/'))
      self.assertTrue(os.path.exists(download_filepath))
      length, hashes = tuf.util.get_file_details(download_filepath)
      download_targetfileinfo = tuf.formats.make_fileinfo(length, hashes)
     
      # Add any 'custom' data from the repository's target fileinfo to the
      # 'download_targetfileinfo' object being tested.
      if 'custom' in target_fileinfo['fileinfo']: 
        download_targetfileinfo['custom'] = target_fileinfo['fileinfo']['custom']
      self.assertEqual(target_fileinfo['fileinfo'], download_targetfileinfo)

    # Test: Invalid arguments.
    self.assertRaises(tuf.FormatError, self.repository_updater.download_target,
                      8, destination_directory)

    random_target_filepath = target_filepaths.pop()
    target_fileinfo = self.repository_updater.target(random_target_filepath)
    self.assertRaises(tuf.FormatError, self.repository_updater.download_target,
                      target_fileinfo, 8)
    
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
      self.repository_updater.download_target(target_fileinfo,
                                              destination_directory)
    
    except tuf.NoWorkingMirrorError as exception:
      # Ensure that no mirrors were found due to mismatch in confined target
      # directories.  get_list_of_mirrors() returns an empty list in this case,
      # which does not generate specific exception errors.
      self.assertEqual(len(exception.mirror_errors), 0)
     




  def test_7_updated_targets(self):
    # Verify that list contains all files that need to be updated, these
    # files include modified and new target files.  Also, confirm that files
    # than need not to be updated are absent from the list.
    # Setup 
    # Create temporary directory which will hold client's target files.
    destination_directory = self.make_temp_directory()

    # Get the list of target files.  It will be used as an argument to
    # 'updated_targets' function.
    all_targets = self.repository_updater.all_targets()
    
    #  At this point client needs to update and download all targets.
    # Test: normal cases.
    updated_targets = \
      self.repository_updater.updated_targets(all_targets, destination_directory)

    # Assumed the pre-generated repository specifies two target files in
    # 'targets.json' and one delegated target file in 'targets/role1.json'. 
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
    self.assertRaises(tuf.FormatError, self.repository_updater.updated_targets,
                      8, destination_directory)

    self.assertRaises(tuf.FormatError, self.repository_updater.updated_targets,
                      all_targets, 8)

    # Modify one target file on the remote repository.
    repository = repo_tool.load_repository(self.repository_directory)
    target1 = os.path.join(self.repository_directory, 'targets', 'file1.txt')
    
    repository.targets.remove_target(target1)
    with open(target1, 'a') as file_object:
      file_object.write('append extra text')

    repository.targets.add_target(target1)
    repository.targets.load_signing_key(self.role_keys['targets']['private'])
    repository.snapshot.load_signing_key(self.role_keys['snapshot']['private'])
    repository.timestamp.load_signing_key(self.role_keys['timestamp']['private'])
    repository.write()
    
    # Move the staged metadata to the "live" metadata.
    shutil.rmtree(os.path.join(self.repository_directory, 'metadata'))
    shutil.copytree(os.path.join(self.repository_directory, 'metadata.staged'),
                    os.path.join(self.repository_directory, 'metadata'))
    
    # Ensure the client has the up-to-date metadata.
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
    target2 = os.path.join(self.repository_directory, 'targets', 'file2.txt')
    repository.targets.remove_target(target1)
    repository.targets.remove_target(target2)

    repository.targets.load_signing_key(self.role_keys['targets']['private'])
    repository.snapshot.load_signing_key(self.role_keys['snapshot']['private'])
    repository.timestamp.load_signing_key(self.role_keys['timestamp']['private'])
    repository.write()
    
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
    self.assertEqual(len(os.listdir(destination_directory)), 1)

    #  Verify that, if there are no obsolete files, the number of files
    #  in 'destination_directory' remains the same.
    self.repository_updater.remove_obsolete_targets(destination_directory)
    self.assertEqual(len(os.listdir(destination_directory)), 1)    
 




  def test_9__get_target_hash(self):
    # Test normal case.
    # Test target filepaths with ascii and non-ascii characters.
    expected_target_hashes = {
      '/file1.txt': 'e3a3d89eb3b70ce3fbce6017d7b8c12d4abd5635427a0e8a238f53157df85b3d',
      '/Jalape\xc3\xb1o': '78bfd5c314680545eb48ecad508aceb861f8d6e680f4fe1b791da45c298cda88' 
    }
    for filepath, target_hash in six.iteritems(expected_target_hashes):
      self.assertTrue(tuf.formats.RELPATH_SCHEMA.matches(filepath))
      self.assertTrue(tuf.formats.HASH_SCHEMA.matches(target_hash))
      self.assertEqual(self.repository_updater._get_target_hash(filepath), target_hash)
   
    # Test for improperly formatted argument.
    self.assertRaises(tuf.FormatError, tuf.util.get_target_hash, 8)





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
    repo_tool.import_rsa_publickey_from_file(targets_key_file+'.pub')
  role_keys['snapshot']['public'] = \
    repo_tool.import_rsa_publickey_from_file(snapshot_key_file+'.pub')
  role_keys['timestamp']['public'] = \
      repo_tool.import_rsa_publickey_from_file(timestamp_key_file+'.pub')
  role_keys['role1']['public'] = \
      repo_tool.import_rsa_publickey_from_file(delegation_key_file+'.pub')

  # Import the private keys of the top-level and delegated roles.
  role_keys['root']['private'] = \
    repo_tool.import_rsa_privatekey_from_file(root_key_file, 
                                              EXPECTED_KEYFILE_PASSWORD)
  role_keys['targets']['private'] = \
    repo_tool.import_rsa_privatekey_from_file(targets_key_file,
                                              EXPECTED_KEYFILE_PASSWORD)
  role_keys['snapshot']['private'] = \
    repo_tool.import_rsa_privatekey_from_file(snapshot_key_file,
                                              EXPECTED_KEYFILE_PASSWORD)
  role_keys['timestamp']['private'] = \
    repo_tool.import_rsa_privatekey_from_file(timestamp_key_file,
                                              EXPECTED_KEYFILE_PASSWORD)
  role_keys['role1']['private'] = \
    repo_tool.import_rsa_privatekey_from_file(delegation_key_file,
                                              EXPECTED_KEYFILE_PASSWORD)

  return role_keys


if __name__ == '__main__':
  unittest.main()
