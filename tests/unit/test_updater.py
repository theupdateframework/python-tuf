#!/usr/bin/env python

"""
<Program Name>
  test_updater.py

<Author>
  Konstantin Andrianov

<Started>
  October 15, 2012.
  March 11, 2014.  Refactored to avoid mocking, and to use exact repositories
  and realistic retrieval of files. -vladimir.v.diaz

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  test_updater.py provides a collection of methods that test all the methods
  and functions of 'tuf.client.updater.py'.

  The 'unittest_toolbox.py' module was created to provide additional testing
  tools.  For more info see 'unittest_toolbox.py'.

<Methodology>
  Test cases here should follow a specific order (i.e., independent methods are 
  tested prior to dependent methods). More accurately, least dependent methods
  are tested before most dependent methods.  There is no reason to rewrite or
  construct other methods that replicate already-tested methods solely for
  testing purposes.  This is possible because the 'unittest.TestCase' class
  guarantees the order of unit tests.  The 'test_something_A' method would
  be tested before 'test_something_B'.  To ensure the expected order of tests,
  a number is be placed after 'test' and before methods name like so:
  'test_1_check_directory'.  The number is a measure of dependence, where 1 is
  less dependent than 2.
"""

import os
import time
import shutil
import tempfile
import logging
import unittest
import random
import subprocess

import tuf
import tuf.client.updater as updater
import tuf.conf
import tuf.log
import tuf.formats
import tuf.keydb
import tuf.roledb
import tuf.repository_tool as repo_tool
import tuf.tests.unittest_toolbox as unittest_toolbox
import tuf.util

logger = logging.getLogger('tuf.test_updater')
repo_tool.disable_console_log_messages()


class TestUpdater(unittest_toolbox.Modified_TestCase):

  @classmethod
  def setUpClass(cls):
    # setUpClass() is called before tests in an individual class run.
    
    # Create a temporary directory to store the repository, metadata, and target
    # files.  'temporary_directory' must be deleted in TearDownModule() so that
    # temporary files are always removed, including when exceptions occur. 
    cls.temporary_directory = tempfile.mkdtemp(dir=os.getcwd())
    
    # Launch a SimpleHTTPServer (serves files in the current directory).
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
   
    # Remove the temporary repository directory, which should contain the
    # metadata, targets, and key files.
    shutil.rmtree(cls.temporary_directory)
    
    unittest_toolbox.Modified_TestCase.clear_toolbox()
   
    # Kill the SimpleHTTPServer process.
    if cls.server_process.returncode is None:
      logger.info('\tServer process '+str(cls.server_process.pid)+' terminated.')
      cls.server_process.kill()



  def setUp(self):
    # We are inheriting from custom class.
    unittest_toolbox.Modified_TestCase.setUp(self)
  
    # Copy the original repository files provided in the test folder.
    # The 'test_repository' directory is expected to exist in the same directory
    # as the unit test modules.
    original_repository_files = os.path.join(os.getcwd(), 'test_repository') 
    temporary_repository_root = \
      self.make_temp_directory(directory=self.temporary_directory)
   
    original_repository = os.path.join(original_repository_files, 'repository')
    original_keystore = os.path.join(original_repository_files, 'keystore')
    original_client = os.path.join(original_repository_files, 'client')

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

    # Creating Repository instance.
    self.repository_updater = updater.Updater('test_repository',
                                              self.repository_mirrors)

    self.role_keys = _load_role_keys(self.keystore_directory)



  def tearDown(self):
    # We are inheriting from custom class.
    unittest_toolbox.Modified_TestCase.tearDown(self)
    
    # Clear roledb and keydb dictionaries.
    #tuf.roledb.clear_roledb()
    #tuf.keydb.clear_keydb()




  # HELPER FUNCTIONS (start with '_').
  
  def _add_file_to_directory(self, directory):
    file_path = tempfile.mkstemp(suffix='.txt', dir=directory)
    fileobj = open(file_path[1], 'wb')
    fileobj.write(self.random_string())
    fileobj.close()
    return file_path[1]



  def _add_target_to_targets_dir(self, targets_keyids):
    """
    Adds a file to server's 'targets' directory and rebuilds
    targets metadata (targets.json).
    """
    
    targets_sub_dir = os.path.join(self.targets_dir, 'targets_sub_dir')
    if not os.path.exists(targets_sub_dir):
      os.mkdir(targets_sub_dir)
    file_path = tempfile.mkstemp(suffix='.txt', dir=targets_sub_dir)
    data = self.random_string()
    file_object = open(file_path[1], 'wb')
    file_object.write(data)
    file_object.close()

    #  In order to rebuild metadata, keystore's dictionary must be loaded.
    #  Fortunately, 'unittest_toolbox.rsa_keystore' dictionary stores all keys.
    keystore._keystore = self.rsa_keystore
    setup.build_server_repository(self.server_repo_dir, self.targets_dir)

    keystore._keystore = {}
    junk, target_filename = os.path.split(file_path[1])
    return os.path.join('targets_sub_dir', target_filename)



  def _remove_target_from_targets_dir(self, target_filename, remove_all=True):
    """
    Remove a target 'target_filename' from server's targets directory and
    rebuild 'targets', 'snapshot', 'timestamp' metadata files.
    'target_filename' is relative to targets directory. 
    Example of 'target_filename': 'targets_sub_dir/somefile.txt'.

    If 'remove_all' is set to True, then the sub directory 'targets_sub_dir'
    (with all added targets) is removed.  All listed metadata files are
    rebuilt.
    """
    
    targets_sub_dir = os.path.join(self.targets_dir, 'targets_sub_dir')
    if remove_all:
      shutil.rmtree(targets_sub_dir)
    else:
      target_path = os.path.join(targets_dir, target_filename)
      os.remove(target_path)

    #  In order to rebuild metadata, keystore's dictionary must be loaded.
    keystore._keystore = self.rsa_keystore
    setup.build_server_repository(self.server_repo_dir, self.targets_dir)
  
    #  Synchronise client's repository with server's repository.
    shutil.rmtree(self.client_meta_dir)
    shutil.copytree(self.server_meta_dir, self.client_current_dir)
    shutil.copytree(self.server_meta_dir, self.client_previous_dir)

    keystore._keystore = {}




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
   
    # Test: properly updated roledb and keydb dicts if Root role changes.
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
    self.assertTrue('root.json' in fileinfo_dict.keys())
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
    
    self.repository_updater._move_current_to_previous('snapshot')
    self.assertTrue(os.path.exists(previous_snapshot_filepath))
    shutil.copy(previous_snapshot_filepath, self.client_metadata_current)





  def test_2__delete_metadata(self):
    # This test will verify that 'root' metadata is never deleted, when
    # role is deleted verify that the file is not present in the 
    # 'self.repository_updater.metadata' dictionary.
    self.repository_updater._delete_metadata('root')
    self.assertTrue('root' in self.repository_updater.metadata['current'])
    
    self.repository_updater._delete_metadata('timestamp')
    self.assertFalse('timestamp' in self.repository_updater.metadata['current'])
    previous_timestamp_filepath = os.path.join(self.client_metadata_previous,
                                       'timestamp.json')
    shutil.copy(previous_timestamp_filepath, self.client_metadata_current)





  def test_2__ensure_not_expired(self):
    # This test condition will verify that nothing is raised when a metadata
    # file has a future expiration date.
    self.repository_updater._ensure_not_expired('root')
    
    # 'tuf.ExpiredMetadataError' should be raised in this next test condition,
    # because the expiration_date has expired by 10 seconds.
    expires = tuf.formats.format_time(time.time() - 10)
    self.repository_updater.metadata['current']['root']['expires'] = expires
    
    # Ensure the 'expires' value of the root file is valid by checking the
    # the formats of the 'root.json' object.
    root_object = self.repository_updater.metadata['current']['root']
    self.assertTrue(tuf.formats.ROOT_SCHEMA.matches(root_object))
    self.assertRaises(tuf.ExpiredMetadataError,
                      self.repository_updater._ensure_not_expired, 'root')





  def test_3__update_metadata(self):
    """
    _update_metadata() downloads, verifies, and installs the specified metadata
    role.  Remove knowledge of currently installed metadata and verify that
    they are re-installed after calling _update_metadata().
    """
    
    # Setup
    # Remove the installed metadata.  _update_metadata() will be called to
    # ensure the removed metadata is properly re-installed.
    
    # This is the default metadata that we would create for the timestamp role,
    # because it has no signed metadata for itself.
    DEFAULT_TIMESTAMP_FILEINFO = {
    'hashes': {},
    'length': tuf.conf.DEFAULT_TIMESTAMP_REQUIRED_LENGTH
    }
    
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
    # version is installed if the compressed one downloaded.
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
    
    except tuf.NoWorkingMirrorError, e:
      for mirror_error in e.mirror_errors.values():
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
    
    except tuf.NoWorkingMirrorError, e:
      for mirror_error in e.mirror_errors.values():
        assert isinstance(mirror_error, tuf.DownloadLengthMismatchError)





  def test_3__update_metadata_if_changed(self):
    """
    This unit test verifies the method's proper behaviour on expected input.
    """
    
    #  To test updater._update_metadata_if_changed, 'targets' metadata file is
    #  going to be modified at the server's repository.
    #  Keyid's are required to build the metadata.
    targets_keyids = setup.role_keyids['targets']

    #  Add a file to targets directory and rebuild targets metadata.
    #  Returned target's filename will be used to verify targets metadata.
    added_target_1 = self._add_target_to_targets_dir(targets_keyids)

    #  Reference 'self.Repository._update_metadata_if_changed' function.
    update_if_changed = self.Repository._update_metadata_if_changed


    # Test: normal case.  Update 'snapshot' metadata.
    #  Patch download_file.
    self._mock_download_url_to_tempfileobj(self.timestamp_filepath)

    #  Update timestamp metadata, it will indicate change in snapshot metadata.
    self.Repository._update_metadata('timestamp', DEFAULT_TIMESTAMP_FILEINFO)

    #  Save current snapshot metadata before updating.  It will be used to
    #  verify the update.
    old_snapshot_meta = self.Repository.metadata['current']['snapshot']
    self._mock_download_url_to_tempfileobj(self.snapshot_filepath)

    #  Update snapshot metadata, it will indicate change in targets metadata.
    update_if_changed(metadata_role='snapshot', referenced_metadata='timestamp')
    current_snapshot_meta = self.Repository.metadata['current']['snapshot']
    previous_snapshot_meta = self.Repository.metadata['previous']['snapshot']
    self.assertEqual(old_snapshot_meta, previous_snapshot_meta)
    self.assertNotEqual(old_snapshot_meta, current_snapshot_meta)


    # Test: normal case.  Update 'targets' metadata. 
    #  Patch 'download.download_url_to_tempfileobj' and update targets.
    self._mock_download_url_to_tempfileobj(self.targets_filepath)
    update_if_changed('targets')
    list_of_targets = self.Repository.metadata['current']['targets']['targets']

    #  Verify that the added target's path is listed in target's metadata.
    if added_target_1 not in list_of_targets.keys():
      self.fail('\nFailed to update targets metadata.')


    # Test: normal case.  Update compressed snapshot file.
    snapshot_filepath_compressed = self._compress_file(self.snapshot_filepath)

    #  Since client's '.../metadata/current' will need to have separate
    #  gzipped metadata file in order to test compressed file handling,
    #  we need to copy it there.  
    shutil.copy(snapshot_filepath_compressed, self.client_current_dir) 
  
    #  Add a target file and rebuild metadata files at the server side.
    added_target_2 = self._add_target_to_targets_dir(targets_keyids)
    
    #  Since snapshot file was updated, update compressed snapshot file.
    snapshot_filepath_compressed = self._compress_file(self.snapshot_filepath)
 
    #  Patch download_file.
    self._mock_download_url_to_tempfileobj(self.timestamp_filepath)

    #  Update timestamp metadata, it will indicate change in snapshot metadata.
    self.Repository._update_metadata('timestamp', DEFAULT_TIMESTAMP_FILEINFO)

    #  Save current snapshot metadata before updating.  It will be used to
    #  verify the update.
    old_snapshot_meta = self.Repository.metadata['current']['snapshot']
    self._mock_download_url_to_tempfileobj(self.snapshot_filepath)

    #  Update snapshot metadata, and verify the change.
    update_if_changed(metadata_role='snapshot', referenced_metadata='timestamp')
    current_snapshot_meta = self.Repository.metadata['current']['snapshot']
    previous_snapshot_meta = self.Repository.metadata['previous']['snapshot']
    self.assertEqual(old_snapshot_meta, previous_snapshot_meta)
    self.assertNotEqual(old_snapshot_meta, current_snapshot_meta)
  

    # Test: Invalid targets metadata file downloaded.
    #  Patch 'download.download_url_to_tempfileobj' and update targets.
    self._mock_download_url_to_tempfileobj(self.root_filepath)

    # FIXME: What is the original intent of this test?
    try:
      update_if_changed('targets')
    except tuf.NoWorkingMirrorError, exception:
      for mirror_url, mirror_error in exception.mirror_errors.iteritems():
        assert isinstance(mirror_error, tuf.DownloadLengthMismatchError)





  def test_3__targets_of_role(self):
    # Setup
    targets_dir_content = os.listdir(self.targets_dir)


    # Test: normal case.
    targets_list = self.Repository._targets_of_role('targets')
    
    #  Verify that list of targets was returned,
    #  and that it contains valid target file.
    self.assertTrue(tuf.formats.TARGETFILES_SCHEMA.matches(targets_list))
    targets_filepaths = []
    for target in range(len(targets_list)):
      targets_filepaths.append(targets_list[target]['filepath'])
    for dir_target in targets_dir_content:
      if dir_target.endswith('.json'):
        self.assertTrue(dir_target in targets_filepaths)





  def test_4_refresh(self):
    
    #  This unit test is based on adding an extra target file to the
    #  server and rebuilding all server-side metadata.  When 'refresh'
    #  function is called by the client all top level metadata should
    #  be updated.
    target_fullpath = self._add_file_to_directory(self.targets_dir)
    target_relpath = os.path.split(target_fullpath)
    
    #  Reference 'self.Repository.metadata['current']['targets']'.
    targets_meta = self.Repository.metadata['current']['targets']
    self.assertFalse(target_relpath[1] in targets_meta['targets'].keys())

    #  Rebuild metadata at the server side.
    self._mock_download_url_to_tempfileobj(self.all_role_paths)
    setup.build_server_repository(self.server_repo_dir, self.targets_dir)
  

    # Test: normal case. 
    self.Repository.refresh()

    #  Verify that clients metadata was updated. 
    targets_meta = self.Repository.metadata['current']['targets']
    self.assertTrue(target_relpath[1] in targets_meta['targets'].keys())


    # Restore server's repository to initial state.
    self._remove_filepath(target_fullpath)
    #  Rebuild metadata at the server side.
    self._mock_download_url_to_tempfileobj(self.all_role_paths)
    setup.build_server_repository(self.server_repo_dir, self.targets_dir)




  def test_4__refresh_targets_metadata(self):
    
    # To test this method a target file would be added to a delegated role,
    # and metadata on the server side would be rebuilt.
    targets_deleg_dir1 = os.path.join(self.targets_dir, 'delegated_level1')
    targets_deleg_dir2 = os.path.join(targets_deleg_dir1, 'delegated_level2')
    shutil.rmtree(self.server_meta_dir)
    shutil.rmtree(os.path.join(self.server_repo_dir, 'keystore'))
    tuf.roledb._roledb_dict['targets/delegated_role1'] = \
        self.semi_roledict['targets/delegated_role1'] 
    tuf.roledb._roledb_dict['targets/delegated_role1/delegated_role2'] = \
        self.semi_roledict['targets/delegated_role1/delegated_role2']

    #  Delegated roles paths.
    role1_dir = os.path.join(self.server_meta_dir, 'targets')
    role1_filepath = os.path.join(role1_dir, 'delegated_role1.json')
    role2_dir = os.path.join(role1_dir, 'delegated_role1')
    role2_filepath = os.path.join(role2_dir, 'delegated_role2.json')

    #  Create a file in the delegated targets directory.
    deleg_target_filepath2 = self._add_file_to_directory(targets_deleg_dir2)
    junk, deleg_target_file2 = os.path.split(deleg_target_filepath2)
  
    #  Rebuild server's metadata and update client's metadata.
    setup.build_server_repository(self.server_repo_dir, self.targets_dir)
    self._update_top_level_roles()

    #  Patching 'download.download_url_to_tempfilepbj' function.
    delegated_roles = [role1_filepath, role2_filepath]
    self._mock_download_url_to_tempfileobj(delegated_roles)


    # Test: normal case.
    self.Repository._refresh_targets_metadata(include_delegations=True)

    #  References
    deleg_role = 'targets/delegated_role1/delegated_role2'
    deleg_metadata = self.Repository.metadata['current'][deleg_role]

    #  Verify that client's metadata files were refreshed successfully by
    #  checking that the added target file is listed in the client's metadata.
    #  'targets_list' is the list of included targets from client's metadata.
    targets_list = [] 
    for target in deleg_metadata['targets']:
      junk, target_file  = os.path.split(target)
      targets_list.append(target_file)

    self.assertTrue(deleg_target_file2 in targets_list)


    #  Clean up.
    self._remove_filepath(deleg_target_filepath2)
    shutil.rmtree(os.path.join(self.server_repo_dir, 'metadata'))
    shutil.rmtree(os.path.join(self.server_repo_dir, 'keystore'))
    setup.build_server_repository(self.server_repo_dir, self.targets_dir)





  def test_5_all_targets(self):
   
   # As with '_refresh_targets_metadata()', tuf.roledb._roledb_dict
   # has to be populated.  The 'tuf.download.safe_download' method
   # should be patched.  The 'self.all_role_paths' argument is passed so that
   # the top-level roles and delegations may be all "downloaded" when
   # Repository.refresh() is called below.  '_mock_download_url_to_tempfileobj'
   # returns each filepath listed in 'self.all_role_paths' in the listed
   # order.
   self._mock_download_url_to_tempfileobj(self.all_role_paths)
   setup.build_server_repository(self.server_repo_dir, self.targets_dir)

   # Update top-level metadata.
   self.Repository.refresh()


   # Test: normal case.
   all_targets = self.Repository.all_targets()

   #  Verify format of 'all_targets', it should correspond to
   #  'TARGETFILES_SCHEMA'.
   self.assertTrue(tuf.formats.TARGETFILES_SCHEMA.matches(all_targets))

   # Verify that there is a correct number of records in 'all_targets' list.
   # On the repository there are 4 target files, 2 of which are delegated.
   # The targets role lists all targets, for a total of 4.  The two delegated
   # roles each list 1 of the already listed targets in 'targets.json', for a
   # total of 2 (the delegated targets are listed twice).  The total number of
   # targets in 'all_targets' should then be 6.
   self.assertTrue(len(all_targets) is 6)   




  def test_5_targets_of_role(self):
    # Setup
    targets_dir_content = os.listdir(self.targets_dir)


    # Test: normal case.
    targets_list = self.Repository.targets_of_role()
    
    #  Verify that list of targets was returned,
    #  and that it contains valid target file.
    self.assertTrue(tuf.formats.TARGETFILES_SCHEMA.matches(targets_list))
    targets_filepaths = []
    for target in range(len(targets_list)):
      targets_filepaths.append(targets_list[target]['filepath'])
    for dir_target in targets_dir_content:
      if dir_target.endswith('.json'):
        self.assertTrue(dir_target in targets_filepaths)





  def test_6_target(self):
    # Requirements: make sure roledb_dict is populated and
    # tuf.download.safe_download function is patched.

    # Setup
    targets_dir_content = os.listdir(self.targets_dir)

    #  Reference 'self.Repository.metadata['current']['targets']['targets']
    targets_field = self.Repository.metadata['current']['targets']['targets']

    #  Reference 'self.Repository.target' function.
    target = self.Repository.target


    # Test: normal case.
    for _target in targets_dir_content:
      if _target.endswith('.json'):
        target_info = target(_target)
        #  Verify that 'target_info' corresponds to 'TARGETFILE_SCHEMA'.
        self.assertTrue(tuf.formats.TARGETFILE_SCHEMA.matches(target_info))


    # Test: invalid target path.    
    self.assertRaises(tuf.UnknownTargetError, target, self.random_path())






  def test_6_download_target(self):
    
    # 'tuf.download.safe_download' method should be patched.
    target_rel_paths_src = self._get_list_of_target_paths(self.targets_dir)

    #  Create temporary directory that will be passed as an argument to the
    #  'download_target' function as a targets destination directory.
    dest_dir = self.make_temp_directory()


    # Test: normal case.
    for file_path in target_rel_paths_src:
      #  Get the target info which is a parameter to 'download_target' method.
      target_info = self.Repository.target(file_path)
      self._mock_download_url_to_tempfileobj(os.path.join(self.targets_dir, file_path))
      self.Repository.download_target(target_info, dest_dir)

    #  Verify that all target files are downloaded.
    target_rel_paths_dest = self._get_list_of_target_paths(dest_dir)
    self.assertTrue(target_rel_paths_dest, target_rel_paths_src)


    # Test:
    # Attempt a file download of a valid target, however, a download exception
    # occurs because the target is not within the mirror's confined
    # target directories.
    #  Adjust mirrors dictionary, so that 'confined_target_dirs' field
    #  contains at least one confined target and excludes needed target file.
    mirrors = self.Repository.mirrors
    for mirror_name, mirror_info in mirrors.items():
      mirrors[mirror_name]['confined_target_dirs'] = [self.random_path()]

    #  Get the target file info.
    file_path = target_rel_paths_src[0]
    target_info = self.Repository.target(file_path)

    #  Patch 'download.download_url_to_tempfileobj' and verify that an
    #  exception is raised.
    self._mock_download_url_to_tempfileobj(os.path.join(self.targets_dir, file_path))

    try:
      self.Repository.download_target(target_info, dest_dir)
    except tuf.NoWorkingMirrorError, exception:
      # Ensure that no mirrors were found due to mismatch in confined target
      # directories.
      assert len(exception.mirror_errors) == 0
      
    for mirror_name, mirror_info in mirrors.items():
      mirrors[mirror_name]['confined_target_dirs'] = ['']




  def test_7_updated_targets(self):
    
    # In this test, client will have two target files.  Server will modify 
    # one of them.  As with 'all_targets' function, tuf.roledb._roledb_dict
    # has to be populated.  'tuf.download.safe_download' method
    # should be patched.
    target_rel_paths_src = self._get_list_of_target_paths(self.targets_dir)

    #  Create temporary directory which will hold client's target files.
    dest_dir = self.make_temp_directory()

    target_info = []
    for target_path in target_rel_paths_src:
      target_info.append(self.Repository.target(target_path))

    #  Populate 'dest_dir' with few target files.
    target_path0 = os.path.join(self.targets_dir, target_info[0]['filepath'])
    self._mock_download_url_to_tempfileobj(target_path0)
    self.Repository.download_target(target_info[0], dest_dir)

    target_path1 = os.path.join(self.targets_dir, target_info[1]['filepath'])
    self._mock_download_url_to_tempfileobj(target_path1)
    self.Repository.download_target(target_info[1], dest_dir)

    #  Modify one of the above downloaded target files at the server side.
    file_obj = open(target_path0, 'wb')
    file_obj.write(2*self.random_string())
    file_obj.close()

    #  Rebuild server's metadata and update client's metadata.
    setup.build_server_repository(self.server_repo_dir, self.targets_dir)
    self._update_top_level_roles()

    # Get the list of target files.  It will be used as an argument to
    # 'updated_targets' function.
    delegated_roles = []
    delegated_roles = self.all_role_paths[4:]
    self._mock_download_url_to_tempfileobj(delegated_roles)
    all_targets = self.Repository.all_targets()

    #  At this point client needs to update modified target and download
    #  two other targets.  As a result of calling 'update_targets' method,
    #  a list of updated/new targets (that will need to be downloaded)
    #  should be returned.

    
    # Test: normal cases.
    updated_targets = self.Repository.updated_targets(all_targets, dest_dir)

    #  Verify that list contains all files that need to be updated, these
    #  files include modified and new target files.  Also, confirm that files
    #  than need not to be updated are absent from the list.
   
    #  'updated_targets' list should contains 5 target files i.e. one - that
    #  was modified, two - that are absent from the client's repository and
    #  same two - belonging to delegated roles.
    self.assertTrue(len(updated_targets) is 5)
    for updated_target in updated_targets:
      if target_info[1]['filepath'] == updated_target['filepath']:
        msg = 'A file that need not to be updated is indicated as updated.'
        self.fail(msg)

    


  def test_8_remove_obsolete_targets(self):
    
    # This unit test should be last, because it removes target files from the
    # server's targets directory. It is done to avoid adding files, rebuilding 
    # and updating metadata. 
    target_rel_paths_src = self._get_list_of_target_paths(self.targets_dir)

    #  Create temporary directory which will hold client's target files.
    dest_dir = self.make_temp_directory()

    #  Populate 'dest_dir' with all target files.
    for target_path in target_rel_paths_src:
      _target_info = self.Repository.target(target_path)
      _target_path = os.path.join(self.targets_dir, target_path)
      self._mock_download_url_to_tempfileobj(_target_path)
      self.Repository.download_target(_target_info, dest_dir)

    #  Remove few target files from the server's repository.
    os.remove(os.path.join(self.targets_dir, target_rel_paths_src[0]))
    os.remove(os.path.join(self.targets_dir, target_rel_paths_src[3]))

    #  Rebuild server's metadata and update client's metadata.
    setup.build_server_repository(self.server_repo_dir, self.targets_dir)
    self._update_top_level_roles()

    #  Get the list of target files.  It will be used as an argument to
    #  'updated_targets' function.
    delegated_roles = []
    delegated_roles = self.all_role_paths[4:]
    self._mock_download_url_to_tempfileobj(delegated_roles)
    all_targets = self.Repository.all_targets()
    

    # Test: normal case.
    #  Verify number of target files in the 'dest_dir' (should be 4),
    #  and execute 'remove_obsolete_targets' function.
    self.assertTrue(os.listdir(dest_dir), 4)
    self.Repository.remove_obsolete_targets(dest_dir)

    #  Verify that number of target files in the 'dest_dir' is now 2, since
    #  two files were previously removed.
    self.assertTrue(os.listdir(dest_dir), 2)
    self.assertTrue(os.path.join(dest_dir), target_rel_paths_src[1])
    self.assertTrue(os.path.join(dest_dir), target_rel_paths_src[2])

    #  Verify that if there are no obsolete files, the number of files,
    #  in the 'dest_dir' remains the same.
    self.Repository.remove_obsolete_targets(dest_dir)
    self.assertTrue(os.listdir(dest_dir), 2)    





def _load_role_keys(keystore_directory):
  
  # Populating 'rsa_keystore' and 'rsa_passwords' dictionaries.
  # We will need them in creating the keystore directory and metadata files.

  # The pre-generated key files in 'test_repository" are all encrypted with
  # a 'password' passphrase.
  EXPECTED_KEYFILE_PASSWORD = 'password'

  # Store the cryptography keys of the top-level roles.  Any delegated roles 
  # should be assigned the key of the Targets role, to avoid .
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

  # Import the private keys of the top-level rolesand delegated roles private
  # keys.
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
