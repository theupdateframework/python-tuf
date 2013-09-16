#!/usr/bin/env python

"""
<Program Name>
  test_updater.py

<Author>
  Konstantin Andrianov

<Started>
  October 15, 2012

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  test_updater.py provides collection of methods that tries to test all the
  units (methods) of the module under test.

  unittest_toolbox module was created to provide additional testing tools for
  tuf's modules.  For more info see unittest_toolbox.py.


<Methodology>
  Unit tests must follow a specific structure i.e. independent methods should
  be tested prior to dependent methods. More accurately: least dependent
  methods are tested before most dependent methods.  There is no reason to
  rewrite or construct other methods that replicate already-tested methods
  solely for testing purposes.  This is possible because 'unittest.TestCase'
  class guarantees the order of unit tests.  So that, 'test_something_A'
  method would be tested before 'test_something_B'.  To ensure the structure
  a number will be placed after 'test' and before methods name like so:
  'test_1_check_directory'.  The number is a measure of dependence, where 1
  is less dependent than 2.

"""

import os
import gzip
import time
import shutil
import tempfile
import logging
import unittest


import tuf
import tuf.client.updater as updater
import tuf.conf
import tuf.log
import tuf.formats
import tuf.keydb
import tuf.repo.keystore as keystore
import tuf.repo.signerlib as signerlib
import tuf.roledb
import tuf.tests.repository_setup as setup
import tuf.tests.unittest_toolbox as unittest_toolbox
import tuf.util

logger = logging.getLogger('tuf.test_updater')


# This is the default metadata that we would create for the timestamp role,
# because it has no signed metadata for itself.
DEFAULT_TIMESTAMP_FILEINFO = {
  'hashes': None,
  'length': tuf.conf.DEFAULT_TIMESTAMP_REQUIRED_LENGTH
}

original_safe_download = tuf.download.safe_download
original_unsafe_download = tuf.download.unsafe_download

class TestUpdater_init_(unittest_toolbox.Modified_TestCase):

  def test__init__exceptions(self):
    # Setup:
    # Create an empty repository structure for client.
    repo_dir = self.make_temp_directory()

    # Config patch.  The repository directory must be configured in 'tuf.conf'.
    tuf.conf.repository_directory = repo_dir


    # Test: empty repository. 
    self.assertRaises(tuf.RepositoryError, updater.Updater, 'Repo_Name',
                      self.mirrors) 

    # Test: empty repository with {repository_dir}/metadata directory.
    meta_dir = os.path.join(repo_dir, 'metadata')
    os.mkdir(meta_dir)
    self.assertRaises(tuf.RepositoryError, updater.Updater, 'Repo_Name',
                      self.mirrors) 

    # Test: empty repository with {repository_dir}/metadata/current directory.
    current_dir = os.path.join(meta_dir, 'current')
    os.mkdir(current_dir)
    self.assertRaises(tuf.RepositoryError, updater.Updater, 'Repo_Name',
                      self.mirrors)

    # Test: normal case.
    repositories = setup.create_repositories()
    client_repo_dir = repositories['client_repository']
    tuf.conf.repository_directory = client_repo_dir
    updater.Updater('Repo_Name', self.mirrors)
    
    # Test: case w/ only root metadata file present in the current dir.
    client_current_dir = os.path.join(client_repo_dir, 'metadata', 'current')
    for directory, junk, role_list in os.walk(client_current_dir):
      for role_filepath in role_list:
        role_filepath = os.path.join(directory, role_filepath)
        if role_filepath.endswith('root.txt'):
          continue
        os.remove(role_filepath)
    updater.Updater('Repo_Name', self.mirrors)

    #  Remove all created repositories and roles.
    setup.remove_all_repositories(repositories['main_repository'])
    tuf.roledb.clear_roledb()




class TestUpdater(unittest_toolbox.Modified_TestCase):

  @classmethod
  def setUpClass(cls):
    # setUpClass() is called before tests in an individual class run.
    # Create repositories.  'repositories' is a tuple that looks like this:
    # (repository_dir, client_repository_dir, server_repository_dir), see 
    # 'repository_setup.py' module.
    cls.repositories = setup.create_repositories()

    # Save references to repository directories and metadata.
    #  Server side references.
    cls.server_repo_dir = cls.repositories['server_repository']
    cls.server_meta_dir = os.path.join(cls.server_repo_dir, 'metadata')
    cls.root_filepath = os.path.join(cls.server_meta_dir, 'root.txt')
    cls.timestamp_filepath = os.path.join(cls.server_meta_dir, 'timestamp.txt')
    cls.targets_filepath = os.path.join(cls.server_meta_dir, 'targets.txt')
    cls.release_filepath = os.path.join(cls.server_meta_dir, 'release.txt')

    #  References to delegated metadata paths and directories.
    cls.delegated_dir1 = os.path.join(cls.server_meta_dir, 'targets')
    cls.delegated_filepath1 = os.path.join(cls.delegated_dir1,
                                           'delegated_role1.txt')
    cls.delegated_dir2 = os.path.join(cls.delegated_dir1, 'delegated_role1')
    cls.delegated_filepath2 = os.path.join(cls.delegated_dir2,
                                           'delegated_role2.txt')
    cls.targets_dir = os.path.join(cls.server_repo_dir, 'targets')  

    #  Client side references.
    cls.client_repo_dir = cls.repositories['client_repository']
    cls.client_meta_dir = os.path.join(cls.client_repo_dir, 'metadata')
    cls.client_current_dir = os.path.join(cls.client_meta_dir, 'current')
    cls.client_previous_dir = os.path.join(cls.client_meta_dir, 'previous')





  def setUp(self):
    #  We are inheriting from custom class.
    unittest_toolbox.Modified_TestCase.setUp(self)

    #  Patching 'tuf.conf.repository_directory' with the one we set up.
    tuf.conf.repository_directory = self.client_repo_dir

    #  Creating Repository instance.
    self.Repository = updater.Updater('Client_Repository', self.mirrors)

    #  List of all role paths, (in order they are updated).  This list will be
    #  used as an optional argument to 'download_url_to_tempfileobj' patch 
    #  function.
    self.all_role_paths = [self.timestamp_filepath,
                           self.release_filepath,
                           self.root_filepath,
                           self.targets_filepath,
                           self.delegated_filepath1,
                           self.delegated_filepath2]

    #  Making sure that server and client's metadata files are the same.
    shutil.rmtree(self.client_current_dir)
    shutil.copytree(self.server_meta_dir, self.client_current_dir)





  def tearDown(self):
    #  We are inheriting from custom class.
    unittest_toolbox.Modified_TestCase.tearDown(self)

    #  Clear roledb and keydb dictionaries.
    tuf.roledb.clear_roledb()
    tuf.keydb.clear_keydb()





  # HELPER FUNCTIONS (start with '_').

  def _mock_download_url_to_tempfileobj(self, output):
    """
    <Purpose>
      Patch 'tuf.download.download_url_to_fileobject' method.
      
    <Arguments>
      output:
        Can be a file path or a list of file paths.  If 'output' is a file
        path then a tuf.util.TempFile file-object of that path is returned on
        the call.  Else if, 'output' is a list of file paths then first
        element of the that list is popped and it's tuf.util.TempFile fileobject
        of is returned every time the patch is called.

    """

    def _mock_download(url, length):
      if isinstance(output, (str, unicode)):
        file_path = output
      elif isinstance(output, list):
        file_path = output.pop(0)
      file_obj = open(file_path, 'rb')
      temp_fileobj = tuf.util.TempFile()
      temp_fileobj.write(file_obj.read())
      return temp_fileobj

    # Patch tuf.download functions.
    tuf.download.unsafe_download = _mock_download
    tuf.download.safe_download = _mock_download



  def _add_file_to_directory(self, directory):
    file_path = tempfile.mkstemp(suffix='.txt', dir=directory)
    fileobj = open(file_path[1], 'wb')
    fileobj.write(self.random_string())
    fileobj.close()
    return file_path[1]



  def _remove_filepath(self, filepath):
    os.remove(filepath)



  def _add_target_to_targets_dir(self, targets_keyids):
    """
    Adds a file to server's 'targets' directory and rebuilds
    targets metadata (targets.txt).
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
    rebuild 'targets', 'release', 'timestamp' metadata files.
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



  def _compress_file(self, file_path):
    fileobj = open(file_path, 'rb')
    file_path_compressed = file_path+'.gz'
    fileobj_compressed = gzip.open(file_path+'.gz', 'wb')
    fileobj_compressed.writelines(fileobj)
    fileobj_compressed.close()
    fileobj.close()
    return file_path_compressed



  def _get_list_of_target_paths(self, targets_directory, relative=True):
    # This helper function returns a list of all target filepaths
    # located in the server's targets directory (where all target files are
    # located).  If 'relative' is true, relative paths to 'targets_directory'
    # are returned.

    target_filepaths = []
    if relative:
      for directory, sub_directories, files in os.walk(targets_directory):
        for _file in files:
          file_path = os.path.join(directory, _file)
          rel_file_path = os.path.relpath(file_path, targets_directory)
          target_filepaths.append(rel_file_path) 

    else:
      for directory, sub_directories, files in os.walk(targets_directory):
        for _file in files:
          file_path = os.path.join(directory, _file)
          target_filepaths.append(file_path)

    return target_filepaths



  def _update_top_level_roles(self):
    self._mock_download_url_to_tempfileobj(self.timestamp_filepath)
    self.Repository._update_metadata('timestamp', DEFAULT_TIMESTAMP_FILEINFO)

    # Reference self.Repository._update_metadata_if_changed().
    update_if_changed = self.Repository._update_metadata_if_changed    

    self._mock_download_url_to_tempfileobj(self.release_filepath)
    update_if_changed('release', referenced_metadata = 'timestamp')

    self._mock_download_url_to_tempfileobj(self.root_filepath)
    update_if_changed('root')

    self._mock_download_url_to_tempfileobj(self.targets_filepath)
    update_if_changed('targets')





  # UNIT TESTS.

  def test_1__load_metadata_from_file(self):
    
    # Setup
    #  Get root.txt file path.  Extract root metadata, 
    #  it will be compared with content of loaded root metadata.
    root_filepath = os.path.join(self.client_current_dir, 'root.txt')
    root_meta = tuf.util.load_json_file(root_filepath)


    # Test: normal case.
    for role in self.role_list:
      self.Repository._load_metadata_from_file('current', role)

    #  Verify that the correct number of metadata objects has been loaded. 
    self.assertEqual(len(self.Repository.metadata['current']), 4)

    #  Verify that the content of root metadata is valid.
    self.assertEqual(self.Repository.metadata['current']['root'],
                     root_meta['signed'])





  def test_1__rebuild_key_and_role_db(self):    
    # Setup
    root_meta = self.Repository.metadata['current']['root']

    # Test: normal case.
    self.Repository._rebuild_key_and_role_db()
    
    #  Verify tuf.roledb._roledb_dict and tuf.keydb._keydb_dict dictionaries
    #  are populated.  'top_level_role_info' is a unittest_toolbox's dict
    #  that contains top level role information it corresponds to a
    #  ROLEDICT_SCHEMA where roles are keys and role information their values.
    self.assertEqual(tuf.roledb._roledb_dict, self.top_level_role_info)
    self.assertEqual(len(tuf.keydb._keydb_dict), 4)

    #  Verify that keydb dictionary was updated.
    for role in self.role_list:
      keyids = self.top_level_role_info[role]['keyids']
      for keyid in keyids:
        self.assertTrue(keyid in tuf.keydb._keydb_dict)



  def test_1__update_fileinfo(self):
    # Tests
    #  Verify that fileinfo dictionary is empty.
    self.assertFalse(self.Repository.fileinfo)

    #  Load file info for top level roles.  This populates the fileinfo 
    #  dictionary.
    for role in self.role_list:
      self.Repository._update_fileinfo(role+'.txt')

    #  Verify that fileinfo has been populated and contains appropriate data.
    self.assertTrue(self.Repository.fileinfo)
    for role in self.role_list:
      role_filepath = os.path.join(self.client_current_dir, role+'.txt')
      role_info = tuf.util.get_file_details(role_filepath)
      role_info_dict = {'length':role_info[0], 'hashes':role_info[1]}
      self.assertTrue(role+'.txt' in self.Repository.fileinfo.keys())
      self.assertEqual(self.Repository.fileinfo[role+'.txt'], role_info_dict)





  def test_2__import_delegations(self):
    # In order to test '_import_delegations' the parent of the delegation
    # has to be in Repository.metadata['current'], but it has to be inserted
    # there without using '_load_metadata_from_file' function since it calls
    # '_import_delegations'.
    # Setup.
    deleg_role1_signable = tuf.util.load_json_file(self.delegated_filepath1)
    self.Repository.metadata['current']['targets/delegated_role1'] = \
        deleg_role1_signable['signed']

 
    # Test: pass a role without delegations.
    self.Repository._import_delegations('root')

    #  Verify that there was no change in roledb and keydb dictionaries
    #  by checking the number of elements in the dictionaries.
    self.assertEqual(len(tuf.roledb._roledb_dict), 5)       
    self.assertEqual(len(tuf.keydb._keydb_dict), 5)

    # Test: normal case, first level delegation.
    self.Repository._import_delegations('targets/delegated_role1')

    self.assertEqual(len(tuf.roledb._roledb_dict), 6)
    self.assertEqual(len(tuf.keydb._keydb_dict), 6)

    #  Verify that roledb dictionary was updated.
    self.assertTrue('targets/delegated_role1' in tuf.roledb._roledb_dict)
    
    #  Verify that keydb dictionary was updated.
    keyids = self.semi_roledict['targets/delegated_role1']['keyids']
    for keyid in keyids:
      self.assertTrue(keyid in tuf.keydb._keydb_dict)





  def test_2__ensure_all_targets_allowed(self):
    # Setup
    #  Reference to self.Repository._ensure_all_targets_allowed()    
    ensure_all_targets_allowed = self.Repository._ensure_all_targets_allowed

    #  Extract delegated role metadata, it will be used as an argument
    #  to updater._ensure_all_targets_allowed() method.
    #  'role1' is delegated by 'targets' role.
    targets_meta_dir = os.path.join(self.server_meta_dir, 'targets')
    role1_meta_dir = os.path.join(targets_meta_dir, 'delegated_role1')
    
    role1_path = os.path.join(targets_meta_dir, 'delegated_role1.txt')
    role1_metadata_signable = tuf.util.load_json_file(role1_path)
    role1_metadata = role1_metadata_signable['signed']
    

    # Test: normal case.
    ensure_all_targets_allowed('targets/delegated_role1', role1_metadata)

    # Test: invalid role.  tuf.UnknownRoleError is raised since 
    # 'delegated_role1' is not in the Repository's 'metadata' dictionary.
    self.assertRaises(tuf.UnknownRoleError, ensure_all_targets_allowed,
                      'targets/delegated_role1/delegated_role2',
                      role1_metadata)

    #  To verify that an exception is raised when targets listed in the 
    #  delegated role's metadata are not indicated in the metadata of the
    #  delegated role's parent, we need to modify delegated role's 'targets'
    #  field.
    target = self.random_string()+'.txt'
    deleg_target_path = os.path.join('delegated_level', target)
    role1_metadata['targets'][deleg_target_path] = self.random_string()

    # Test: targets not included in the parent's metadata.
    self.assertRaises(tuf.RepositoryError, ensure_all_targets_allowed,
                      'targets/delegated_role1',
                      role1_metadata)





  def test_2__fileinfo_has_changed(self):
    #  Verify that the method returns 'False' if file info was not changed.
    for role in self.role_list:
      role_filepath = os.path.join(self.client_current_dir, role+'.txt')
      role_info = tuf.util.get_file_details(role_filepath)
      role_info_dict = {'length':role_info[0], 'hashes':role_info[1]}
      self.assertFalse(self.Repository._fileinfo_has_changed(role+'.txt',
                                                             role_info_dict))

    # Verify that the method returns 'True' if length or hashes were changed.
    for role in self.role_list:
      role_filepath = os.path.join(self.client_current_dir, role+'.txt')
      role_info = tuf.util.get_file_details(role_filepath)
      role_info_dict = {'length':8, 'hashes':role_info[1]}
      self.assertTrue(self.Repository._fileinfo_has_changed(role+'.txt',
                                                             role_info_dict))

    for role in self.role_list:
      role_filepath = os.path.join(self.client_current_dir, role+'.txt')
      role_info = tuf.util.get_file_details(role_filepath)
      role_info_dict = {'length':role_info[0],
                        'hashes':{'sha256':self.random_string()}}
      self.assertTrue(self.Repository._fileinfo_has_changed(role+'.txt',
                                                             role_info_dict))




  def test_2__move_current_to_previous(self):
    # The test will consist of removing a metadata file from client's
    # {client_repository}/metadata/previous directory, executing the method
    # and then verifying that the 'previous' directory contains
    # the release file.
    release_meta_path = os.path.join(self.client_previous_dir, 'release.txt')
    os.remove(release_meta_path)
    self.assertFalse(os.path.exists(release_meta_path))
    self.Repository._move_current_to_previous('release')
    self.assertTrue(os.path.exists(release_meta_path))
    shutil.copy(release_meta_path, self.client_current_dir)





  def test_2__delete_metadata(self):
    # This test will verify that 'root' metadata is never deleted, when
    # role is deleted verify that the file is not present in the 
    # self.Repository.metadata dictionary.
    self.Repository._delete_metadata('root')
    self.assertTrue('root' in self.Repository.metadata['current'])
    self.Repository._delete_metadata('timestamp')
    self.assertFalse('timestamp' in self.Repository.metadata['current'])
    timestamp_meta_path = os.path.join(self.client_previous_dir,
                                       'timestamp.txt')
    shutil.copy(timestamp_meta_path, self.client_current_dir)





  def test_2__ensure_not_expired(self):
    # This test condition will verify that nothing is raised when a metadata
    # file has a future expiration date.
    self.Repository._ensure_not_expired('root')
    
    # 'tuf.ExpiredMetadataError' should be raised in this next test condition,
    # because the expiration_date has expired by 10 seconds.
    expires = tuf.formats.format_time(time.time() - 10)
    self.Repository.metadata['current']['root']['expires'] = expires
    
    # Ensure the 'expires' field of the root file is properly formatted.
    self.assertTrue(tuf.formats.ROOT_SCHEMA.matches(self.Repository.metadata\
                                                    ['current']['root']))
    self.assertRaises(tuf.ExpiredMetadataError,
                      self.Repository._ensure_not_expired, 'root')





  def test_3__update_metadata(self):
    """
    This unit test verifies the method's proper behaviour on the expected input.
    """
    
    #  Since client's '.../metadata/current' will need to have separate
    #  gzipped metadata file in order to test compressed file handling,
    #  we need to copy it there.  
    targets_filepath_compressed = self._compress_file(self.targets_filepath)
    shutil.copy(targets_filepath_compressed, self.client_current_dir) 

    #  To test updater._update_metadata(), 'targets' metadata file is
    #  going to be modified at the server's repository.
    #  Keyid's are required to build the metadata.
    targets_keyids = setup.role_keyids['targets']

    #  Add a file to targets directory and rebuild targets metadata.
    #  Returned target's filename will be used to verify targets metadata.
    added_target_1 = self._add_target_to_targets_dir(targets_keyids)

    #  Reference 'self.Repository._update_metadata'.
    _update_metadata = self.Repository._update_metadata


    # Test: Invalid file downloaded.
    #  Patch 'download.download_url_to_tempfileobj' function.
    self._mock_download_url_to_tempfileobj(self.release_filepath)

    # TODO: Is this the original intent of this test?
    self.assertRaises(TypeError, _update_metadata, 'targets', None)


    # Test: normal case.
    #  Patch 'download.download_url_to_tempfileobj' function.
    self._mock_download_url_to_tempfileobj(self.targets_filepath)
    uncompressed_fileinfo = \
      signerlib.get_metadata_file_info(self.targets_filepath)
    _update_metadata('targets', uncompressed_fileinfo)
    list_of_targets = self.Repository.metadata['current']['targets']['targets']

    #  Verify that the added target's path is listed in target's metadata.
    if added_target_1 not in list_of_targets.keys():
      self.fail('\nFailed to update targets metadata.')

  
    # Test: normal case, compressed metadata file.
    #  Add a file to targets directory and rebuild targets metadata. 
    added_target_2 = self._add_target_to_targets_dir(targets_keyids)
    uncompressed_fileinfo = \
      signerlib.get_metadata_file_info(self.targets_filepath)

    #  To test compressed file handling, compress targets metadata file.
    targets_filepath_compressed = self._compress_file(self.targets_filepath)
    compressed_fileinfo = \
      signerlib.get_metadata_file_info(targets_filepath_compressed)

    #  Re-patch 'download.download_url_to_tempfileobj' function.
    self._mock_download_url_to_tempfileobj(targets_filepath_compressed)
    # The length (but not the hash) passed to this function is incorrect. The
    # length must be that of the compressed file, whereas the hash must be that
    # of the uncompressed file.
    mixed_fileinfo = {
      'length': compressed_fileinfo['length'],
      'hashes': uncompressed_fileinfo['hashes']
    }
    _update_metadata('targets', mixed_fileinfo, compression='gzip')
    list_of_targets = self.Repository.metadata['current']['targets']['targets']

    #  Verify that the added target's path is listed in target's metadata.
    if added_target_2 not in list_of_targets.keys():
      self.fail('\nFailed to update targets metadata.')


    # Restoring server's repository to the initial state.
    os.remove(targets_filepath_compressed)
    os.remove(os.path.join(self.client_current_dir,'targets.txt'))
    self._remove_target_from_targets_dir(added_target_1)





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


    # Test: normal case.  Update 'release' metadata.
    #  Patch download_file.
    self._mock_download_url_to_tempfileobj(self.timestamp_filepath)

    #  Update timestamp metadata, it will indicate change in release metadata.
    self.Repository._update_metadata('timestamp', DEFAULT_TIMESTAMP_FILEINFO)

    #  Save current release metadata before updating.  It will be used to
    #  verify the update.
    old_release_meta = self.Repository.metadata['current']['release']
    self._mock_download_url_to_tempfileobj(self.release_filepath)

    #  Update release metadata, it will indicate change in targets metadata.
    update_if_changed(metadata_role='release', referenced_metadata='timestamp')
    current_release_meta = self.Repository.metadata['current']['release']
    previous_release_meta = self.Repository.metadata['previous']['release']
    self.assertEqual(old_release_meta, previous_release_meta)
    self.assertNotEqual(old_release_meta, current_release_meta)


    # Test: normal case.  Update 'targets' metadata. 
    #  Patch 'download.download_url_to_tempfileobj' and update targets.
    self._mock_download_url_to_tempfileobj(self.targets_filepath)
    update_if_changed('targets')
    list_of_targets = self.Repository.metadata['current']['targets']['targets']

    #  Verify that the added target's path is listed in target's metadata.
    if added_target_1 not in list_of_targets.keys():
      self.fail('\nFailed to update targets metadata.')


    # Test: normal case.  Update compressed release file.
    release_filepath_compressed = self._compress_file(self.release_filepath)

    #  Since client's '.../metadata/current' will need to have separate
    #  gzipped metadata file in order to test compressed file handling,
    #  we need to copy it there.  
    shutil.copy(release_filepath_compressed, self.client_current_dir) 
  
    #  Add a target file and rebuild metadata files at the server side.
    added_target_2 = self._add_target_to_targets_dir(targets_keyids)
    
    #  Since release file was updated, update compressed release file.
    release_filepath_compressed = self._compress_file(self.release_filepath)
 
    #  Patch download_file.
    self._mock_download_url_to_tempfileobj(self.timestamp_filepath)

    #  Update timestamp metadata, it will indicate change in release metadata.
    self.Repository._update_metadata('timestamp', DEFAULT_TIMESTAMP_FILEINFO)

    #  Save current release metadata before updating.  It will be used to
    #  verify the update.
    old_release_meta = self.Repository.metadata['current']['release']
    self._mock_download_url_to_tempfileobj(self.release_filepath)

    #  Update release metadata, and verify the change.
    update_if_changed(metadata_role='release', referenced_metadata='timestamp')
    current_release_meta = self.Repository.metadata['current']['release']
    previous_release_meta = self.Repository.metadata['previous']['release']
    self.assertEqual(old_release_meta, previous_release_meta)
    self.assertNotEqual(old_release_meta, current_release_meta)
  

    # Test: Invalid targets metadata file downloaded.
    #  Patch 'download.download_url_to_tempfileobj' and update targets.
    self._mock_download_url_to_tempfileobj(self.root_filepath)

    # FIXME: What is the original intent of this test?
    try:
      update_if_changed('targets')
    except tuf.NoWorkingMirrorError, exception:
      for mirror_url, mirror_error in exception.mirror_errors.iteritems():
        assert isinstance(mirror_error, tuf.DownloadLengthMismatchError)

    # Restoring repositories to the initial state.
    os.remove(release_filepath_compressed)
    os.remove(os.path.join(self.client_current_dir, 'release.txt.gz'))
    self._remove_target_from_targets_dir(added_target_1)




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
      if dir_target.endswith('.txt'):
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
    role1_filepath = os.path.join(role1_dir, 'delegated_role1.txt')
    role2_dir = os.path.join(role1_dir, 'delegated_role1')
    role2_filepath = os.path.join(role2_dir, 'delegated_role2.txt')

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
   # roles each list 1 of the already listed targets in 'targets.txt', for a
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
      if dir_target.endswith('.txt'):
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
      if _target.endswith('.txt'):
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


def tearDownModule():
  # tearDownModule() is called after all the tests have run.
  # http://docs.python.org/2/library/unittest.html#class-and-module-fixtures
  setup.remove_all_repositories(TestUpdater.repositories['main_repository'])
  unittest_toolbox.Modified_TestCase.clear_toolbox()
  tuf.download.safe_download = original_safe_download
  tuf.download.unsafe_download = original_unsafe_download

if __name__ == '__main__':
  unittest.main()
