"""
<Program Name>
  test_repository_tool.py

<Author> 
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  April 7, 2014. 

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Unit test for 'repository_tool.py'.
"""

import unittest
import logging

import tuf
import tuf.log
import tuf.formats
import tuf.roledb
import tuf.keydb
import tuf.repository_tool as repo_tool

logger = logging.getLogger('tuf.test_repository_tool')



class TestRepository(unittest.TestCase):
  def setUp(self):
    pass



  def tearDown(self):
    tuf.roledb.clear_roledb() 
    tuf.keydb.clear_keydb()


  def test_init(self):
    
    # Test normal case.
    repository = repo_tool.Repository('repository_directory/',
                                      'metadata_directory/',
                                      'targets_directory/')
    self.assertTrue(isinstance(repository.root, repo_tool.Root))
    self.assertTrue(isinstance(repository.snapshot, repo_tool.Snapshot))
    self.assertTrue(isinstance(repository.timestamp, repo_tool.Timestamp))
    self.assertTrue(isinstance(repository.targets, repo_tool.Targets))

    # Test improperly formatted arguments.
    self.assertRaises(tuf.FormatError, repo_tool.Repository, 3,
                      'metadata_directory/', 'targets_directory')
    self.assertRaises(tuf.FormatError, repo_tool.Repository,
                      'repository_directory', 3, 'targets_directory')
    self.assertRaises(tuf.FormatError, repo_tool.Repository,
                      'repository_directory', 'metadata_directory', 3)



class TestMetadata(unittest.TestCase):
  def setUp(self):
    pass



  def tearDown(self):
    pass





class TestRoot(unittest.TestCase):
  def setUp(self):
    pass



  def tearDown(self):
    tuf.roledb.clear_roledb() 
    tuf.keydb.clear_keydb()


  
  def test_init(self):
    
    # Test normal case.
    # Root() subclasses Metadata(), and creates a 'root' role in 'tuf.roledb'.
    root_object = repo_tool.Root()
    self.assertTrue(isinstance(root_object, repo_tool.Metadata))
    self.assertTrue(tuf.roledb.role_exists('root'))



class TestTimestamp(unittest.TestCase):
  def setUp(self):
    pass



  def tearDown(self):
    tuf.roledb.clear_roledb() 
    tuf.keydb.clear_keydb()
  
  
  
  def test_init(self):
    
    # Test normal case.
    # Timestamp() subclasses Metadata(), and creates a 'timestamp' role in
    # 'tuf.roledb'.
    timestamp_object = repo_tool.Timestamp()
    self.assertTrue(isinstance(timestamp_object, repo_tool.Metadata))
    self.assertTrue(tuf.roledb.role_exists('timestamp'))





class TestSnapshot(unittest.TestCase):
  def setUp(self):
    pass



  def tearDown(self):
    tuf.roledb.clear_roledb() 
    tuf.keydb.clear_keydb()
  
  
  
  def test_init(self):
    
    # Test normal case.
    # Snapshot() subclasses Metadata(), and creates a 'snapshot' role in
    # 'tuf.roledb'.
    snapshot_object = repo_tool.Snapshot()
    self.assertTrue(isinstance(snapshot_object, repo_tool.Metadata))
    self.assertTrue(tuf.roledb.role_exists('snapshot'))





class TestTargets(unittest.TestCase):
  def setUp(self):
    pass



  def tearDown(self):
    tuf.roledb.clear_roledb() 
    tuf.keydb.clear_keydb()
  
  
  
  def test_init(self):
    
    # Test normal case.
    # Snapshot() subclasses Metadata(), and creates a 'snapshot' role in
    # 'tuf.roledb'.
    targets_object = repo_tool.Targets('targets_directory/')
    self.assertTrue(isinstance(targets_object, repo_tool.Metadata))
    self.assertTrue(tuf.roledb.role_exists('targets'))

    # Custom Targets object rolename.
    targets_object = repo_tool.Targets('targets_directory/', 'project') 
    self.assertTrue(isinstance(targets_object, repo_tool.Metadata))
    self.assertTrue(tuf.roledb.role_exists('project'))

    # Custom roleinfo object (i.e., tuf.formats.ROLEDB_SCHEMA).  'keyids' and
    # 'threshold' are required, the rest are optional.
    roleinfo = {'keyids': 
          ['66c4cb5fef5e4d62b7013ef1cab4b8a827a36c14056d5603c3a970e21eb30e6f'],
                'threshold': 8}
    self.assertTrue(tuf.formats.ROLEDB_SCHEMA.matches(roleinfo))
    
    targets_object = repo_tool.Targets('targets_directory/', 'package', roleinfo)
    self.assertTrue(isinstance(targets_object, repo_tool.Metadata))
    self.assertTrue(tuf.roledb.role_exists('package'))


    # Test improperly formatted arguments.
    self.assertRaises(tuf.FormatError, repo_tool.Targets, 3)
    self.assertRaises(tuf.FormatError, repo_tool.Targets, 'targets_directory/', 3)
    self.assertRaises(tuf.FormatError, repo_tool.Targets, 'targets_directory/',
                      'targets', 3)



class TestRepositoryToolFunctions(unittest.TestCase):
  def setUp(self):
    pass


  def tearDown(self):
    pass



  def test_create_new_repository(self):
    pass



  def test_load_repository(self):
    pass



  def test_generate_and_write_rsa_keypair(self):
    pass



  def test_import_rsa_privatekey_from_file(self):
    pass



  def test_import_rsa_publickey_from_file(self):
    pass



  def test_generate_and_write_ed25519_keypair(self):
    pass



  def test_import_ed25519_publickey_from_file(self):
    pass



  def test_import_ed25519_privatekey_from_file(self):
    pass



  def test_get_metadata_filenames(self):
    pass



  def test_get_metadata_file_info(self):
    pass



  def test_get_target_hash(self):
    # Test normal case. 
    expected_target_hashes = {
      '/file1.txt': 'e3a3d89eb3b70ce3fbce6017d7b8c12d4abd5635427a0e8a238f53157df85b3d',
      '/README.txt': '8faee106f1bb69f34aaf1df1e3c2e87d763c4d878cb96b91db13495e32ceb0b0',
      '/packages/file2.txt': 'c9c4a5cdd84858dd6a23d98d7e6e6b2aec45034946c16b2200bc317c75415e92'  
    }
    for filepath, target_hash in expected_target_hashes.items():
      self.assertTrue(tuf.formats.RELPATH_SCHEMA.matches(filepath))
      self.assertTrue(tuf.formats.HASH_SCHEMA.matches(target_hash))
      self.assertEqual(repo_tool.get_target_hash(filepath), target_hash)
   
    # Test for improperly formatted argument.
    self.assertRaises(tuf.FormatError, repo_tool.get_target_hash, 8)



  def test_generate_root_metadata(self):
    pass



  def test_generate_targets_metadata(self):
    pass



  def test_generate_snapshot_metadata(self):
    pass



  def test_generate_timestamp_metadata(self):
    pass



  def test_sign_metadata(self):
    pass



  def test_write_metadata_file(self):
    pass



  def test_create_tuf_client_directory(self):
    pass


# Run the test cases.
if __name__ == '__main__':
  unittest.main()
