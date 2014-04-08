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

import os
import unittest
import logging
import tempfile
import shutil

import tuf
import tuf.log
import tuf.formats
import tuf.roledb
import tuf.keydb
import tuf.hash
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
  @classmethod
  def setUpClass(cls):
    
    # setUpClass() is called before tests in an individual class are executed.
    
    # Create a temporary directory to store the repository, metadata, and target
    # files.  'temporary_directory' must be deleted in TearDownClass() so that
    # temporary files are always removed, even when exceptions occur. 
    cls.temporary_directory = tempfile.mkdtemp(dir=os.getcwd())
    


  @classmethod 
  def tearDownClass(cls):
    
    # tearDownModule() is called after all the tests have run.
    # http://docs.python.org/2/library/unittest.html#class-and-module-fixtures
   
    # Remove the temporary repository directory, which should contain all the
    # metadata, targets, and key files generated for the test cases.
    shutil.rmtree(cls.temporary_directory)



  def setUp(self):
    pass


  def tearDown(self):
    pass



  def test_create_new_repository(self):
    pass



  def test_load_repository(self):
    pass



  def test_generate_and_write_rsa_keypair(self):
  
    # Test normal case.
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory) 
    test_keypath = os.path.join(temporary_directory, 'rsa_key')

    repo_tool.generate_and_write_rsa_keypair(test_keypath, password='pw')
    self.assertTrue(os.path.exists(test_keypath))
    self.assertTrue(os.path.exists(test_keypath + '.pub'))
    
    # Ensure the generated key files are importable.
    imported_pubkey = \
      repo_tool.import_rsa_publickey_from_file(test_keypath + '.pub')
    self.assertTrue(tuf.formats.RSAKEY_SCHEMA.matches(imported_pubkey))
    
    imported_privkey = \
      repo_tool.import_rsa_privatekey_from_file(test_keypath, 'pw')
    self.assertTrue(tuf.formats.RSAKEY_SCHEMA.matches(imported_privkey))

    # Custom 'bits' argument.
    os.remove(test_keypath)
    os.remove(test_keypath + '.pub')
    repo_tool.generate_and_write_rsa_keypair(test_keypath, bits=2048,
                                             password='pw')
    self.assertTrue(os.path.exists(test_keypath))
    self.assertTrue(os.path.exists(test_keypath + '.pub'))


    # Test improperly formatted arguments.
    self.assertRaises(tuf.FormatError, repo_tool.generate_and_write_rsa_keypair,
                      3, bits=2048, password='pw')
    self.assertRaises(tuf.FormatError, repo_tool.generate_and_write_rsa_keypair,
                      test_keypath, bits='bad', password='pw')
    self.assertRaises(tuf.FormatError, repo_tool.generate_and_write_rsa_keypair,
                      test_keypath, bits=2048, password=3)


    # Test invalid 'bits' argument.
    self.assertRaises(tuf.FormatError, repo_tool.generate_and_write_rsa_keypair,
                      test_keypath, bits=1024, password='pw')



  def test_import_rsa_privatekey_from_file(self):
    # Test normal case.
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)
    
    # Load one of the pre-generated key files from 'tuf/tests/repository_data'.
    # 'password' unlocks the pre-generated key files.
    key_filepath = os.path.join(os.pardir, 'repository_data', 'keystore',
                                'root_key')
    self.assertTrue(os.path.exists(key_filepath))
    
    imported_rsa_key = repo_tool.import_rsa_privatekey_from_file(key_filepath,
                                                                 'password')
    self.assertTrue(tuf.formats.RSAKEY_SCHEMA.matches(imported_rsa_key))

    
    # Test improperly formatted argument.
    self.assertRaises(tuf.FormatError,
                      repo_tool.import_rsa_privatekey_from_file, 3, 'pw')


    # Test invalid argument.
    # Non-existent key file.
    nonexistent_keypath = os.path.join(temporary_directory,
                                       'nonexistent_keypath') 
    self.assertRaises(IOError, repo_tool.import_rsa_privatekey_from_file,
                      nonexistent_keypath, 'pw')
    
    # Invalid key file argument. 
    invalid_keyfile = os.path.join(temporary_directory, 'invalid_keyfile') 
    with open(invalid_keyfile, 'wb') as file_object:
      file_object.write('bad keyfile')
    self.assertRaises(tuf.CryptoError, repo_tool.import_rsa_privatekey_from_file,
                      invalid_keyfile, 'pw')



  def test_import_rsa_publickey_from_file(self):
    # Test normal case.
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)
    
    # Load one of the pre-generated key files from 'tuf/tests/repository_data'.
    key_filepath = os.path.join(os.pardir, 'repository_data', 'keystore',
                                'root_key.pub')
    self.assertTrue(os.path.exists(key_filepath))
    
    imported_rsa_key = repo_tool.import_rsa_publickey_from_file(key_filepath)
    self.assertTrue(tuf.formats.RSAKEY_SCHEMA.matches(imported_rsa_key))

    
    # Test improperly formatted argument.
    self.assertRaises(tuf.FormatError,
                      repo_tool.import_rsa_privatekey_from_file, 3)


    # Test invalid argument.
    # Non-existent key file.
    nonexistent_keypath = os.path.join(temporary_directory,
                                       'nonexistent_keypath')
    self.assertRaises(IOError, repo_tool.import_rsa_publickey_from_file,
                      nonexistent_keypath)
    
    # Invalid key file argument. 
    invalid_keyfile = os.path.join(temporary_directory, 'invalid_keyfile') 
    with open(invalid_keyfile, 'wb') as file_object:
      file_object.write('bad keyfile')
    self.assertRaises(tuf.Error, repo_tool.import_rsa_publickey_from_file,
                      invalid_keyfile)



  def test_generate_and_write_ed25519_keypair(self):
    
    # Test normal case.
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory) 
    test_keypath = os.path.join(temporary_directory, 'ed25519_key')

    repo_tool.generate_and_write_ed25519_keypair(test_keypath, password='pw')
    self.assertTrue(os.path.exists(test_keypath))
    self.assertTrue(os.path.exists(test_keypath + '.pub'))

    # Ensure the generated key files are importable.
    imported_pubkey = \
      repo_tool.import_ed25519_publickey_from_file(test_keypath + '.pub')
    self.assertTrue(tuf.formats.ED25519KEY_SCHEMA.matches(imported_pubkey))
    
    imported_privkey = \
      repo_tool.import_ed25519_privatekey_from_file(test_keypath, 'pw')
    self.assertTrue(tuf.formats.ED25519KEY_SCHEMA.matches(imported_privkey))


    # Test improperly formatted arguments.
    self.assertRaises(tuf.FormatError,
                      repo_tool.generate_and_write_ed25519_keypair,
                      3, password='pw')
    self.assertRaises(tuf.FormatError, repo_tool.generate_and_write_rsa_keypair,
                      test_keypath, password=3)



  def test_import_ed25519_publickey_from_file(self):
    # Test normal case.
    # Generate ed25519 keys that can be imported.
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)
    ed25519_keypath = os.path.join(temporary_directory, 'ed25519_key') 
    repo_tool.generate_and_write_ed25519_keypair(ed25519_keypath, password='pw')
     
    imported_ed25519_key = \
      repo_tool.import_ed25519_publickey_from_file(ed25519_keypath + '.pub')
    self.assertTrue(tuf.formats.ED25519KEY_SCHEMA.matches(imported_ed25519_key))
    
    
    # Test improperly formatted argument.
    self.assertRaises(tuf.FormatError,
                      repo_tool.import_ed25519_publickey_from_file, 3)


    # Test invalid argument.
    # Non-existent key file.
    nonexistent_keypath = os.path.join(temporary_directory,
                                       'nonexistent_keypath')
    self.assertRaises(IOError, repo_tool.import_ed25519_publickey_from_file,
                      nonexistent_keypath)
    
    # Invalid key file argument. 
    invalid_keyfile = os.path.join(temporary_directory, 'invalid_keyfile') 
    with open(invalid_keyfile, 'wb') as file_object:
      file_object.write('bad keyfile')
    
    self.assertRaises(tuf.Error, repo_tool.import_ed25519_publickey_from_file,
                      invalid_keyfile)



  def test_import_ed25519_privatekey_from_file(self):
    # Test normal case.
    # Generate ed25519 keys that can be imported.
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)
    ed25519_keypath = os.path.join(temporary_directory, 'ed25519_key') 
    repo_tool.generate_and_write_ed25519_keypair(ed25519_keypath, password='pw')
     
    imported_ed25519_key = \
      repo_tool.import_ed25519_privatekey_from_file(ed25519_keypath, 'pw')
    self.assertTrue(tuf.formats.ED25519KEY_SCHEMA.matches(imported_ed25519_key))
    
    
    # Test improperly formatted argument.
    self.assertRaises(tuf.FormatError,
                      repo_tool.import_ed25519_privatekey_from_file, 3, 'pw')


    # Test invalid argument.
    # Non-existent key file.
    nonexistent_keypath = os.path.join(temporary_directory,
                                       'nonexistent_keypath')
    self.assertRaises(IOError, repo_tool.import_ed25519_privatekey_from_file,
                      nonexistent_keypath, 'pw')
    
    # Invalid key file argument. 
    invalid_keyfile = os.path.join(temporary_directory, 'invalid_keyfile') 
    with open(invalid_keyfile, 'wb') as file_object:
      file_object.write('bad keyfile')
    
    self.assertRaises(tuf.Error, repo_tool.import_ed25519_privatekey_from_file,
                      invalid_keyfile, 'pw')



  def test_get_metadata_filenames(self):
   
    # Test normal case.
    metadata_directory = os.path.join('metadata/')
    filenames = {'root.json': metadata_directory + 'root.json',
                 'targets.json': metadata_directory + 'targets.json',
                 'snapshot.json': metadata_directory + 'snapshot.json',
                 'timestamp.json': metadata_directory + 'timestamp.json'}
    
    self.assertEqual(filenames, repo_tool.get_metadata_filenames('metadata/'))

    # If a directory argument is not specified, the current working directory
    # is used.
    metadata_directory = os.getcwd()
    filenames = {'root.json': os.path.join(metadata_directory, 'root.json'),
                 'targets.json': os.path.join(metadata_directory, 'targets.json'),
                 'snapshot.json': os.path.join(metadata_directory, 'snapshot.json'),
                 'timestamp.json': os.path.join(metadata_directory,  'timestamp.json')}
    self.assertEqual(filenames, repo_tool.get_metadata_filenames())


    # Test improperly formatted argument.
    self.assertRaises(tuf.FormatError, repo_tool.get_metadata_filenames, 3)



  def test_get_metadata_fileinfo(self):
    # Test normal case. 
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)
    test_filepath = os.path.join(temporary_directory, 'file.txt')
    
    with open(test_filepath, 'wb') as file_object:
      file_object.write('test file')
  
    # Generate test fileinfo object.  It is assumed SHA256 hashes are computed
    # by get_metadata_fileinfo().
    file_length = os.path.getsize(test_filepath)
    digest_object = tuf.hash.digest_filename(test_filepath)
    file_hashes = {'sha256': digest_object.hexdigest()}
    fileinfo = {'length': file_length, 'hashes': file_hashes}
    self.assertTrue(tuf.formats.FILEINFO_SCHEMA.matches(fileinfo))
    
    self.assertEqual(fileinfo, repo_tool.get_metadata_fileinfo(test_filepath))


    # Test improperly formatted argument.
    self.assertRaises(tuf.FormatError, repo_tool.get_metadata_fileinfo, 3)


    # Test non-existent file.
    nonexistent_filepath = os.path.join(temporary_directory, 'oops.txt')
    self.assertRaises(tuf.Error, repo_tool.get_metadata_fileinfo,
                      nonexistent_filepath)



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
