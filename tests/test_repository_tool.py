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
import time
import datetime
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

repo_tool.disable_console_log_messages()


class TestRepository(unittest.TestCase):
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

  

  def test_write_and_write_partial(self):
    # Test creation of a TUF repository.
    # 
    # 1. Load public and private keys.
    # 2. Add verification keys.
    # 3. Load signing keys.
    # 4. Add target files.
    # 5. Perform delegation.
    # 5. write()
    # 
    # Copy the target files from 'tuf/tests/repository_data' so that write()
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
    targets_pubkey = \
      repo_tool.import_rsa_publickey_from_file(targets_pubkey_path)
    snapshot_pubkey = \
      repo_tool.import_rsa_publickey_from_file(snapshot_pubkey_path)
    timestamp_pubkey = \
      repo_tool.import_rsa_publickey_from_file(timestamp_pubkey_path)
    role1_pubkey = repo_tool.import_rsa_publickey_from_file(role1_pubkey_path)
    
    # Load the private keys.
    root_privkey_path = os.path.join(keystore_directory, 'root_key')
    targets_privkey_path = os.path.join(keystore_directory, 'targets_key')
    snapshot_privkey_path = os.path.join(keystore_directory, 'snapshot_key')
    timestamp_privkey_path = os.path.join(keystore_directory, 'timestamp_key')
    role1_privkey_path = os.path.join(keystore_directory, 'delegation_key')
    
    root_privkey = \
      repo_tool.import_rsa_privatekey_from_file(root_privkey_path, 'password')
    targets_privkey = \
      repo_tool.import_rsa_privatekey_from_file(targets_privkey_path,
                                                'password')
    snapshot_privkey = \
      repo_tool.import_rsa_privatekey_from_file(snapshot_privkey_path,
                                                'password')
    timestamp_privkey = \
      repo_tool.import_rsa_privatekey_from_file(timestamp_privkey_path,
                                                'password')
    role1_privkey = \
      repo_tool.import_rsa_privatekey_from_file(role1_privkey_path,
                                                'password')


    # (2) Add top-level verification keys.
    repository.root.add_verification_key(root_pubkey)
    repository.targets.add_verification_key(targets_pubkey)
    repository.snapshot.add_verification_key(snapshot_pubkey)

    # Verify that repository.write() fails for insufficient threshold
    # of signatures (default threshold = 1).
    self.assertRaises(tuf.UnsignedMetadataError, repository.write) 
    
    repository.timestamp.add_verification_key(timestamp_pubkey)
    
    
    # (3) Load top-level signing keys.
    repository.root.load_signing_key(root_privkey)
    repository.targets.load_signing_key(targets_privkey)
    repository.snapshot.load_signing_key(snapshot_privkey)
   
    # Verify that repository.write() fails for insufficient threshold
    # of signatures (default threshold = 1).
    self.assertRaises(tuf.UnsignedMetadataError, repository.write) 
    
    repository.timestamp.load_signing_key(timestamp_privkey)
   
    
    # (4) Add target files.
    target1 = os.path.join(targets_directory, 'file1.txt')
    target2 = os.path.join(targets_directory, 'file2.txt')
    target3 = os.path.join(targets_directory, 'file3.txt')
    repository.targets.add_target(target1)
    repository.targets.add_target(target2)

    # (5) Perform delegation.
    repository.targets.delegate('role1', [role1_pubkey], [target3]) 
    repository.targets('role1').load_signing_key(role1_privkey)
    
    # (6) Write repository.
    repository.targets.compressions = ['gz']
    repository.write()

    
    # Verify that the expected metadata is written.
    for role in ['root.json', 'targets.json', 'snapshot.json', 'timestamp.json']:
      role_filepath = os.path.join(metadata_directory, role)
      role_signable = tuf.util.load_json_file(role_filepath)
      
      # Raise 'tuf.FormatError' if 'role_signable' is an invalid signable.
      tuf.formats.check_signable_object_format(role_signable)

      if role == 'targets.json':
        compressed_filepath = role_filepath + '.gz'
        self.assertTrue(os.path.exists(compressed_filepath))
       
    # Verify the 'role1.json' delegation is also written.
    role1_filepath = os.path.join(metadata_directory, 'targets', 'role1.json')
    role1_signable = tuf.util.load_json_file(role1_filepath)
    tuf.formats.check_signable_object_format(role1_signable)

    # Verify that an exception is *not* raised for multiple repository.write().
    repository.write()

    # Verify the status() does not raise an exception.
    repository.status()

    # Verify that a write() fails if a repository is loaded and a change
    # is made to a role.
    repo_tool.load_repository(repository_directory)
    
    repository.timestamp.expiration = datetime.datetime(2030, 01, 01, 12, 00)
    self.assertRaises(tuf.UnsignedMetadataError, repository.write)

    # Verify that a write_partial() is allowed. 
    repository.write_partial()

    # Next, perform a non-partial write() with consistent snapshots enabled.
    # Since the timestamp was modified, load its private key.
    repository.timestamp.load_signing_key(timestamp_privkey)

    # Test creation of a consistent snapshot repository.  Writing a consistent
    # snapshot modifies the Root metadata, which specifies whether a repository
    # supports consistent snapshots.  Verify that an exception is raised due to
    # the missing signatures of Root and Snapshot.
    self.assertRaises(tuf.UnsignedMetadataError, repository.write,
                      False, True)
    
    # Load the private keys of Root and Snapshot (new version required since
    # Root has changed.)
    repository.root.load_signing_key(root_privkey)
    repository.snapshot.load_signing_key(snapshot_privkey)
   
    # Verify that consistent snapshot can be written and loaded. 
    repository.write(consistent_snapshot=True) 
    repo_tool.load_repository(repository_directory)


    # Test improperly formatted arguments.
    self.assertRaises(tuf.FormatError, repository.write, 3, False)
    self.assertRaises(tuf.FormatError, repository.write, False, 3)



  def test_get_filepaths_in_directory(self):
    # Test normal case.
    # Use the pre-generated metadata directory for testing.
    metadata_directory = os.path.join('repository_data',
                                      'repository', 'metadata')
    
    
    # Test improperly formatted arguments.
    # Set 'repo' reference to improve readability.
    repo = repo_tool.Repository

    self.assertRaises(tuf.FormatError, repo.get_filepaths_in_directory,
                      3, recursive_walk=False, followlinks=False)
    self.assertRaises(tuf.FormatError, repo.get_filepaths_in_directory,
                      metadata_directory, 3, followlinks=False)
    self.assertRaises(tuf.FormatError, repo.get_filepaths_in_directory,
                      metadata_directory, recursive_walk=False, followlinks=3)

    # Test invalid directory argument.
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)
    nonexistent_directory = os.path.join(temporary_directory, 'nonexistent/')
    self.assertRaises(tuf.Error, repo.get_filepaths_in_directory,
                      nonexistent_directory, recursive_walk=False,
                      followlinks=False)





class TestMetadata(unittest.TestCase):
  def setUp(self):
    # Inherit from the repo_tool.Metadata() base class.  All of the methods
    # to be tested in TestMetadata require at least 1 role, so create it here
    # and set its roleinfo.
    class MetadataRole(repo_tool.Metadata):
      
      def __init__(self):
        super(MetadataRole, self).__init__() 
        
        self._rolename = 'metadata_role'
        
        # Expire in 86400 seconds (1 day).
        expiration = \
          tuf.formats.unix_timestamp_to_datetime(int(time.time() + 86400))
        expiration = expiration.isoformat() + 'Z' 
        roleinfo = {'keyids': [], 'signing_keyids': [], 'threshold': 1, 
                    'signatures': [], 'version': 0,
                    'consistent_snapshot': False,
                    'compressions': [''], 'expires': expiration,
                    'partial_loaded': False}
        
        tuf.roledb.add_role(self._rolename, roleinfo)
    
    self.metadata = MetadataRole() 



  def tearDown(self):
    tuf.roledb.clear_roledb()
    tuf.keydb.clear_keydb()
    self.metadata = None 

  

  def test_rolename(self):
    base_metadata = repo_tool.Metadata()
    
    self.assertEqual(base_metadata.rolename, None)
    
    # Test the sub-classed MetadataRole().
    self.assertEqual(self.metadata.rolename, 'metadata_role')



  def test_version(self):
    # Test version getter, and the default version number.
    self.assertEqual(self.metadata.version, 0)

    # Test version setter, and verify updated version number.
    self.metadata.version = 8
    self.assertEqual(self.metadata.version, 8)



  def test_threshold(self):
    # Test threshold getter, and the default threshold number.
    self.assertEqual(self.metadata.threshold, 1)

    # Test threshold setter, and verify updated threshold number.
    self.metadata.threshold = 3
    self.assertEqual(self.metadata.threshold, 3)



  def test_expiration(self):
    # Test expiration getter.
    expiration = self.metadata.expiration
    self.assertTrue(isinstance(expiration, datetime.datetime))

    # Test expiration setter. 
    self.metadata.expiration = datetime.datetime(2030, 01, 01, 12, 00)
    expiration = self.metadata.expiration
    self.assertTrue(isinstance(expiration, datetime.datetime))


    # Test improperly formatted datetime.
    try: 
      self.metadata.expiration = '3' 
    
    except tuf.FormatError:
      pass
    
    else:
      self.fail('Setter failed to detect improperly formatted datetime.')


    # Test invalid argument (i.e., expiration has already expired.)
    expired_datetime = tuf.formats.unix_timestamp_to_datetime(int(time.time() - 1))
    try: 
      self.metadata.expiration = expired_datetime 
    
    except tuf.Error:
      pass
    
    else:
      self.fail('Setter failed to detect an expired datetime.')



  def test_keys(self):
    # Test default case, where a verification key has not been added. 
    self.assertEqual(self.metadata.keys, [])


    # Test keys() getter after a verification key has been loaded.
    key_path = os.path.join('repository_data',
                            'keystore', 'root_key.pub')
    key_object = repo_tool.import_rsa_publickey_from_file(key_path)
    self.metadata.add_verification_key(key_object)
    
    keyid = key_object['keyid']
    self.assertEqual([keyid], self.metadata.keys)



  def test_signing_keys(self):
    # Test default case, where a signing key has not been added. 
    self.assertEqual(self.metadata.signing_keys, [])


    # Test signing_keys() getter after a signing key has been loaded.
    key_path = os.path.join('repository_data',
                            'keystore', 'root_key')
    key_object = repo_tool.import_rsa_privatekey_from_file(key_path, 'password')
    self.metadata.load_signing_key(key_object)
    
    keyid = key_object['keyid']
    self.assertEqual([keyid], self.metadata.signing_keys)



  def test_compressions(self):
    # Test default case, where only uncompressed metadata is supported.
    self.assertEqual(self.metadata.compressions, [''])

    # Test compressions getter after a compressions algorithm is added.
    self.metadata.compressions = ['gz']

    self.assertEqual(self.metadata.compressions, ['', 'gz'])


    # Test improperly formatted argument.
    try:
      self.metadata.compressions = 3
    except tuf.FormatError:
      pass
    else:
      self.fail('Setter failed to detect improperly formatted compressions')



  def test_add_verification_key(self):
    # Add verification key and verify with keys() that it was added. 
    key_path = os.path.join('repository_data',
                            'keystore', 'root_key.pub')
    key_object = repo_tool.import_rsa_publickey_from_file(key_path)
    self.metadata.add_verification_key(key_object)
    
    keyid = key_object['keyid']
    self.assertEqual([keyid], self.metadata.keys)


    # Test improperly formatted key argument.
    self.assertRaises(tuf.FormatError, self.metadata.add_verification_key, 3)



  def test_remove_verification_key(self):
    # Add verification key so that remove_verifiation_key() can be tested.
    key_path = os.path.join('repository_data',
                            'keystore', 'root_key.pub')
    key_object = repo_tool.import_rsa_publickey_from_file(key_path)
    self.metadata.add_verification_key(key_object)
    
    keyid = key_object['keyid']
    self.assertEqual([keyid], self.metadata.keys)


    # Test successful removal of verification key added above.
    self.metadata.remove_verification_key(key_object)
    self.assertEqual(self.metadata.keys, [])
    

    # Test improperly formatted argument
    self.assertRaises(tuf.FormatError, self.metadata.remove_verification_key, 3)


    # Test non-existent public key argument.
    key_path = os.path.join('repository_data',
                            'keystore', 'targets_key.pub')
    unused_key_object = repo_tool.import_rsa_publickey_from_file(key_path)
    
    self.assertRaises(tuf.Error, self.metadata.remove_verification_key,
                      unused_key_object)



  def test_load_signing_key(self):
    # Test normal case. 
    key_path = os.path.join('repository_data',
                            'keystore', 'root_key')
    key_object = repo_tool.import_rsa_privatekey_from_file(key_path, 'password')
    self.metadata.load_signing_key(key_object)
    
    keyid = key_object['keyid']
    self.assertEqual([keyid], self.metadata.signing_keys)


    # Test improperly formatted arguments.
    self.assertRaises(tuf.FormatError, self.metadata.load_signing_key, 3)

    
    # Test non-private key.
    key_path = os.path.join('repository_data',
                            'keystore', 'root_key.pub')
    key_object = repo_tool.import_rsa_publickey_from_file(key_path)
    self.assertRaises(tuf.Error, self.metadata.load_signing_key, key_object)



  def test_unload_signing_key(self):
    # Load a signing key so that unload_signing_key() can have a key to unload.
    key_path = os.path.join('repository_data',
                            'keystore', 'root_key')
    key_object = repo_tool.import_rsa_privatekey_from_file(key_path, 'password')
    self.metadata.load_signing_key(key_object)
    
    keyid = key_object['keyid']
    self.assertEqual([keyid], self.metadata.signing_keys)

    self.metadata.unload_signing_key(key_object)

    self.assertEqual(self.metadata.signing_keys, [])


    # Test improperly formatted arguments.
    self.assertRaises(tuf.FormatError, self.metadata.unload_signing_key, 3)


    # Test non-existent key argument.
    key_path = os.path.join('repository_data',
                            'keystore', 'targets_key')
    unused_key_object = repo_tool.import_rsa_privatekey_from_file(key_path,
                                                                  'password')
    
    self.assertRaises(tuf.Error, self.metadata.unload_signing_key,
                      unused_key_object)



  def test_add_signature(self):
    # Test normal case.
    # Load signature list from any of pre-generated metadata; needed for
    # testing.
    metadata_directory = os.path.join('repository_data',
                                      'repository', 'metadata')
    root_filepath = os.path.join(metadata_directory, 'root.json')
    root_signable = tuf.util.load_json_file(root_filepath)
    signatures = root_signable['signatures']

    # Add the first signature from the list, as only need one is needed.
    self.metadata.add_signature(signatures[0])
    self.assertEqual(signatures, self.metadata.signatures)


    # Test improperly formatted signature argument.
    self.assertRaises(tuf.FormatError, self.metadata.add_signature, 3)



  def test_remove_signature(self):
    # Test normal case.
    # Add a signature so remove_signature() has some signature to remove.
    metadata_directory = os.path.join('repository_data',
                                      'repository', 'metadata')
    root_filepath = os.path.join(metadata_directory, 'root.json')
    root_signable = tuf.util.load_json_file(root_filepath)
    signatures = root_signable['signatures']
    self.metadata.add_signature(signatures[0])

    self.metadata.remove_signature(signatures[0])
    self.assertEqual(self.metadata.signatures, [])


    # Test improperly formatted signature argument.
    self.assertRaises(tuf.FormatError, self.metadata.remove_signature, 3)


    # Test invalid signature argument (i.e., signature that has not been added.)
    # Load an unused signature to be tested.
    targets_filepath = os.path.join(metadata_directory, 'targets.json')
    targets_signable = tuf.util.load_json_file(targets_filepath)
    signatures = targets_signable['signatures']
    
    self.assertRaises(tuf.Error, self.metadata.remove_signature, signatures[0])



  def test_signatures(self):
    # Test default case, where no signatures have been added yet.
    self.assertEqual(self.metadata.signatures, [])


    # Test getter after adding an example signature.
    metadata_directory = os.path.join('repository_data',
                                      'repository', 'metadata')
    root_filepath = os.path.join(metadata_directory, 'root.json')
    root_signable = tuf.util.load_json_file(root_filepath)
    signatures = root_signable['signatures']

    # Add the first signature from the list, as only need one is needed.
    self.metadata.add_signature(signatures[0])
    self.assertEqual(signatures, self.metadata.signatures)



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
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)
    self.targets_directory = os.path.join(temporary_directory, 'repository',
                                          'targets')
    original_targets_directory = os.path.join('repository_data',
                                              'repository', 'targets')
    shutil.copytree(original_targets_directory, self.targets_directory)
    self.targets_object = repo_tool.Targets(self.targets_directory)



  def tearDown(self):
    tuf.roledb.clear_roledb() 
    tuf.keydb.clear_keydb()
    self.targets_object = None
  
  
  
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



  def test_get_delegated_rolenames(self):
    # Test normal case.
    # Perform two delegations so that get_delegated_rolenames() has roles to 
    # return.
    keystore_directory = os.path.join('repository_data', 'keystore')
    public_keypath = os.path.join(keystore_directory, 'root_key.pub')
    public_key = repo_tool.import_rsa_publickey_from_file(public_keypath)
    target1_filepath = os.path.join(self.targets_directory, 'file1.txt')
    target2_filepath = os.path.join(self.targets_directory, 'file2.txt')

    # Set needed arguments by delegate().
    public_keys = [public_key]
    threshold = 1

    self.targets_object.delegate('tuf', public_keys, [target1_filepath],
                                 threshold, restricted_paths=None,
                                 path_hash_prefixes=None)
    self.targets_object.delegate('warehouse', public_keys, [target2_filepath],
                                 threshold, restricted_paths=None,
                                 path_hash_prefixes=None)

    # Test that get_delegated_rolenames returns the expected delegations.
    expected_delegated_rolenames = ['targets/tuf/', 'targets/warehouse']
    for delegated_rolename in self.targets_object.get_delegated_rolenames():
      delegated_rolename in expected_delegated_rolenames  



  def test_target_files(self):
    # Test normal case.
    # Verify the targets object initially contains zero target files.
    self.assertEqual(self.targets_object.target_files, [])

    target_filepath = os.path.join(self.targets_directory, 'file1.txt')
    self.targets_object.add_target(target_filepath)

    self.assertEqual(len(self.targets_object.target_files), 1)
    self.assertTrue('/file1.txt' in self.targets_object.target_files)



  def test_delegations(self):
    # Test normal case.
    # Perform a delegation so that delegations() has a Targets() object to
    # return.
    keystore_directory = os.path.join('repository_data', 'keystore')
    public_keypath = os.path.join(keystore_directory, 'root_key.pub')
    public_key = repo_tool.import_rsa_publickey_from_file(public_keypath)
    target1_filepath = os.path.join(self.targets_directory, 'file1.txt')

    # Set needed arguments by delegate().
    public_keys = [public_key]
    rolename = 'tuf'
    list_of_targets = [target1_filepath] 
    threshold = 1

    self.targets_object.delegate(rolename, public_keys, list_of_targets,
                                 threshold, restricted_paths=None,
                                 path_hash_prefixes=None)

    # Test that a valid Targets() object is returned by delegations().
    for delegated_object in self.targets_object.delegations:
      self.assertTrue(isinstance(delegated_object, repo_tool.Targets))



  def test_add_target(self):
    # Test normal case.
    # Verify the targets object initially contains zero target files.
    self.assertEqual(self.targets_object.target_files, [])

    target_filepath = os.path.join(self.targets_directory, 'file1.txt')
    self.targets_object.add_target(target_filepath)

    self.assertEqual(len(self.targets_object.target_files), 1)
    self.assertTrue('/file1.txt' in self.targets_object.target_files)
    

    # Test improperly formatted arguments.
    self.assertRaises(tuf.FormatError, self.targets_object.add_target,
                      3)


    # Test invalid filepath argument (i.e., non-existent or invalid file.)
    self.assertRaises(tuf.Error, self.targets_object.add_target,
                      'non-existent.txt')
    self.assertRaises(tuf.Error, self.targets_object.add_target,
                      self.temporary_directory)



  def test_add_targets(self):
    # Test normal case.
    # Verify the targets object initially contains zero target files.
    self.assertEqual(self.targets_object.target_files, [])

    target1_filepath = os.path.join(self.targets_directory, 'file1.txt')
    target2_filepath = os.path.join(self.targets_directory, 'file2.txt')
    target3_filepath = os.path.join(self.targets_directory, 'file3.txt')
    
    target_files = [target1_filepath, target2_filepath, target3_filepath]
    self.targets_object.add_targets(target_files)
    
    self.assertEqual(len(self.targets_object.target_files), 3)
    self.assertEqual(self.targets_object.target_files, 
                     ['/file1.txt', '/file2.txt', '/file3.txt'])


    # Test improperly formatted arguments.
    self.assertRaises(tuf.FormatError, self.targets_object.add_targets,
                      3)


    # Test invalid filepath argument (i.e., non-existent or invalid file.)
    self.assertRaises(tuf.Error, self.targets_object.add_target,
                      ['non-existent.txt'])
    self.assertRaises(tuf.Error, self.targets_object.add_target,
                      [target1_filepath, target2_filepath, 'non-existent.txt'])
    self.assertRaises(tuf.Error, self.targets_object.add_target,
                      self.temporary_directory)



  def test_remove_target(self):
    # Test normal case.
    # Verify the targets object initially contains zero target files.
    self.assertEqual(self.targets_object.target_files, [])

    # Add a target so that remove_target() has something to remove.
    target_filepath = os.path.join(self.targets_directory, 'file1.txt')
    self.targets_object.add_target(target_filepath)

    # Test remove_target()'s behavior.
    self.targets_object.remove_target(target_filepath)
    self.assertEqual(self.targets_object.target_files, [])


    # Test improperly formatted arguments.
    self.assertRaises(tuf.FormatError, self.targets_object.remove_target,
                      3)


    # Test invalid filepath argument (i.e., non-existent or invalid file.)
    self.assertRaises(tuf.Error, self.targets_object.remove_target,
                      '/non-existent.txt')



  def test_clear_targets(self):
    # Test normal case.
    # Verify the targets object initially contains zero target files.
    self.assertEqual(self.targets_object.target_files, [])

    # Add targets, to be tested by clear_targets().
    target1_filepath = os.path.join(self.targets_directory, 'file1.txt')
    target2_filepath = os.path.join(self.targets_directory, 'file2.txt')
    self.targets_object.add_targets([target1_filepath, target2_filepath])

    self.targets_object.clear_targets()
    self.assertEqual(self.targets_object.target_files, [])



  def test_delegate(self):
    # Test normal case.
    # Need at least one public key and valid target paths required by
    # delegate().
    keystore_directory = os.path.join('repository_data', 'keystore')
    public_keypath = os.path.join(keystore_directory, 'root_key.pub')
    public_key = repo_tool.import_rsa_publickey_from_file(public_keypath)
    target1_filepath = os.path.join(self.targets_directory, 'file1.txt')
    target2_filepath = os.path.join(self.targets_directory, 'file2.txt')
  

    # Set needed arguments by delegate().
    public_keys = [public_key]
    rolename = 'tuf'
    list_of_targets = [target1_filepath, target2_filepath] 
    threshold = 1
    restricted_paths = [self.targets_directory]
    path_hash_prefixes = ['e3a3', '8fae', 'd543']

    self.targets_object.delegate(rolename, public_keys, list_of_targets,
                                 threshold, restricted_paths,
                                 path_hash_prefixes)

    self.assertEqual(self.targets_object.get_delegated_rolenames(),
                     ['targets/tuf'])


    # Test improperly formatted arguments.
    self.assertRaises(tuf.FormatError, self.targets_object.delegate,
                      3, public_keys, list_of_targets, threshold,
                      restricted_paths, path_hash_prefixes)
    self.assertRaises(tuf.FormatError, self.targets_object.delegate,
                      rolename, 3, list_of_targets, threshold,
                      restricted_paths, path_hash_prefixes)
    self.assertRaises(tuf.FormatError, self.targets_object.delegate,
                      rolename, public_keys, 3, threshold,
                      restricted_paths, path_hash_prefixes)
    self.assertRaises(tuf.FormatError, self.targets_object.delegate,
                      rolename, public_keys, list_of_targets, '3',
                      restricted_paths, path_hash_prefixes)
    self.assertRaises(tuf.FormatError, self.targets_object.delegate,
                      rolename, public_keys, list_of_targets, threshold,
                      3, path_hash_prefixes)
    self.assertRaises(tuf.FormatError, self.targets_object.delegate,
                      rolename, public_keys, list_of_targets, threshold,
                      restricted_paths, 3)


    # Test invalid arguments (e.g., already delegated 'rolename', non-existent
    # files, etc.).
    # Test duplicate 'rolename' delegation, which should have been delegated
    # in the normal case above.
    self.assertRaises(tuf.Error, self.targets_object.delegate,
                      rolename, public_keys, list_of_targets, threshold,
                      restricted_paths, path_hash_prefixes)
    
    # Test non-existent target paths.
    self.assertRaises(tuf.Error, self.targets_object.delegate,
                      rolename, public_keys, ['/non-existent'], threshold,
                      restricted_paths, path_hash_prefixes)



  def test_delegate_hashed_bins(self):
    # Test normal case.
    keystore_directory = os.path.join('repository_data', 'keystore')
    public_keypath = os.path.join(keystore_directory, 'root_key.pub')
    public_key = repo_tool.import_rsa_publickey_from_file(public_keypath)
    target1_filepath = os.path.join(self.targets_directory, 'file1.txt')

    # Set needed arguments by delegate_hashed_bins().
    public_keys = [public_key]
    list_of_targets = [target1_filepath] 

    # Test delegate_hashed_bins() and verify that 16 hashed bins have
    # been delegated in the parent's roleinfo.
    self.targets_object.delegate_hashed_bins(list_of_targets, public_keys,
                                             number_of_bins=16)

    # The expected child rolenames, since 'number_of_bins' = 16 
    delegated_rolenames = ['0', '1', '2', '3', '4', '5', '6', '7',
                           '8', '9', 'a', 'b', 'c', 'd', 'e', 'f']

    # Prepend the parent's rolename.
    expected_delegated_rolenames = []
    for rolename in delegated_rolenames:
      rolename = self.targets_object.rolename + '/' + rolename
      expected_delegated_rolenames.append(rolename)

    self.assertEqual(sorted(self.targets_object.get_delegated_rolenames()),
                     sorted(expected_delegated_rolenames))


    # Test improperly formatted arguments.
    self.assertRaises(tuf.FormatError,
                      self.targets_object.delegate_hashed_bins, 3, public_keys,
                      number_of_bins=1)
    self.assertRaises(tuf.FormatError,
                      self.targets_object.delegate_hashed_bins,
                      list_of_targets, 3, number_of_bins=1)
    self.assertRaises(tuf.FormatError,
                      self.targets_object.delegate_hashed_bins,
                      list_of_targets, public_keys, '1')


    # Test invalid arguments.
    # Invalid number of bins, which must be a power of 2.
    self.assertRaises(tuf.Error,
                      self.targets_object.delegate_hashed_bins,
                      list_of_targets, public_keys, number_of_bins=3)
    
    # Invalid 'list_of_targets'.
    self.assertRaises(tuf.Error,
                      self.targets_object.delegate_hashed_bins,
                      ['/non-existent'], public_keys, number_of_bins=3)



  def test_add_restricted_paths(self):
    # Test normal case.
    # Perform a delegation so that add_restricted_paths() has a child role
    # to restrict.
    keystore_directory = os.path.join('repository_data', 'keystore')
    public_keypath = os.path.join(keystore_directory, 'root_key.pub')
    public_key = repo_tool.import_rsa_publickey_from_file(public_keypath)

    # Set needed arguments by delegate().
    public_keys = [public_key]
    rolename = 'tuf'
    threshold = 1

    self.targets_object.delegate(rolename, public_keys, [],
                                 threshold, restricted_paths=None,
                                 path_hash_prefixes=None)

    restricted_path = os.path.join(self.targets_directory, 'tuf_files')
    os.mkdir(restricted_path)
    restricted_paths = [restricted_path]
    self.targets_object.add_restricted_paths(restricted_paths, 'tuf')
    
    # Retrieve 'targets_object' roleinfo, and verify the roleinfo contains
    # the expected restricted paths of the delegated role.  Only
    # Repository.write() verifies that child target paths are allowed by the
    # parent.
    targets_object_roleinfo = tuf.roledb.get_roleinfo(self.targets_object.rolename)

    delegated_role = targets_object_roleinfo['delegations']['roles'][0]
    self.assertEqual(['/tuf_files/'], delegated_role['paths'])


    # Test improperly formatted arguments.
    self.assertRaises(tuf.FormatError, self.targets_object.add_restricted_paths,
                      3, 'tuf')
    self.assertRaises(tuf.FormatError, self.targets_object.add_restricted_paths,
                      restricted_paths, 3)


    # Test invalid arguments.
    # A non-delegated child role.
    self.assertRaises(tuf.Error, self.targets_object.add_restricted_paths,
                      restricted_paths, 'non_delegated_rolename')
    
    # Non-existent 'restricted_paths'.
    self.assertRaises(tuf.Error, self.targets_object.add_restricted_paths,
                      ['/non-existent'], 'tuf')



  def test_revoke(self):
    # Test normal case.
    # Perform a delegation so that revoke() has a delegation to revoke.
    keystore_directory = os.path.join('repository_data', 'keystore')
    public_keypath = os.path.join(keystore_directory, 'root_key.pub')
    public_key = repo_tool.import_rsa_publickey_from_file(public_keypath)
    target1_filepath = os.path.join(self.targets_directory, 'file1.txt')

    # Set needed arguments by delegate().
    public_keys = [public_key]
    rolename = 'tuf'
    list_of_targets = [target1_filepath] 
    threshold = 1

    self.targets_object.delegate(rolename, public_keys, list_of_targets,
                                 threshold, restricted_paths=None,
                                 path_hash_prefixes=None)

    # Test revoke()
    self.targets_object.revoke('tuf')
    self.assertEqual(self.targets_object.get_delegated_rolenames(), [])


    # Test improperly formatted rolename argument.
    self.assertRaises(tuf.FormatError, self.targets_object.revoke, 3)





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
    # Test normal case.
    # Setup the temporary repository directories needed by
    # create_new_repository().
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory) 
    repository_directory = os.path.join(temporary_directory, 'repository')
    metadata_directory = os.path.join(repository_directory,
                                      repo_tool.METADATA_STAGED_DIRECTORY_NAME)
    targets_directory = os.path.join(repository_directory,
                                     repo_tool.TARGETS_DIRECTORY_NAME)
    
    repository = repo_tool.create_new_repository(repository_directory)
    self.assertTrue(isinstance(repository, repo_tool.Repository))
    
    # Verify that the 'repository/', 'repository/metadata', and
    # 'repository/targets' directories were created.
    self.assertTrue(os.path.exists(repository_directory))
    self.assertTrue(os.path.exists(metadata_directory))
    self.assertTrue(os.path.exists(targets_directory))


    # Test that the 'repository' directory is created (along with the other
    # sub-directories) when it does not exist yet.  The repository tool creates
    # the non-existent directory.
    shutil.rmtree(repository_directory)

    repository = repo_tool.create_new_repository(repository_directory)
    repository = repo_tool.create_new_repository(repository_directory)
    self.assertTrue(isinstance(repository, repo_tool.Repository))
    
    # Verify that the 'repository/', 'repository/metadata', and
    # 'repository/targets' directories were created.
    self.assertTrue(os.path.exists(repository_directory))
    self.assertTrue(os.path.exists(metadata_directory))
    self.assertTrue(os.path.exists(targets_directory))
     

    # Test improperly formatted arguments.
    self.assertRaises(tuf.FormatError, repo_tool.create_new_repository, 3)



  def test_load_repository(self):
    # Test normal case.
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory) 
    original_repository_directory = os.path.join('repository_data',
                                                 'repository')
    repository_directory = os.path.join(temporary_directory, 'repository')
    shutil.copytree(original_repository_directory, repository_directory)
     
    repository = repo_tool.load_repository(repository_directory)
    self.assertTrue(isinstance(repository, repo_tool.Repository))

    # Verify the expected roles have been loaded.  See
    # 'tuf/tests/repository_data/repository/'.
    expected_roles = \
      ['root', 'targets', 'snapshot', 'timestamp', 'targets/role1']
    for role in tuf.roledb.get_rolenames():
      self.assertTrue(role in expected_roles)
    
    self.assertTrue(len(repository.root.keys))
    self.assertTrue(len(repository.targets.keys))
    self.assertTrue(len(repository.snapshot.keys))
    self.assertTrue(len(repository.timestamp.keys))
    self.assertTrue(len(repository.targets('role1').keys))

    # Assumed the targets (tuf/tests/repository_data/) role contains 'file1.txt'
    # and 'file2.txt'.
    self.assertTrue('/file1.txt' in repository.targets.target_files)
    self.assertTrue('/file2.txt' in repository.targets.target_files)
    self.assertTrue('/file3.txt' in repository.targets('role1').target_files)
    
    # Test improperly formatted arguments.
    self.assertRaises(tuf.FormatError, repo_tool.load_repository, 3)


    # Test for invalid 'repository_directory' (i.e., does not contain the
    # minimum required metadata.
    root_filepath = \
      os.path.join(repository_directory,
                   repo_tool.METADATA_STAGED_DIRECTORY_NAME, 'root.json') 
    os.remove(root_filepath)
    self.assertRaises(tuf.RepositoryError, repo_tool.load_repository,
                      repository_directory)



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
    key_filepath = os.path.join('repository_data', 'keystore',
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
    key_filepath = os.path.join('repository_data', 'keystore',
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
                 'timestamp.json': os.path.join(metadata_directory, 'timestamp.json')}
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
    # Test normal case.
    # Load the root metadata provided in 'tuf/tests/repository_data/'.
    root_filepath = os.path.join('repository_data', 'repository',
                                 'metadata', 'root.json')
    root_signable = tuf.util.load_json_file(root_filepath)

    # generate_root_metadata() expects the top-level roles and keys to be
    # available in 'tuf.keydb' and 'tuf.roledb'.
    tuf.roledb.create_roledb_from_root_metadata(root_signable['signed'])
    tuf.keydb.create_keydb_from_root_metadata(root_signable['signed'])
    expires = '1985-10-21T01:22:00Z'

    root_metadata = repo_tool.generate_root_metadata(1, expires,
                                                     consistent_snapshot=False)
    self.assertTrue(tuf.formats.ROOT_SCHEMA.matches(root_metadata))

    
    # Test improperly formatted arguments.
    self.assertRaises(tuf.FormatError, repo_tool.generate_root_metadata,  
                      '3', expires, False) 
    self.assertRaises(tuf.FormatError, repo_tool.generate_root_metadata,  
                      1, '3', False) 
    self.assertRaises(tuf.FormatError, repo_tool.generate_root_metadata,  
                      1, expires, 3) 

    # Test for missing required roles and keys.
    tuf.roledb.clear_roledb()
    tuf.keydb.clear_keydb()
    self.assertRaises(tuf.Error, repo_tool.generate_root_metadata,
                      1, expires, False)



  def test_generate_targets_metadata(self):
    # Test normal case. 
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)
    targets_directory = os.path.join(temporary_directory, 'targets')
    file1_path = os.path.join(targets_directory, 'file.txt')
    tuf.util.ensure_parent_dir(file1_path)

    with open(file1_path, 'wb') as file_object:
      file_object.write('test file.')
   
    # Set valid generate_targets_metadata() arguments.
    version = 1
    datetime_object = datetime.datetime(2030, 01, 01, 12, 00)
    expiration_date = datetime_object.isoformat() + 'Z'
    target_files = ['file.txt']
    
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
      repo_tool.generate_targets_metadata(targets_directory, target_files,
                                          version, expiration_date, delegations,
                                          False)
    self.assertTrue(tuf.formats.TARGETS_SCHEMA.matches(targets_metadata))

    # Verify that 'digest.filename' file is saved to 'targets_directory' if
    # the 'write_consistent_targets' argument is True.
    list_targets_directory = os.listdir(targets_directory)
    targets_metadata = \
      repo_tool.generate_targets_metadata(targets_directory, target_files,
                                          version, expiration_date, delegations,
                                          write_consistent_targets=True)
    new_list_targets_directory = os.listdir(targets_directory)
    
    # Verify that 'targets_directory' contains only one extra item.
    self.assertTrue(len(list_targets_directory) + 1,
                    len(new_list_targets_directory))


    # Test improperly formatted arguments.
    self.assertRaises(tuf.FormatError, repo_tool.generate_targets_metadata,
                      3, target_files, version, expiration_date)  
    self.assertRaises(tuf.FormatError, repo_tool.generate_targets_metadata,
                      targets_directory, 3, version, expiration_date)  
    self.assertRaises(tuf.FormatError, repo_tool.generate_targets_metadata,
                      targets_directory, target_files, '3', expiration_date)  
    self.assertRaises(tuf.FormatError, repo_tool.generate_targets_metadata,
                      targets_directory, target_files, version, '3')  
    
    # Improperly formatted 'delegations' and 'write_consistent_targets' 
    self.assertRaises(tuf.FormatError, repo_tool.generate_targets_metadata,
                      targets_directory, target_files, version, expiration_date,
                      3, False)  
    self.assertRaises(tuf.FormatError, repo_tool.generate_targets_metadata,
                      targets_directory, target_files, version, expiration_date,
                      delegations, 3)  


    # Test invalid 'target_files' argument.
    self.assertRaises(tuf.Error, repo_tool.generate_targets_metadata,
                      targets_directory, ['nonexistent_file.txt'], version,
                      expiration_date)  




  def test_generate_snapshot_metadata(self):
    # Test normal case.
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)
    original_repository_path = os.path.join('repository_data',
                                            'repository')
    repository_directory = os.path.join(temporary_directory, 'repository') 
    shutil.copytree(original_repository_path, repository_directory)
    metadata_directory = os.path.join(repository_directory,
                                      repo_tool.METADATA_STAGED_DIRECTORY_NAME)
    root_filename = os.path.join(metadata_directory, repo_tool.ROOT_FILENAME)
    targets_filename = os.path.join(metadata_directory,
                                    repo_tool.TARGETS_FILENAME)
    version = 1
    expiration_date = '1985-10-21T13:20:00Z'
    
    snapshot_metadata = \
      repo_tool.generate_snapshot_metadata(metadata_directory, version,
                                           expiration_date, root_filename,
                                           targets_filename,
                                           consistent_snapshot=False)
    self.assertTrue(tuf.formats.SNAPSHOT_SCHEMA.matches(snapshot_metadata))


    # Test improperly formatted arguments.
    self.assertRaises(tuf.FormatError, repo_tool.generate_snapshot_metadata,
                      3, version, expiration_date,
                      root_filename, targets_filename, consistent_snapshot=False)
    self.assertRaises(tuf.FormatError, repo_tool.generate_snapshot_metadata,
                      metadata_directory, '3', expiration_date,
                      root_filename, targets_filename, consistent_snapshot=False)
    self.assertRaises(tuf.FormatError, repo_tool.generate_snapshot_metadata,
                      metadata_directory, version, '3',
                      root_filename, targets_filename, consistent_snapshot=False)
    self.assertRaises(tuf.FormatError, repo_tool.generate_snapshot_metadata,
                      metadata_directory, version, expiration_date,
                      3, targets_filename, consistent_snapshot=False)
    self.assertRaises(tuf.FormatError, repo_tool.generate_snapshot_metadata,
                      metadata_directory, version, expiration_date,
                      root_filename, 3, consistent_snapshot=False)
    self.assertRaises(tuf.FormatError, repo_tool.generate_snapshot_metadata,
                      metadata_directory, version, expiration_date,
                      root_filename, targets_filename, 3)



  def test_generate_timestamp_metadata(self):
    # Test normal case.
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)
    original_repository_path = os.path.join('repository_data',
                                            'repository')
    repository_directory = os.path.join(temporary_directory, 'repository') 
    shutil.copytree(original_repository_path, repository_directory)
    metadata_directory = os.path.join(repository_directory,
                                      repo_tool.METADATA_STAGED_DIRECTORY_NAME)
    snapshot_filename = os.path.join(metadata_directory,
                                     repo_tool.SNAPSHOT_FILENAME)
   
    # Set valid generate_timestamp_metadata() arguments.
    version = 1
    expiration_date = '1985-10-21T13:20:00Z'

    compressions = ['gz']

    snapshot_metadata = \
      repo_tool.generate_timestamp_metadata(snapshot_filename, version,
                                            expiration_date, compressions)
    self.assertTrue(tuf.formats.TIMESTAMP_SCHEMA.matches(snapshot_metadata))
    

    # Test improperly formatted arguments.
    self.assertRaises(tuf.FormatError, repo_tool.generate_timestamp_metadata,
                      3, version, expiration_date, compressions)
    self.assertRaises(tuf.FormatError, repo_tool.generate_timestamp_metadata,
                      snapshot_filename, '3', expiration_date, compressions)
    self.assertRaises(tuf.FormatError, repo_tool.generate_timestamp_metadata,
                      snapshot_filename, version, '3', compressions)
    self.assertRaises(tuf.FormatError, repo_tool.generate_timestamp_metadata,
                      snapshot_filename, version, expiration_date, 3)
    self.assertRaises(tuf.FormatError, repo_tool.generate_timestamp_metadata,
                      snapshot_filename, version, expiration_date, ['compress'])




  def test_sign_metadata(self):
    # Test normal case.
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)
    metadata_path = os.path.join('repository_data',
                                 'repository', 'metadata')
    keystore_path = os.path.join('repository_data',
                                 'keystore')
    root_filename = os.path.join(metadata_path, 'root.json')
    root_metadata = tuf.util.load_json_file(root_filename)['signed']
    
    tuf.keydb.create_keydb_from_root_metadata(root_metadata)
    tuf.roledb.create_roledb_from_root_metadata(root_metadata)
    root_keyids = tuf.roledb.get_role_keyids('root')

    root_private_keypath = os.path.join(keystore_path, 'root_key')
    root_private_key = \
      repo_tool.import_rsa_privatekey_from_file(root_private_keypath,
                                                'password')
    
    # sign_metadata() expects the private key 'root_metadata' to be in
    # 'tuf.keydb'.  Remove any public keys that may be loaded before
    # adding private key, otherwise a 'tuf.KeyAlreadyExists' exception is
    # raised.
    tuf.keydb.remove_key(root_private_key['keyid'])
    tuf.keydb.add_key(root_private_key)

    root_signable = repo_tool.sign_metadata(root_metadata, root_keyids,
                                            root_filename) 
    self.assertTrue(tuf.formats.SIGNABLE_SCHEMA.matches(root_signable))


    # Test improperly formatted arguments.
    self.assertRaises(tuf.FormatError, repo_tool.sign_metadata, 3, root_keyids,
                      'root.json')
    self.assertRaises(tuf.FormatError, repo_tool.sign_metadata, root_metadata,
                      3, 'root.json')
    self.assertRaises(tuf.FormatError, repo_tool.sign_metadata, root_metadata,
                      root_keyids, 3)



  def test_write_metadata_file(self):
    # Test normal case.
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)
    metadata_directory = os.path.join('repository_data',
                                      'repository', 'metadata')
    root_filename = os.path.join(metadata_directory, 'root.json')
    root_signable = tuf.util.load_json_file(root_filename)
  
    output_filename = os.path.join(temporary_directory, 'root.json')
    compressions = ['gz']
  
    self.assertFalse(os.path.exists(output_filename))
    repo_tool.write_metadata_file(root_signable, output_filename, compressions,
                                  consistent_snapshot=False)
    self.assertTrue(os.path.exists(output_filename))
    self.assertTrue(os.path.exists(output_filename + '.gz'))


    # Test improperly formatted arguments.
    self.assertRaises(tuf.FormatError, repo_tool.write_metadata_file,
                      3, output_filename, compressions, False)
    self.assertRaises(tuf.FormatError, repo_tool.write_metadata_file,
                      root_signable, 3, compressions, False)
    self.assertRaises(tuf.FormatError, repo_tool.write_metadata_file,
                      root_signable, output_filename, 3, False)
    self.assertRaises(tuf.FormatError, repo_tool.write_metadata_file,
                      root_signable, output_filename, compressions, 3)



  def test_create_tuf_client_directory(self):
    # Test normal case.
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)
    repository_directory = os.path.join('repository_data',
                                        'repository')
    client_directory = os.path.join(temporary_directory, 'client')

    repo_tool.create_tuf_client_directory(repository_directory, client_directory)

    self.assertTrue(os.path.exists(client_directory))
    metadata_directory = os.path.join(client_directory, 'metadata')
    current_directory = os.path.join(metadata_directory, 'current')
    previous_directory = os.path.join(metadata_directory, 'previous')
    self.assertTrue(os.path.exists(client_directory))
    self.assertTrue(os.path.exists(metadata_directory))
    self.assertTrue(os.path.exists(current_directory))
    self.assertTrue(os.path.exists(previous_directory))


    # Test improperly formatted arguments.
    self.assertRaises(tuf.FormatError, repo_tool.create_tuf_client_directory,
                      3, client_directory)
    self.assertRaises(tuf.FormatError, repo_tool.create_tuf_client_directory,
                      repository_directory, 3)


    # Test invalid argument (i.e., client directory already exists.)
    self.assertRaises(tuf.RepositoryError, repo_tool.create_tuf_client_directory,
                      repository_directory, client_directory)


# Run the test cases.
if __name__ == '__main__':
  unittest.main()
