#!/usr/bin/env python

"""
<Program Name>
  test_repository_lib.py

<Author> 
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  June 1, 2014.

<Copyright>
  See LICENSE for licensing information.

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

# 'unittest2' required for testing under Python < 2.7.
if sys.version_info >= (2, 7):
  import unittest

else:
  import unittest2 as unittest 

import tuf
import tuf.ssl_crypto.formats
import tuf.log
import tuf.formats
import tuf.roledb
import tuf.ssl_crypto.keydb
import tuf.ssl_crypto.hash
from simple_settings import settings
import tuf.repository_lib as repo_lib
import tuf.repository_tool as repo_tool

import six

logger = logging.getLogger('tuf.test_repository_lib')

repo_lib.disable_console_log_messages()



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
    tuf.roledb.clear_roledb(clear_all=True)
    tuf.ssl_crypto.keydb.clear_keydb(clear_all=True)



  def test_generate_and_write_rsa_keypair(self):
  
    # Test normal case.
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory) 
    test_keypath = os.path.join(temporary_directory, 'rsa_key')

    repo_lib.generate_and_write_rsa_keypair(test_keypath, password='pw')
    self.assertTrue(os.path.exists(test_keypath))
    self.assertTrue(os.path.exists(test_keypath + '.pub'))
    
    # Ensure the generated key files are importable.
    imported_pubkey = \
      repo_lib.import_rsa_publickey_from_file(test_keypath + '.pub')
    self.assertTrue(tuf.ssl_crypto.formats.RSAKEY_SCHEMA.matches(imported_pubkey))
    
    imported_privkey = \
      repo_lib.import_rsa_privatekey_from_file(test_keypath, 'pw')
    self.assertTrue(tuf.ssl_crypto.formats.RSAKEY_SCHEMA.matches(imported_privkey))

    # Custom 'bits' argument.
    os.remove(test_keypath)
    os.remove(test_keypath + '.pub')
    repo_lib.generate_and_write_rsa_keypair(test_keypath, bits=2048,
                                             password='pw')
    self.assertTrue(os.path.exists(test_keypath))
    self.assertTrue(os.path.exists(test_keypath + '.pub'))


    # Test improperly formatted arguments.
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError, repo_lib.generate_and_write_rsa_keypair,
                      3, bits=2048, password='pw')
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError, repo_lib.generate_and_write_rsa_keypair,
                      test_keypath, bits='bad', password='pw')
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError, repo_lib.generate_and_write_rsa_keypair,
                      test_keypath, bits=2048, password=3)


    # Test invalid 'bits' argument.
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError, repo_lib.generate_and_write_rsa_keypair,
                      test_keypath, bits=1024, password='pw')



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
    self.assertTrue(tuf.ssl_crypto.formats.RSAKEY_SCHEMA.matches(imported_rsa_key))

    
    # Test improperly formatted argument.
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError,
                      repo_lib.import_rsa_privatekey_from_file, 3, 'pw')


    # Test invalid argument.
    # Non-existent key file.
    nonexistent_keypath = os.path.join(temporary_directory,
                                       'nonexistent_keypath') 
    self.assertRaises(IOError, repo_lib.import_rsa_privatekey_from_file,
                      nonexistent_keypath, 'pw')
    
    # Invalid key file argument. 
    invalid_keyfile = os.path.join(temporary_directory, 'invalid_keyfile') 
    with open(invalid_keyfile, 'wb') as file_object:
      file_object.write(b'bad keyfile')
    self.assertRaises(tuf.ssl_commons.exceptions.CryptoError, repo_lib.import_rsa_privatekey_from_file,
                      invalid_keyfile, 'pw')



  def test_import_rsa_publickey_from_file(self):
    # Test normal case.
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)
    
    # Load one of the pre-generated key files from 'tuf/tests/repository_data'.
    key_filepath = os.path.join('repository_data', 'keystore',
                                'root_key.pub')
    self.assertTrue(os.path.exists(key_filepath))
    
    imported_rsa_key = repo_lib.import_rsa_publickey_from_file(key_filepath)
    self.assertTrue(tuf.ssl_crypto.formats.RSAKEY_SCHEMA.matches(imported_rsa_key))

    
    # Test improperly formatted argument.
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError,
                      repo_lib.import_rsa_privatekey_from_file, 3)


    # Test invalid argument.
    # Non-existent key file.
    nonexistent_keypath = os.path.join(temporary_directory,
                                       'nonexistent_keypath')
    self.assertRaises(IOError, repo_lib.import_rsa_publickey_from_file,
                      nonexistent_keypath)
    
    # Invalid key file argument. 
    invalid_keyfile = os.path.join(temporary_directory, 'invalid_keyfile') 
    with open(invalid_keyfile, 'wb') as file_object:
      file_object.write(b'bad keyfile')
    self.assertRaises(tuf.ssl_commons.exceptions.Error, repo_lib.import_rsa_publickey_from_file,
                      invalid_keyfile)



  def test_generate_and_write_ed25519_keypair(self):
    
    # Test normal case.
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory) 
    test_keypath = os.path.join(temporary_directory, 'ed25519_key')

    repo_lib.generate_and_write_ed25519_keypair(test_keypath, password='pw')
    self.assertTrue(os.path.exists(test_keypath))
    self.assertTrue(os.path.exists(test_keypath + '.pub'))

    # Ensure the generated key files are importable.
    imported_pubkey = \
      repo_lib.import_ed25519_publickey_from_file(test_keypath + '.pub')
    self.assertTrue(tuf.ssl_crypto.formats.ED25519KEY_SCHEMA.matches(imported_pubkey))
    
    imported_privkey = \
      repo_lib.import_ed25519_privatekey_from_file(test_keypath, 'pw')
    self.assertTrue(tuf.ssl_crypto.formats.ED25519KEY_SCHEMA.matches(imported_privkey))


    # Test improperly formatted arguments.
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError,
                      repo_lib.generate_and_write_ed25519_keypair,
                      3, password='pw')
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError, repo_lib.generate_and_write_rsa_keypair,
                      test_keypath, password=3)



  def test_import_ed25519_publickey_from_file(self):
    # Test normal case.
    # Generate ed25519 keys that can be imported.
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)
    ed25519_keypath = os.path.join(temporary_directory, 'ed25519_key') 
    repo_lib.generate_and_write_ed25519_keypair(ed25519_keypath, password='pw')
     
    imported_ed25519_key = \
      repo_lib.import_ed25519_publickey_from_file(ed25519_keypath + '.pub')
    self.assertTrue(tuf.ssl_crypto.formats.ED25519KEY_SCHEMA.matches(imported_ed25519_key))
    
    
    # Test improperly formatted argument.
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError,
                      repo_lib.import_ed25519_publickey_from_file, 3)


    # Test invalid argument.
    # Non-existent key file.
    nonexistent_keypath = os.path.join(temporary_directory,
                                       'nonexistent_keypath')
    self.assertRaises(IOError, repo_lib.import_ed25519_publickey_from_file,
                      nonexistent_keypath)
    
    # Invalid key file argument. 
    invalid_keyfile = os.path.join(temporary_directory, 'invalid_keyfile') 
    with open(invalid_keyfile, 'wb') as file_object:
      file_object.write(b'bad keyfile')
    
    self.assertRaises(tuf.ssl_commons.exceptions.Error, repo_lib.import_ed25519_publickey_from_file,
                      invalid_keyfile)
 
    # Invalid public key imported (contains unexpected keytype.)
    keytype = imported_ed25519_key['keytype'] 
    keyval = imported_ed25519_key['keyval']
    ed25519key_metadata_format = \
      tuf.ssl_crypto.keys.format_keyval_to_metadata(keytype, keyval, private=False)
    
    ed25519key_metadata_format['keytype'] = 'invalid_keytype'
    with open(ed25519_keypath + '.pub', 'wb') as file_object:
      file_object.write(json.dumps(ed25519key_metadata_format).encode('utf-8'))
    
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError,
                      repo_lib.import_ed25519_publickey_from_file,
                      ed25519_keypath + '.pub')



  def test_import_ed25519_privatekey_from_file(self):
    # Test normal case.
    # Generate ed25519 keys that can be imported.
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)
    ed25519_keypath = os.path.join(temporary_directory, 'ed25519_key') 
    repo_lib.generate_and_write_ed25519_keypair(ed25519_keypath, password='pw')
     
    imported_ed25519_key = \
      repo_lib.import_ed25519_privatekey_from_file(ed25519_keypath, 'pw')
    self.assertTrue(tuf.ssl_crypto.formats.ED25519KEY_SCHEMA.matches(imported_ed25519_key))
    
    
    # Test improperly formatted argument.
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError,
                      repo_lib.import_ed25519_privatekey_from_file, 3, 'pw')


    # Test invalid argument.
    # Non-existent key file.
    nonexistent_keypath = os.path.join(temporary_directory,
                                       'nonexistent_keypath')
    self.assertRaises(IOError, repo_lib.import_ed25519_privatekey_from_file,
                      nonexistent_keypath, 'pw')
    
    # Invalid key file argument. 
    invalid_keyfile = os.path.join(temporary_directory, 'invalid_keyfile') 
    with open(invalid_keyfile, 'wb') as file_object:
      file_object.write(b'bad keyfile')
    
    self.assertRaises(tuf.ssl_commons.exceptions.Error, repo_lib.import_ed25519_privatekey_from_file,
                      invalid_keyfile, 'pw')
    
    # Invalid private key imported (contains unexpected keytype.)
    imported_ed25519_key['keytype'] = 'invalid_keytype'

    # Use 'pycrypto_keys.py' to bypass the key format validation performed by
    # 'keys.py'.
    salt, iterations, derived_key = \
      tuf.ssl_crypto.pycrypto_keys._generate_derived_key('pw')
 
    # Store the derived key info in a dictionary, the object expected
    # by the non-public _encrypt() routine.
    derived_key_information = {'salt': salt, 'iterations': iterations,
                               'derived_key': derived_key}

    # Convert the key object to json string format and encrypt it with the
    # derived key.
    encrypted_key = \
      tuf.ssl_crypto.pycrypto_keys._encrypt(json.dumps(imported_ed25519_key),
                                 derived_key_information)  
    
    with open(ed25519_keypath, 'wb') as file_object:
      file_object.write(encrypted_key.encode('utf-8'))

    self.assertRaises(tuf.ssl_commons.exceptions.FormatError,
                      repo_lib.import_ed25519_privatekey_from_file,
                      ed25519_keypath, 'pw')



  def test_get_metadata_filenames(self):
   
    # Test normal case.
    metadata_directory = os.path.join('metadata/')
    filenames = {'root.json': metadata_directory + 'root.json',
                 'targets.json': metadata_directory + 'targets.json',
                 'snapshot.json': metadata_directory + 'snapshot.json',
                 'timestamp.json': metadata_directory + 'timestamp.json'}
    
    self.assertEqual(filenames, repo_lib.get_metadata_filenames('metadata/'))

    # If a directory argument is not specified, the current working directory
    # is used.
    metadata_directory = os.getcwd()
    filenames = {'root.json': os.path.join(metadata_directory, 'root.json'),
                 'targets.json': os.path.join(metadata_directory, 'targets.json'),
                 'snapshot.json': os.path.join(metadata_directory, 'snapshot.json'),
                 'timestamp.json': os.path.join(metadata_directory, 'timestamp.json')}
    self.assertEqual(filenames, repo_lib.get_metadata_filenames())


    # Test improperly formatted argument.
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError, repo_lib.get_metadata_filenames, 3)



  def test_get_metadata_fileinfo(self):
    # Test normal case. 
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)
    test_filepath = os.path.join(temporary_directory, 'file.txt')
    
    with open(test_filepath, 'wt') as file_object:
      file_object.write('test file')
  
    # Generate test fileinfo object.  It is assumed SHA256 and SHA512 hashes
    # are computed by get_metadata_fileinfo().
    file_length = os.path.getsize(test_filepath)
    sha256_digest_object = tuf.ssl_crypto.hash.digest_filename(test_filepath)
    sha512_digest_object = tuf.ssl_crypto.hash.digest_filename(test_filepath, algorithm='sha512')
    file_hashes = {'sha256': sha256_digest_object.hexdigest(),
                   'sha512': sha512_digest_object.hexdigest()}
    fileinfo = {'length': file_length, 'hashes': file_hashes}
    self.assertTrue(tuf.ssl_crypto.formats.FILEINFO_SCHEMA.matches(fileinfo))
    
    self.assertEqual(fileinfo, repo_lib.get_metadata_fileinfo(test_filepath))


    # Test improperly formatted argument.
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError, repo_lib.get_metadata_fileinfo, 3)


    # Test non-existent file.
    nonexistent_filepath = os.path.join(temporary_directory, 'oops.txt')
    self.assertRaises(tuf.ssl_commons.exceptions.Error, repo_lib.get_metadata_fileinfo,
                      nonexistent_filepath)



  def test_get_target_hash(self):
    # Test normal case. 
    expected_target_hashes = {
      '/file1.txt': 'e3a3d89eb3b70ce3fbce6017d7b8c12d4abd5635427a0e8a238f53157df85b3d',
      '/README.txt': '8faee106f1bb69f34aaf1df1e3c2e87d763c4d878cb96b91db13495e32ceb0b0',
      '/packages/file2.txt': 'c9c4a5cdd84858dd6a23d98d7e6e6b2aec45034946c16b2200bc317c75415e92'  
    }
    for filepath, target_hash in six.iteritems(expected_target_hashes):
      self.assertTrue(tuf.ssl_crypto.formats.RELPATH_SCHEMA.matches(filepath))
      self.assertTrue(tuf.ssl_crypto.formats.HASH_SCHEMA.matches(target_hash))
      self.assertEqual(repo_lib.get_target_hash(filepath), target_hash)
   
    # Test for improperly formatted argument.
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError, repo_lib.get_target_hash, 8)



  def test_generate_root_metadata(self):
    # Test normal case.
    # Load the root metadata provided in 'tuf/tests/repository_data/'.
    root_filepath = os.path.join('repository_data', 'repository',
                                 'metadata', 'root.json')
    root_signable = tuf.ssl_crypto.util.load_json_file(root_filepath)

    # generate_root_metadata() expects the top-level roles and keys to be
    # available in 'tuf.ssl_crypto.keydb' and 'tuf.roledb'.
    tuf.roledb.create_roledb_from_root_metadata(root_signable['signed'])
    tuf.ssl_crypto.keydb.create_keydb_from_root_metadata(root_signable['signed'])
    expires = '1985-10-21T01:22:00Z'

    root_metadata = repo_lib.generate_root_metadata(1, expires,
                                                    consistent_snapshot=False)
    self.assertTrue(tuf.ssl_crypto.formats.ROOT_SCHEMA.matches(root_metadata))

    root_keyids = tuf.roledb.get_role_keyids('root')
    tuf.ssl_crypto.keydb._keydb_dict['default'][root_keyids[0]]['keytype'] = 'bad_keytype'
    self.assertRaises(tuf.ssl_commons.exceptions.Error, repo_lib.generate_root_metadata, 1,
                      expires, consistent_snapshot=False)
    
    # Reset the root key's keytype, so that we can next verify that a different
    # tuf.ssl_commons.exceptions.Error exception is raised for duplicate keyids.
    tuf.ssl_crypto.keydb._keydb_dict['default'][root_keyids[0]]['keytype'] = 'rsa'
    
    # Add duplicate keyid to root's roleinfo.
    tuf.roledb._roledb_dict['default']['root']['keyids'].append(root_keyids[0])
    self.assertRaises(tuf.ssl_commons.exceptions.Error, repo_lib.generate_root_metadata, 1,
                      expires, consistent_snapshot=False)
    
    # Test improperly formatted arguments.
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError, repo_lib.generate_root_metadata,  
                      '3', expires, False)
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError, repo_lib.generate_root_metadata,  
                      1, '3', False) 
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError, repo_lib.generate_root_metadata,  
                      1, expires, 3) 

    # Test for missing required roles and keys.
    tuf.roledb.clear_roledb()
    tuf.ssl_crypto.keydb.clear_keydb()
    self.assertRaises(tuf.ssl_commons.exceptions.Error, repo_lib.generate_root_metadata,
                      1, expires, False)



  def test_generate_targets_metadata(self):
    # Test normal case. 
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)
    targets_directory = os.path.join(temporary_directory, 'targets')
    file1_path = os.path.join(targets_directory, 'file.txt')
    tuf.ssl_crypto.util.ensure_parent_dir(file1_path)

    with open(file1_path, 'wt') as file_object:
      file_object.write('test file.')
   
    # Set valid generate_targets_metadata() arguments.  Add a custom field for
    # the 'target_files' target set below.
    version = 1
    datetime_object = datetime.datetime(2030, 1, 1, 12, 0)
    expiration_date = datetime_object.isoformat() + 'Z'
    file_permissions = oct(os.stat(file1_path).st_mode)[4:] 
    target_files = {'file.txt': {'file_permission': file_permissions}}
    
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
    self.assertTrue(tuf.ssl_crypto.formats.TARGETS_SCHEMA.matches(targets_metadata))
   
    # Valid arguments with 'delegations' set to None.
    targets_metadata = \
      repo_lib.generate_targets_metadata(targets_directory, target_files,
                                         version, expiration_date, None,
                                         False)
    self.assertTrue(tuf.ssl_crypto.formats.TARGETS_SCHEMA.matches(targets_metadata))

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
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError, repo_lib.generate_targets_metadata,
                      3, target_files, version, expiration_date)  
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError, repo_lib.generate_targets_metadata,
                      targets_directory, 3, version, expiration_date)  
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError, repo_lib.generate_targets_metadata,
                      targets_directory, target_files, '3', expiration_date)  
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError, repo_lib.generate_targets_metadata,
                      targets_directory, target_files, version, '3')  
    
    # Improperly formatted 'delegations' and 'write_consistent_targets' 
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError, repo_lib.generate_targets_metadata,
                      targets_directory, target_files, version, expiration_date,
                      3, False)  
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError, repo_lib.generate_targets_metadata,
                      targets_directory, target_files, version, expiration_date,
                      delegations, 3)  

    # Test non-existent target file.
    bad_target_file = \
      {'non-existent.txt': {'file_permission': file_permissions}}

    self.assertRaises(tuf.ssl_commons.exceptions.Error, repo_lib.generate_targets_metadata,
                      targets_directory, bad_target_file, version,
                      expiration_date)



  def test_generate_snapshot_metadata(self):
    # Test normal case.
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)
    original_repository_path = os.path.join('repository_data',
                                            'repository')
    repository_directory = os.path.join(temporary_directory, 'repository') 
    shutil.copytree(original_repository_path, repository_directory)
    metadata_directory = os.path.join(repository_directory,
                                      repo_lib.METADATA_STAGED_DIRECTORY_NAME)
    targets_directory = os.path.join(repository_directory, repo_lib.TARGETS_DIRECTORY_NAME)
    root_filename = os.path.join(metadata_directory, repo_lib.ROOT_FILENAME)
    targets_filename = os.path.join(metadata_directory,
                                    repo_lib.TARGETS_FILENAME)
    version = 1
    expiration_date = '1985-10-21T13:20:00Z'
   
    # Load a valid repository so that top-level roles exist in roledb and 
    # generate_snapshot_metadata() has roles to specify in snapshot metadata. 
    repository = repo_tool.Repository(repository_directory, metadata_directory,
                                      targets_directory)
   
    repository_junk = repo_tool.load_repository(repository_directory)

    root_filename = 'root'
    targets_filename = 'targets'
    snapshot_metadata = \
      repo_lib.generate_snapshot_metadata(metadata_directory, version,
                                          expiration_date, root_filename,
                                          targets_filename,
                                          consistent_snapshot=False)
    self.assertTrue(tuf.formats.SNAPSHOT_SCHEMA.matches(snapshot_metadata))


    # Test improperly formatted arguments.
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError, repo_lib.generate_snapshot_metadata,
                      3, version, expiration_date,
                      root_filename, targets_filename, consistent_snapshot=False)
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError, repo_lib.generate_snapshot_metadata,
                      metadata_directory, '3', expiration_date,
                      root_filename, targets_filename, consistent_snapshot=False)
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError, repo_lib.generate_snapshot_metadata,
                      metadata_directory, version, '3',
                      root_filename, targets_filename, consistent_snapshot=False)
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError, repo_lib.generate_snapshot_metadata,
                      metadata_directory, version, expiration_date,
                      3, targets_filename, consistent_snapshot=False)
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError, repo_lib.generate_snapshot_metadata,
                      metadata_directory, version, expiration_date,
                      root_filename, 3, consistent_snapshot=False)
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError, repo_lib.generate_snapshot_metadata,
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
                                      repo_lib.METADATA_STAGED_DIRECTORY_NAME)
    targets_directory = os.path.join(repository_directory, repo_lib.TARGETS_DIRECTORY_NAME)

    snapshot_filename = os.path.join(metadata_directory,
                                     repo_lib.SNAPSHOT_FILENAME)
   
    # Set valid generate_timestamp_metadata() arguments.
    version = 1
    expiration_date = '1985-10-21T13:20:00Z'
    
    # Load a valid repository so that top-level roles exist in roledb and 
    # generate_snapshot_metadata() has roles to specify in snapshot metadata. 
    repository = repo_tool.Repository(repository_directory, metadata_directory,
                                      targets_directory)
   
    repository_junk = repo_tool.load_repository(repository_directory)

    timestamp_metadata = \
      repo_lib.generate_timestamp_metadata(snapshot_filename, version,
                                           expiration_date)
    self.assertTrue(tuf.formats.TIMESTAMP_SCHEMA.matches(timestamp_metadata))
    

    # Test improperly formatted arguments.
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError, repo_lib.generate_timestamp_metadata,
                      3, version, expiration_date)
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError, repo_lib.generate_timestamp_metadata,
                      snapshot_filename, '3', expiration_date)
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError, repo_lib.generate_timestamp_metadata,
                      snapshot_filename, version, '3')





  def test_sign_metadata(self):
    # Test normal case.
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)
    metadata_path = os.path.join('repository_data',
                                 'repository', 'metadata')
    keystore_path = os.path.join('repository_data',
                                 'keystore')
    root_filename = os.path.join(metadata_path, 'root.json')
    root_metadata = tuf.ssl_crypto.util.load_json_file(root_filename)['signed']
    targets_filename = os.path.join(metadata_path, 'targets.json')
    targets_metadata = tuf.ssl_crypto.util.load_json_file(targets_filename)['signed']
    
    tuf.ssl_crypto.keydb.create_keydb_from_root_metadata(root_metadata)
    tuf.roledb.create_roledb_from_root_metadata(root_metadata)
    root_keyids = tuf.roledb.get_role_keyids('root')
    targets_keyids = tuf.roledb.get_role_keyids('targets')

    root_private_keypath = os.path.join(keystore_path, 'root_key')
    root_private_key = \
      repo_lib.import_rsa_privatekey_from_file(root_private_keypath, 'password')
    
    # Sign with a valid, but not a threshold, key.
    targets_public_keypath = os.path.join(keystore_path, 'targets_key.pub')
    targets_public_key = \
      repo_lib.import_ed25519_publickey_from_file(targets_public_keypath)

    # sign_metadata() expects the private key 'root_metadata' to be in
    # 'tuf.ssl_crypto.keydb'.  Remove any public keys that may be loaded before
    # adding private key, otherwise a 'tuf.KeyAlreadyExists' exception is
    # raised.
    tuf.ssl_crypto.keydb.remove_key(root_private_key['keyid'])
    tuf.ssl_crypto.keydb.add_key(root_private_key)
    tuf.ssl_crypto.keydb.remove_key(targets_public_key['keyid'])
    tuf.ssl_crypto.keydb.add_key(targets_public_key)
   
    # Verify that a valid root signable is generated.
    root_signable = repo_lib.sign_metadata(root_metadata, root_keyids,
                                           root_filename) 
    self.assertTrue(tuf.ssl_crypto.formats.SIGNABLE_SCHEMA.matches(root_signable))

    # Test for an unset private key (in this case, target's).
    repo_lib.sign_metadata(targets_metadata, targets_keyids,
                           targets_filename)

    # Add an invalid keytype to one of the root keys.
    root_keyid = root_keyids[0]
    tuf.ssl_crypto.keydb._keydb_dict['default'][root_keyid]['keytype'] = 'bad_keytype'
    self.assertRaises(tuf.ssl_commons.exceptions.Error, repo_lib.sign_metadata, root_metadata,
                      root_keyids, root_filename)

    # Test improperly formatted arguments.
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError, repo_lib.sign_metadata, 3, root_keyids,
                      'root.json')
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError, repo_lib.sign_metadata, root_metadata,
                      3, 'root.json')
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError, repo_lib.sign_metadata, root_metadata,
                      root_keyids, 3)



  def test_write_metadata_file(self):
    # Test normal case.
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)
    metadata_directory = os.path.join('repository_data',
                                      'repository', 'metadata')
    root_filename = os.path.join(metadata_directory, 'root.json')
    root_signable = tuf.ssl_crypto.util.load_json_file(root_filename)
  
    output_filename = os.path.join(temporary_directory, 'root.json')
    compression_algorithms = ['gz']
    version_number = root_signable['signed']['version'] + 1
  
    self.assertFalse(os.path.exists(output_filename))
    repo_lib.write_metadata_file(root_signable, output_filename,
                                 version_number,
                                 compression_algorithms,
                                 consistent_snapshot=False)
    self.assertTrue(os.path.exists(output_filename))
    self.assertTrue(os.path.exists(output_filename + '.gz'))
   
    # Attempt to over-write the previously written metadata file.  An exception
    # is not raised in this case, only a debug message is logged. 
    repo_lib.write_metadata_file(root_signable, output_filename,
                                 version_number,
                                 compression_algorithms,
                                 consistent_snapshot=False)

    # Try to write a consistent metadate file. An exception is not raised in
    # this case.  For testing purposes, root.json should be a hard link to the
    # consistent metadata file.  We should verify that root.json points to
    # the latest consistent files.
    settings.CONSISTENT_METHOD = 'hard_link'
    repo_lib.write_metadata_file(root_signable, output_filename,
                                 version_number,
                                 compression_algorithms,
                                 consistent_snapshot=True)

    # Test if the consistent files are properly named
    # Filename format of a consistent file: <version number>.rolename.json
    version_and_filename = str(version_number) + '.' + 'root.json'
    first_version_output_file = os.path.join(temporary_directory, version_and_filename)
    self.assertTrue(os.path.exists(first_version_output_file))

    # Try to add more consistent metadata files.
    version_number += 1
    repo_lib.write_metadata_file(root_signable, output_filename,
                                 version_number,
                                 compression_algorithms,
                                 consistent_snapshot=True)

    # Test if the the latest root.json points to the expected consistent file
    # and consistent metadata do not all point to the same root.json
    version_and_filename = str(version_number) + '.' + 'root.json'
    second_version_output_file = os.path.join(temporary_directory, version_and_filename)
    self.assertTrue(os.path.exists(second_version_output_file))
    self.assertNotEqual(os.stat(output_filename).st_ino, os.stat(first_version_output_file).st_ino)
    self.assertEqual(os.stat(output_filename).st_ino, os.stat(second_version_output_file).st_ino)

    # Test for an improper settings.CONSISTENT_METHOD string value.
    settings.CONSISTENT_METHOD = 'somebadidea'
    self.assertRaises(tuf.ssl_commons.exceptions.InvalidConfigurationError, repo_lib.write_metadata_file,
                                                     root_signable, output_filename,
                                                     version_number,
                                                     compression_algorithms,
                                                     consistent_snapshot=True)

    # Try to create a link to root.json when root.json doesn't exist locally.
    # repository_lib should log a message if this is the case.
    settings.CONSISTENT_METHOD = 'hard_link'
    os.remove(output_filename)
    repo_lib.write_metadata_file(root_signable, output_filename,
                                 version_number,
                                 compression_algorithms,
                                 consistent_snapshot=True)
    
    # Reset CONSISTENT_METHOD so that subsequent tests work as expected.
    settings.CONSISTENT_METHOD = 'copy'
    
    # Test for unknown compression algorithm.
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError, repo_lib.write_metadata_file,
                                       root_signable, output_filename,
                                       version_number,
                                       compression_algorithms=['bad_algo'],
                                       consistent_snapshot=False)

    # Test improperly formatted arguments.
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError, repo_lib.write_metadata_file,
                      3, output_filename, version_number,
                      compression_algorithms, False)
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError, repo_lib.write_metadata_file,
                      root_signable, 3, version_number, compression_algorithms,
                      False)
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError, repo_lib.write_metadata_file,
                      root_signable, output_filename, '3',
                      compression_algorithms, False)
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError, repo_lib.write_metadata_file,
                      root_signable, output_filename, version_number,
                      compression_algorithms, 3)
  


  def test__write_compressed_metadata(self):
    # Test for invalid 'compressed_filename' argument and set
    # 'write_new_metadata' to False.
    file_object = tuf.ssl_crypto.util.TempFile()
    existing_filename = os.path.join('repository_data', 'repository',
                                     'metadata', 'root.json')

    write_new_metadata = False 
    repo_lib._write_compressed_metadata(file_object,
                                        compressed_filename=existing_filename,
                                        write_new_metadata=write_new_metadata,
                                        consistent_snapshot=False,
                                        version_number=8)

    # Test writing of compressed metadata when consistent snapshots is enabled. 
    file_object = tuf.ssl_crypto.util.TempFile()
    shutil.copy(existing_filename, os.path.join(self.temporary_directory, '8.root.json.gz'))
    shutil.copy(existing_filename, os.path.join(self.temporary_directory, '8.root.json.zip'))
    shutil.copy(existing_filename, os.path.join(self.temporary_directory, 'root.json.zip'))
    compressed_filename = os.path.join(self.temporary_directory, 'root.json.gz')
   
    # For testing purposes, add additional compression algorithms to
    # repo_lib.SUPPORTED_COMPRESSION_EXTENSIONS.
    repo_lib.SUPPORTED_COMPRESSION_EXTENSIONS = ['gz', 'zip', 'bz2']
    repo_lib._write_compressed_metadata(file_object,
                                        compressed_filename=compressed_filename,
                                        write_new_metadata=True,
                                        consistent_snapshot=True,
                                        version_number=8)
    repo_lib.SUPPORTED_COMPRESSION_EXTENSIONS = ['gz']


  def test_create_tuf_client_directory(self):
    # Test normal case.
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)
    repository_directory = os.path.join('repository_data',
                                        'repository')
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
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError, repo_lib.create_tuf_client_directory,
                      3, client_directory)
    self.assertRaises(tuf.ssl_commons.exceptions.FormatError, repo_lib.create_tuf_client_directory,
                      repository_directory, 3)


    # Test invalid argument (i.e., client directory already exists.)
    self.assertRaises(tuf.ssl_commons.exceptions.RepositoryError, repo_lib.create_tuf_client_directory,
                      repository_directory, client_directory)

    # Test invalid client metadata directory (i.e., non-errno.EEXIST exceptions
    # should be re-raised.) 
    shutil.rmtree(metadata_directory)
    current_client_directory_mode = os.stat(client_directory)[stat.ST_MODE]
    
    # Remove write access for the client directory so that the 'metadata'
    # directory cannot be created.  create_tuf_client_directory() should
    # re-raise the 'OSError' (i.e., errno.EACCES) exception and only handle
    # errno.EEXIST.
    os.chmod(client_directory, current_client_directory_mode & ~stat.S_IWUSR)

    self.assertRaises(OSError, repo_lib.create_tuf_client_directory,
                      repository_directory, client_directory)
    
    # Reset the client directory's mode.
    os.chmod(client_directory, current_client_directory_mode)



  def test__check_directory(self):
    # Test for non-existent directory.
    self.assertRaises(tuf.ssl_commons.exceptions.Error, repo_lib._check_directory, 'non-existent')



  def test__generate_and_write_metadata(self):
    # Test for invalid, or unsupported, rolename.
    # Load the root metadata provided in 'tuf/tests/repository_data/'.
    root_filepath = os.path.join('repository_data', 'repository',
                                 'metadata', 'root.json')
    root_signable = tuf.ssl_crypto.util.load_json_file(root_filepath)

    # _generate_and_write_metadata() expects the top-level roles
    # (specifically 'snapshot') and keys to be available in 'tuf.roledb'.
    tuf.roledb.create_roledb_from_root_metadata(root_signable['signed'])
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)
    targets_directory = os.path.join(temporary_directory, 'targets')
    os.mkdir(targets_directory)
    repository_directory = os.path.join(temporary_directory, 'repository') 
    metadata_directory = os.path.join(repository_directory,
                                      repo_lib.METADATA_STAGED_DIRECTORY_NAME)
    targets_metadata = os.path.join('repository_data', 'repository', 'metadata',
                                    'targets.json')
    obsolete_metadata = os.path.join(metadata_directory,
                                            'obsolete_role.json')
    tuf.ssl_crypto.util.ensure_parent_dir(obsolete_metadata)
    shutil.copyfile(targets_metadata, obsolete_metadata)
    
    # Verify that obsolete metadata (a metadata file exists on disk, but the
    # role is unavailable in 'tuf.roledb').  First add the obsolete
    # role to 'tuf.roledb' so that its metadata file can be written to disk.
    targets_roleinfo = tuf.roledb.get_roleinfo('targets')
    targets_roleinfo['version'] = 1
    expiration = \
      tuf.formats.unix_timestamp_to_datetime(int(time.time() + 86400))
    expiration = expiration.isoformat() + 'Z' 
    targets_roleinfo['expires'] = expiration 
    tuf.roledb.add_role('obsolete_role', targets_roleinfo)

    repo_lib._generate_and_write_metadata('obsolete_role', obsolete_metadata,
                                          targets_directory, metadata_directory,         
                                          consistent_snapshot=False,
                                          filenames=None,     
                                          compression_algorithms=['gz'])

    snapshot_filepath = os.path.join('repository_data', 'repository',
                                     'metadata', 'snapshot.json')
    snapshot_signable = tuf.ssl_crypto.util.load_json_file(snapshot_filepath)
    tuf.roledb.remove_role('obsolete_role')
    self.assertTrue(os.path.exists(os.path.join(metadata_directory,
                                                'obsolete_role.json')))
    tuf.repository_lib._delete_obsolete_metadata(metadata_directory,
                                                 snapshot_signable['signed'],
                                                 False)
    self.assertFalse(os.path.exists(metadata_directory + 'obsolete_role.json'))
    shutil.copyfile(targets_metadata, obsolete_metadata)



  def test__delete_obsolete_metadata(self):
    temporary_directory = tempfile.mkdtemp(dir=self.temporary_directory)
    repository_directory = os.path.join(temporary_directory, 'repository') 
    metadata_directory = os.path.join(repository_directory,
                                      repo_lib.METADATA_STAGED_DIRECTORY_NAME)
    os.makedirs(metadata_directory)
    snapshot_filepath = os.path.join('repository_data', 'repository',
                                     'metadata', 'snapshot.json')
    snapshot_signable = tuf.ssl_crypto.util.load_json_file(snapshot_filepath)
 
    # Create role metadata that should not exist in snapshot.json.
    role1_filepath = os.path.join('repository_data', 'repository',
                                  'metadata', 'role1.json')
    shutil.copyfile(role1_filepath, os.path.join(metadata_directory, 'role2.json'))

    repo_lib._delete_obsolete_metadata(metadata_directory,
                                       snapshot_signable['signed'],
                                       True)

    # _delete_obsolete_metadata should never delete root.json.
    root_filepath = os.path.join('repository_data', 'repository',
                                 'metadata', 'root.json')
    shutil.copyfile(root_filepath, os.path.join(metadata_directory, 'root.json'))
    repo_lib._delete_obsolete_metadata(metadata_directory,
                                       snapshot_signable['signed'],
                                       True)
    self.assertTrue(os.path.exists(os.path.join(metadata_directory, 'root.json')))

    # Verify what happens for a non-existent metadata directory (a debug
    # message is logged).
    repo_lib._delete_obsolete_metadata('non-existent',
                                       snapshot_signable['signed'],
                                       True)


  def test__load_top_level_metadata(self):
    tuf.roledb.clear_roledb(clear_all=True)
    tuf.ssl_crypto.keydb.clear_keydb(clear_all=True)

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
    signable = tuf.ssl_crypto.util.load_json_file(os.path.join(metadata_directory, 'root.json'))
    signable['signatures'].append(signable['signatures'][0])

    repo_lib.write_metadata_file(signable, root_file, 8, ['gz'], False)

    # Remove compressed metadata so that we can test for loading of a
    # repository with no compression enabled.
    for role_file in os.listdir(metadata_directory):
      if role_file.endswith('.json.gz'):
        role_filename = os.path.join(metadata_directory, role_file)
        os.remove(role_filename)

    filenames = repo_lib.get_metadata_filenames(metadata_directory)
    repository = repo_tool.create_new_repository(repository_directory)
    repo_lib._load_top_level_metadata(repository, filenames)

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
    
    repo_lib._load_top_level_metadata(repository, filenames)

    # Attempt to load a repository with missing top-level metadata.
    for role_file in os.listdir(metadata_directory):
      if role_file.endswith('.json') and not role_file.startswith('root'):
        role_filename = os.path.join(metadata_directory, role_file)
        os.remove(role_filename)
    repo_lib._load_top_level_metadata(repository, filenames)

    # Remove the required Root file and verify that an exception is raised.
    os.remove(os.path.join(metadata_directory, 'root.json'))
    self.assertRaises(tuf.ssl_commons.exceptions.RepositoryError, repo_lib._load_top_level_metadata,
                      repository, filenames)



  def test__remove_invalid_and_duplicate_signatures(self):
    # Remove duplicate PSS signatures (same key generates valid, but different
    # signatures).  First load a valid signable (in this case, the root role).
    root_filepath = os.path.join('repository_data', 'repository',
                                 'metadata', 'root.json')
    root_signable = tuf.ssl_crypto.util.load_json_file(root_filepath)
    key_filepath = os.path.join('repository_data', 'keystore', 'root_key')
    root_rsa_key = repo_lib.import_rsa_privatekey_from_file(key_filepath,
                                                            'password')
    
    # Add 'root_rsa_key' to tuf.ssl_crypto.keydb, since
    # _remove_invalid_and_duplicate_signatures() checks for unknown keys in
    # tuf.ssl_crypto.keydb.
    tuf.ssl_crypto.keydb.add_key(root_rsa_key)

    # Append the new valid, but duplicate PSS signature, and test that
    # duplicates are removed.  create_signature() generates a key for the
    # key type of the first argument (i.e., root_rsa_key).
    new_pss_signature = tuf.ssl_crypto.keys.create_signature(root_rsa_key,
                                                  root_signable['signed'])
    root_signable['signatures'].append(new_pss_signature)

    expected_number_of_signatures = len(root_signable['signatures'])
    tuf.repository_lib._remove_invalid_and_duplicate_signatures(root_signable)
    self.assertEqual(len(root_signable), expected_number_of_signatures)

    # Test for an invalid keyid.
    root_signable['signatures'][0]['keyid'] = '404'
    tuf.repository_lib._remove_invalid_and_duplicate_signatures(root_signable)
  
    # Re-add a valid signature for the following test condition.
    root_signable['signatures'].append(new_pss_signature)

    # Test that an exception is not raised if an invalid sig is present,
    # and that the duplicate key is removed 'root_signable'.
    root_signable['signatures'][0]['sig'] = '4040'
    invalid_keyid = root_signable['signatures'][0]['keyid'] 
    tuf.repository_lib._remove_invalid_and_duplicate_signatures(root_signable)

    for signature in root_signable['signatures']:
      self.assertFalse(invalid_keyid == signature['keyid'])



# Run the test cases.
if __name__ == '__main__':
  unittest.main()
