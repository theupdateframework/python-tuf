#!/usr/bin/env python

"""
<Program Name>
  test_util.py

<Author>
  Konstantin Andrianov.

<Started>
  February 1, 2013.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Unit test for 'util.py'
"""

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import os
import sys
import gzip
import shutil
import logging
import tempfile
import unittest

import tuf
import tuf.log
import tuf.hash
import tuf.util
import tuf.unittest_toolbox as unittest_toolbox
import tuf._vendor.six as six

logger = logging.getLogger('tuf.test_util')


class TestUtil(unittest_toolbox.Modified_TestCase):

  def setUp(self):
    unittest_toolbox.Modified_TestCase.setUp(self)
    self.temp_fileobj = tuf.util.TempFile()

		

  def tearDown(self):
    unittest_toolbox.Modified_TestCase.tearDown(self)
    self.temp_fileobj.close_temp_file()



  def test_A1_tempfile_close_temp_file(self):
    # Was the temporary file closed?
    self.temp_fileobj.close_temp_file()
    self.assertTrue(self.temp_fileobj.temporary_file.closed)



  def _extract_tempfile_directory(self, config_temp_dir=None):
    """
      Takes a directory (essentially specified in the conf.py as
      'temporary_directory') and substitutes tempfile.TemporaryFile() with
      tempfile.mkstemp() in order to extract actual directory of the stored  
      tempfile.  Returns the config's temporary directory (or default temp
      directory) and actual directory.
    """

    # Patching 'tuf.conf.temporary_directory'.
    tuf.conf.temporary_directory = config_temp_dir

    if config_temp_dir is None:
      # 'config_temp_dir' needs to be set to default.
      config_temp_dir = tempfile.gettempdir()

    # Patching 'tempfile.TemporaryFile()' (by substituting 
    # temfile.TemporaryFile() with tempfile.mkstemp()) in order to get the 
    # directory of the stored tempfile object.
    saved_tempfile_TemporaryFile = tuf.util.tempfile.NamedTemporaryFile
    tuf.util.tempfile.NamedTemporaryFile = tempfile.mkstemp
    _temp_fileobj = tuf.util.TempFile()
    tuf.util.tempfile.NamedTemporaryFile = saved_tempfile_TemporaryFile
    junk, _tempfilepath = _temp_fileobj.temporary_file
    _tempfile_dir = os.path.dirname(_tempfilepath)

    # In the case when 'config_temp_dir' is None or some other discrepancy,
    # '_temp_fileobj' needs to be closed manually since tempfile.mkstemp() 
    # was used.
    if os.path.exists(_tempfilepath):
      os.remove(_tempfilepath)

    return config_temp_dir, _tempfile_dir


 
  def test_A2_tempfile_init(self):
    # Goal: Verify that temporary files are stored in the appropriate temp
    # directory.  The location of the temporary files is set in 'tuf.conf.py'.

    # Test: Expected input verification.
    # Assumed 'tuf.conf.temporary_directory' is 'None' initially.
    temp_file = tuf.util.TempFile()
    temp_file_directory = os.path.dirname(temp_file.temporary_file.name)
    self.assertEqual(tempfile.gettempdir(), temp_file_directory)

    saved_temporary_directory = tuf.conf.temporary_directory
    temp_directory = self.make_temp_directory()
    tuf.conf.temporary_directory = temp_directory
    temp_file = tuf.util.TempFile()
    temp_file_directory = os.path.dirname(temp_file.temporary_file.name)
    self.assertEqual(temp_directory, temp_file_directory)

    tuf.conf.temporary_directory = saved_temporary_directory

    # Test: Unexpected input handling.
    config_temp_dirs = [self.random_string(), 123, ['a'], {'a':1}]
    for config_temp_dir in config_temp_dirs:
      config_temp_dir, actual_dir = \
      self._extract_tempfile_directory(config_temp_dir)
      self.assertEqual(tempfile.gettempdir(), actual_dir)


   
  def test_A3_tempfile_read(self):
    filepath = self.make_temp_data_file(data = '1234567890')
    fileobj = open(filepath, 'rb')

    # Patching 'temp_fileobj.temporary_file'.
    self.temp_fileobj.temporary_file = fileobj

    # Test: Expected input.
    self.assertEqual(self.temp_fileobj.read().decode('utf-8'), '1234567890')
    self.assertEqual(self.temp_fileobj.read(4).decode('utf-8'), '1234')

    # Test: Unexpected input.
    for bogus_arg in ['abcd', ['abcd'], {'a':'a'}, -100]:
      self.assertRaises(tuf.FormatError, self.temp_fileobj.read, bogus_arg)



  def test_A4_tempfile_write(self):
    data = self.random_string()
    self.temp_fileobj.write(data.encode('utf-8'))
    self.assertEqual(data, self.temp_fileobj.read().decode('utf-8'))
    
    self.temp_fileobj.write(data.encode('utf-8'), auto_flush=False)
    self.assertEqual(data, self.temp_fileobj.read().decode('utf-8'))



  def test_A5_tempfile_move(self):
    # Destination directory to save the temporary file in.
    dest_temp_dir = self.make_temp_directory()
    dest_path = os.path.join(dest_temp_dir, self.random_string())
    self.temp_fileobj.write(self.random_string().encode('utf-8'))
    self.temp_fileobj.move(dest_path)
    self.assertTrue(dest_path)



  def _compress_existing_file(self, filepath):
    """
    [Helper]Compresses file 'filepath' and returns file path of 
    the compresses file.
    """
    
    # NOTE: DO NOT forget to remove the newly created compressed file!
    if os.path.exists(filepath):
      compressed_filepath = filepath+'.gz'
      f_in = open(filepath, 'rb')
      f_out = gzip.open(compressed_filepath, 'wb')
      f_out.writelines(f_in)
      f_out.close()
      f_in.close()
      
      return compressed_filepath
    
    else:
      logger.error('Compression of '+repr(filepath)+' failed. Path does not exist.')
      sys.exit(1)
 


  def _decompress_file(self, compressed_filepath):
    """[Helper]"""
    if os.path.exists(compressed_filepath):
      f = gzip.open(compressed_filepath, 'rb')
      file_content = f.read()
      f.close()
      return file_content
    
    else:
      logger.error('Decompression of '+repr(compressed_filepath)+' failed. '+\
            'Path does not exist.')
      sys.exit(1)



  def test_A6_tempfile_decompress_temp_file_object(self):
    # Setup: generate a temp file (self.make_temp_data_file()),
    # compress it.  Write it to self.temp_fileobj().
    filepath = self.make_temp_data_file()
    fileobj = open(filepath, 'rb')
    compressed_filepath = self._compress_existing_file(filepath)
    compressed_fileobj = open(compressed_filepath, 'rb')
    self.temp_fileobj.write(compressed_fileobj.read())
    os.remove(compressed_filepath)

    # Try decompression using incorrect compression type i.e. compressions
    # other than 'gzip'.  In short feeding incorrect input.
    bogus_args = ['zip', 1234, self.random_string()]
    for arg in bogus_args:    
      self.assertRaises(tuf.Error,
                        self.temp_fileobj.decompress_temp_file_object, arg)
    self.temp_fileobj.decompress_temp_file_object('gzip')
    self.assertEqual(self.temp_fileobj.read(), fileobj.read())

    # Checking the content of the TempFile's '_orig_file' instance.
    check_compressed_original = self.make_temp_file()
    with open(check_compressed_original, 'wb') as file_object:
      file_object.write(self.temp_fileobj._orig_file.read())
    data_in_orig_file = self._decompress_file(check_compressed_original)
    fileobj.seek(0)
    self.assertEqual(data_in_orig_file, fileobj.read())
    
    # Try decompressing once more.
    self.assertRaises(tuf.Error, 
                      self.temp_fileobj.decompress_temp_file_object, 'gzip')
    
    # Test decompression of invalid gzip file.
    temp_file = tuf.util.TempFile()
    fileobj.seek(0)
    temp_file.write(fileobj.read())
    temp_file.decompress_temp_file_object('gzip')



  def test_B1_get_file_details(self):
    # Goal: Verify proper output given certain expected/unexpected input.

    # Making a temporary file.
    filepath = self.make_temp_data_file()

    # Computing the hash and length of the tempfile.
    digest_object = tuf.hash.digest_filename(filepath, algorithm='sha256')
    file_hash = {'sha256' : digest_object.hexdigest()}
    file_length = os.path.getsize(filepath)
 
    # Test: Expected input.
    self.assertEqual(tuf.util.get_file_details(filepath), (file_length, file_hash))

    # Test: Incorrect input.
    bogus_inputs = [self.random_string(), 1234, [self.random_string()],
                    {'a': 'b'}, None]
    
    for bogus_input in bogus_inputs:
      if isinstance(bogus_input, six.string_types):
        self.assertRaises(tuf.Error, tuf.util.get_file_details, bogus_input)
      else:
        self.assertRaises(tuf.FormatError, tuf.util.get_file_details, bogus_input)

 
    
  def  test_B2_ensure_parent_dir(self):
    existing_parent_dir = self.make_temp_directory()
    non_existing_parent_dir = os.path.join(existing_parent_dir, 'a', 'b')

    for parent_dir in [existing_parent_dir, non_existing_parent_dir, 12, [3]]:
      if isinstance(parent_dir, six.string_types):
        tuf.util.ensure_parent_dir(os.path.join(parent_dir, 'a.txt'))
        self.assertTrue(os.path.isdir(parent_dir))
      else:
        self.assertRaises(tuf.FormatError, tuf.util.ensure_parent_dir, parent_dir)
      


  def  test_B3_file_in_confined_directories(self):
    # Goal: Provide invalid input for 'filepath' and 'confined_directories'.
    # Include inputs like: '[1, 2, "a"]' and such...
    # Reference to 'file_in_confined_directories()' to improve readability.
    in_confined_directory = tuf.util.file_in_confined_directories
    list_of_confined_directories = ['a', 12, {'a':'a'}, [1]]
    list_of_filepaths = [12, ['a'], {'a':'a'}, 'a']    
    for bogus_confined_directory in list_of_confined_directories:
      for filepath in list_of_filepaths:
        self.assertRaises(tuf.FormatError, in_confined_directory, 
                          filepath, bogus_confined_directory)

    # Test: Inputs that evaluate to False.
    confined_directories = ['a/b/', 'a/b/c/d/']
    self.assertFalse(in_confined_directory('a/b/c/1.txt', confined_directories))
    
    confined_directories = ['a/b/c/d/e/']
    self.assertFalse(in_confined_directory('a', confined_directories))
    self.assertFalse(in_confined_directory('a/b', confined_directories))
    self.assertFalse(in_confined_directory('a/b/c', confined_directories))
    self.assertFalse(in_confined_directory('a/b/c/d', confined_directories))
    # Below, 'e' is a file in the 'a/b/c/d/' directory.
    self.assertFalse(in_confined_directory('a/b/c/d/e', confined_directories))
    
    # Test: Inputs that evaluate to True.
    self.assertTrue(in_confined_directory('a/b/c.txt', ['']))
    self.assertTrue(in_confined_directory('a/b/c.txt', ['a/b/']))
    self.assertTrue(in_confined_directory('a/b/c.txt', ['x', '']))
    self.assertTrue(in_confined_directory('a/b/c/..', ['a/']))


  def test_B4_import_json(self):
    self.assertTrue('json' in sys.modules)



  def  test_B5_load_json_string(self):
    # Test normal case. 
    data = ['a', {'b': ['c', None, 30.3, 29]}]
    json_string = tuf.util.json.dumps(data)
    self.assertEqual(data, tuf.util.load_json_string(json_string))

    # Test invalid arguments.
    self.assertRaises(tuf.Error, tuf.util.load_json_string, 8)
    invalid_json_string = {'a': tuf.FormatError}
    self.assertRaises(tuf.Error, tuf.util.load_json_string, invalid_json_string)

 

  def  test_B6_load_json_file(self):
    data = ['a', {'b': ['c', None, 30.3, 29]}]
    filepath = self.make_temp_file()
    fileobj = open(filepath, 'wt')
    tuf.util.json.dump(data, fileobj)
    fileobj.close()
    self.assertEqual(data, tuf.util.load_json_file(filepath))

    # Test a gzipped file.
    compressed_filepath = self._compress_existing_file(filepath)
    self.assertEqual(data, tuf.util.load_json_file(compressed_filepath))

    Errors = (tuf.FormatError, IOError)
    for bogus_arg in [b'a', 1, [b'a'], {'a':b'b'}]:
      self.assertRaises(Errors, tuf.util.load_json_file, bogus_arg)

  
  
  def test_C1_get_target_hash(self):
    # Test normal case. 
    expected_target_hashes = {
      '/file1.txt': 'e3a3d89eb3b70ce3fbce6017d7b8c12d4abd5635427a0e8a238f53157df85b3d',
      '/README.txt': '8faee106f1bb69f34aaf1df1e3c2e87d763c4d878cb96b91db13495e32ceb0b0',
      '/warehouse/file2.txt': 'd543a573a2cec67026eff06e75702303559e64e705eba06f65799baaf0424417'
    }
    for filepath, target_hash in six.iteritems(expected_target_hashes):
      self.assertTrue(tuf.formats.RELPATH_SCHEMA.matches(filepath))
      self.assertTrue(tuf.formats.HASH_SCHEMA.matches(target_hash))
      self.assertEqual(tuf.util.get_target_hash(filepath), target_hash)
   
    # Test for improperly formatted argument.
    self.assertRaises(tuf.FormatError, tuf.util.get_target_hash, 8)



  def test_C2_find_delegated_role(self):
    # Test normal case.  Create an expected role list, which is one of the
    # required arguments to 'find_delegated_role()'.
    role_list = [
      {
       "keyids": [
        "a394c28384648328b16731f81440d72243c77bb44c07c040be99347f0df7d7bf"
       ], 
       "name": "targets/warehouse", 
       "paths": [
        "/file1.txt", "/README.txt", '/warehouse/'
       ], 
       "threshold": 3
      },
      {
       "keyids": [
        "a394c28384648328b16731f81440d72243c77bb44c07c040be99347f0df7d7bf"
       ], 
       "name": "targets/tuf", 
       "paths": [
        "/updater.py", "formats.py", '/tuf/'
       ], 
       "threshold": 4
      }
    ]

    self.assertTrue(tuf.formats.ROLELIST_SCHEMA.matches(role_list))
    self.assertEqual(tuf.util.find_delegated_role(role_list, 'targets/tuf'), 1)
    self.assertEqual(tuf.util.find_delegated_role(role_list, 'targets/warehouse'), 0)
    # Test for non-existent role.  'find_delegated_role()' returns 'None'
    # if the role is not found.
    self.assertEqual(tuf.util.find_delegated_role(role_list, 'targets/non-existent'),
                                              None)

    # Test improperly formatted arguments.
    self.assertRaises(tuf.FormatError, tuf.util.find_delegated_role, 8, role_list)
    self.assertRaises(tuf.FormatError, tuf.util.find_delegated_role, 8, 'targets/tuf')

    # Test duplicate roles.
    role_list.append(role_list[1])
    self.assertRaises(tuf.RepositoryError, tuf.util.find_delegated_role, role_list,
                      'targets/tuf')

    # Test missing 'name' attribute (optional, but required by 
    # 'find_delegated_role()'.
    # Delete the duplicate role, and the remaining role's 'name' attribute. 
    del role_list[2]
    del role_list[0]['name']
    self.assertRaises(tuf.RepositoryError, tuf.util.find_delegated_role, role_list,
                      'targets/warehouse')
  
  
  
  def test_C3_paths_are_consistent_with_hash_prefixes(self):
    # Test normal case.
    path_hash_prefixes = ['e3a3', '8fae', 'd543']
    list_of_targets = ['/file1.txt', '/README.txt', '/warehouse/file2.txt']
    
    # Ensure the paths of 'list_of_targets' each have the epected path hash
    # prefix listed in 'path_hash_prefixes'. 
    for filepath in list_of_targets: 
      self.assertTrue(tuf.util.get_target_hash(filepath)[0:4] in path_hash_prefixes)

    self.assertTrue(tuf.util.paths_are_consistent_with_hash_prefixes(list_of_targets,
                                                            path_hash_prefixes))

    extra_invalid_prefix = ['e3a3', '8fae', 'd543', '0000']
    self.assertTrue(tuf.util.paths_are_consistent_with_hash_prefixes(list_of_targets,
                                                          extra_invalid_prefix))

    # Test improperly formatted arguments.
    self.assertRaises(tuf.FormatError,
                      tuf.util.paths_are_consistent_with_hash_prefixes, 8,
                      path_hash_prefixes) 
    
    self.assertRaises(tuf.FormatError,
                      tuf.util.paths_are_consistent_with_hash_prefixes,
                      list_of_targets, 8)
    
    self.assertRaises(tuf.FormatError,
                      tuf.util.paths_are_consistent_with_hash_prefixes,
                      list_of_targets, ['zza1'])
    
    # Test invalid list of targets.
    bad_target_path = '/file5.txt'
    self.assertTrue(tuf.util.get_target_hash(bad_target_path)[0:4] not in
                    path_hash_prefixes)
    self.assertFalse(tuf.util.paths_are_consistent_with_hash_prefixes([bad_target_path],
                                                            path_hash_prefixes))

    # Add invalid target path to 'list_of_targets'.
    list_of_targets.append(bad_target_path)
    self.assertFalse(tuf.util.paths_are_consistent_with_hash_prefixes(list_of_targets,
                                                            path_hash_prefixes))



  def test_C4_ensure_all_targets_allowed(self):
    # Test normal case.
    rolename = 'targets/warehouse'
    self.assertTrue(tuf.formats.ROLENAME_SCHEMA.matches(rolename))
    list_of_targets = ['/file1.txt', '/README.txt', '/warehouse/file2.txt'] 
    self.assertTrue(tuf.formats.RELPATHS_SCHEMA.matches(list_of_targets))
    parent_delegations = {"keys": {
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
    self.assertTrue(tuf.formats.DELEGATIONS_SCHEMA.matches(parent_delegations))

    tuf.util.ensure_all_targets_allowed(rolename, list_of_targets,
                                    parent_delegations)

    # The target files of 'targets' are always allowed.  'list_of_targets' and
    # 'parent_delegations' are not checked in this case. 
    tuf.util.ensure_all_targets_allowed('targets', list_of_targets,
                                    parent_delegations)
    
    # Test improperly formatted arguments.
    self.assertRaises(tuf.FormatError, tuf.util.ensure_all_targets_allowed,
                      8, list_of_targets, parent_delegations)
    
    self.assertRaises(tuf.FormatError, tuf.util.ensure_all_targets_allowed,
                      rolename, 8, parent_delegations)
    
    self.assertRaises(tuf.FormatError, tuf.util.ensure_all_targets_allowed,
                      rolename, list_of_targets, 8)

    # Test for invalid 'rolename', which has not been delegated by its parent,
    # 'targets'.
    self.assertRaises(tuf.RepositoryError, tuf.util.ensure_all_targets_allowed,
                      'targets/non-delegated_rolename', list_of_targets,
                      parent_delegations)

    # Test for target file that is not allowed by the parent role.
    self.assertRaises(tuf.ForbiddenTargetError, tuf.util.ensure_all_targets_allowed,
                      'targets/warehouse', ['file8.txt'], parent_delegations)
    
    self.assertRaises(tuf.ForbiddenTargetError, tuf.util.ensure_all_targets_allowed,
                      'targets/warehouse', ['file1.txt', 'bad-README.txt'],
                      parent_delegations)

    # Test for required attributes.
    # Missing 'paths' attribute.
    del parent_delegations['roles'][0]['paths']
    self.assertRaises(tuf.FormatError, tuf.util.ensure_all_targets_allowed,
                      'targets/warehouse', list_of_targets, parent_delegations)
    
    # Test 'path_hash_prefixes' attribute.
    path_hash_prefixes = ['e3a3', '8fae', 'd543']
    parent_delegations['roles'][0]['path_hash_prefixes'] = path_hash_prefixes
    
    # Test normal case for 'path_hash_prefixes'.
    tuf.util.ensure_all_targets_allowed('targets/warehouse', list_of_targets,
                                    parent_delegations)
   
    # Test target file with a path_hash_prefix that is not allowed in its
    # parent role.
    path_hash_prefix = tuf.util.get_target_hash('file5.txt')[0:4]
    self.assertTrue(path_hash_prefix not in parent_delegations['roles'][0]
                                                        ['path_hash_prefixes'])
    self.assertRaises(tuf.ForbiddenTargetError, tuf.util.ensure_all_targets_allowed,
                      'targets/warehouse', ['file5.txt'], parent_delegations)
  
  
  
  def test_C5_unittest_toolbox_make_temp_directory(self):
    # Verify that the tearDown function does not fail when
    # unittest_toolbox.make_temp_directory deletes the generated temp directory
    # here.
    temp_directory = self.make_temp_directory()
    os.rmdir(temp_directory)



  def test_c6_get_compressed_length(self):
   self.temp_fileobj.write(b'hello world')
   self.assertTrue(self.temp_fileobj.get_compressed_length() == 11)
   
   temp_file = tuf.util.TempFile()



# Run unit test.
if __name__ == '__main__':
  unittest.main()
