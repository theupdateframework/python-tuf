#!/usr/bin/env python

"""
<Program Name>
  test_util.py

<Author>
  Konstantin Andrianov

<Started>
  February 1, 2013

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  util.py unit tests.

"""

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
import tuf.util as util
import tuf.tests.unittest_toolbox as unittest_toolbox

logger = logging.getLogger('tuf.test_util')


class TestUtil(unittest_toolbox.Modified_TestCase):

  def setUp(self):
    unittest_toolbox.Modified_TestCase.setUp(self)
    self.temp_fileobj = util.TempFile()

		

  def tearDown(self):
    unittest_toolbox.Modified_TestCase.tearDown(self)
    self.temp_fileobj.close_temp_file()



  def test_A1_tempfile_close_temp_file(self):
    # Was the temporary file closed?
    self.temp_fileobj.close_temp_file()
    self.assertTrue(self.temp_fileobj.temporary_file.closed)



  def _extract_tempfile_directory(self, config_temp_dir=None):
    """[Helper] Takes a directory (essentially specified in the config.py as
       'temporary_directory') and substitutes tempfile.TemporaryFile() with
       tempfile.mkstemp() in order to extract actual directory of the stored  
       tempfile.  Returns the config's temporary directory (or default temp
       directory) and actual directory."""
    # Patching 'tuf.conf.temporary_directory'.
    util.tuf.conf.temporary_directory = config_temp_dir

    if config_temp_dir is None:
      # 'config_temp_dir' needs to be set to default.
      config_temp_dir = tempfile.gettempdir()

    # Patching 'tempfile.TemporaryFile()' (by substituting 
    # temfile.TemporaryFile() with tempfile.mkstemp()) in order to get the 
    # directory of the stored tempfile object.
    saved_tempfile_TemporaryFile = util.tempfile.NamedTemporaryFile
    util.tempfile.NamedTemporaryFile = tempfile.mkstemp
    _temp_fileobj = util.TempFile()
    util.tempfile.NamedTemporaryFile = saved_tempfile_TemporaryFile
    junk, _tempfilepath = _temp_fileobj.temporary_file
    _tempfile_dir = os.path.dirname(_tempfilepath)

    # In the case when 'config_temp_dir' is None or some other discrepancy,
    # '_temp_fileobj' needs to be closed manually since tempfile.mkstemp() 
    # was used.
    if os.path.exists(_tempfilepath):
      os.remove(_tempfilepath)

    return config_temp_dir, _tempfile_dir


 
  def test_A2_tempfile_init(self):
    # Goal: Verify that tempfile is stored in an appropriate temp directory.  

    # Test: Expected input verification.
    config_temp_dirs = [None, self.make_temp_directory()]
    for config_temp_dir in config_temp_dirs:
      config_temp_dir, actual_dir = \
      self._extract_tempfile_directory(config_temp_dir)
      self.assertEquals(config_temp_dir, actual_dir)
    
    # Test: Unexpected input handling.
    config_temp_dirs = [self.random_string(), 123, ['a'], {'a':1}]
    for config_temp_dir in config_temp_dirs:
      config_temp_dir, actual_dir = \
      self._extract_tempfile_directory(config_temp_dir)
      self.assertEquals(tempfile.gettempdir(), actual_dir)


   
  def test_A3_tempfile_read(self):
    filepath = self.make_temp_data_file(data = '1234567890')
    fileobj = open(filepath, 'rb')

    # Patching 'temp_fileobj.temporary_file'.
    self.temp_fileobj.temporary_file = fileobj

    # Test: Expected input.
    self.assertEquals(self.temp_fileobj.read(), '1234567890')
    self.assertEquals(self.temp_fileobj.read(4), '1234')

    # Test: Unexpected input.
    for bogus_arg in ['abcd', ['abcd'], {'a':'a'}, -100]:
      self.assertRaises(tuf.FormatError, self.temp_fileobj.read, bogus_arg)



  def test_A4_tempfile_write(self):
    data = self.random_string()
    self.temp_fileobj.write(data)
    self.assertEquals(data, self.temp_fileobj.read())



  def test_A5_tempfile_move(self):
    # Destination directory to save the temporary file in.
    dest_temp_dir = self.make_temp_directory()
    dest_path = os.path.join(dest_temp_dir, self.random_string())
    self.temp_fileobj.write(self.random_string())
    self.temp_fileobj.move(dest_path)
    self.assertTrue(dest_path)



  def _compress_existing_file(self, filepath):
    """[Helper]Compresses file 'filepath' and returns file path of 
       the compresses file."""
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
      print 'Compression of '+repr(filepath)+' failed. Path does not exist.'
      sys.exit(1)
 


  def _decompress_file(self, compressed_filepath):
    """[Helper]"""
    if os.path.exists(compressed_filepath):
      f = gzip.open(compressed_filepath, 'rb')
      file_content = f.read()
      f.close()
      return file_content
    else:
      print 'Decompression of '+repr(compressed_filepath)+' failed. '+\
            'Path does not exist.'
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
    self.assertEquals(self.temp_fileobj.read(), fileobj.read())

    # Checking the content of the TempFile's '_orig_file' instance.
    _orig_data_file = \
    self.make_temp_data_file(data=self.temp_fileobj._orig_file.read())
    data_in_orig_file = self._decompress_file(_orig_data_file)
    fileobj.seek(0)
    self.assertEquals(data_in_orig_file, fileobj.read())

    # Try decompressing once more.
    self.assertRaises(tuf.Error, 
                      self.temp_fileobj.decompress_temp_file_object,'gzip')
    


  def test_B1_get_file_details(self):
    # Goal: Verify proper output given certain expected/unexpected input.

    # Making a temporary file.
    filepath = self.make_temp_data_file()

    # Computing the hash and length of the tempfile.
    digest_object = tuf.hash.digest_filename(filepath, algorithm='sha256')
    file_hash = {'sha256' : digest_object.hexdigest()}
    file_length = os.path.getsize(filepath)
 
    # Test: Expected input.
    self.assertEquals(util.get_file_details(filepath), (file_length, file_hash))

    # Test: Incorrect input.
    bogus_inputs = [self.random_string(), 1234, [self.random_string()],
                    {'a', 'a'}, None]
    for bogus_input in bogus_inputs:
      if isinstance(bogus_input, basestring):
        self.assertRaises(tuf.Error, util.get_file_details, bogus_input)
      else:
        self.assertRaises(tuf.FormatError, util.get_file_details, bogus_input)

 
    
  def  test_B2_ensure_parent_dir(self):
    existing_parent_dir = self.make_temp_directory()
    non_existing_parent_dir = os.path.join(existing_parent_dir, 'a', 'b')

    for parent_dir in [existing_parent_dir, non_existing_parent_dir, 12, [3]]:
      if isinstance(parent_dir, basestring):
        util.ensure_parent_dir(os.path.join(parent_dir, 'a.txt'))
        self.assertTrue(os.path.isdir(parent_dir))
      else:
        self.assertRaises(tuf.FormatError, util.ensure_parent_dir, parent_dir)
      


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
    data = ['a', {'b': ['c', None, 30.3, 29]}]
    json_string = util.json.dumps(data)
    self.assertEquals(data, util.load_json_string(json_string))
 


  def  test_B6_load_json_file(self):
    data = ['a', {'b': ['c', None, 30.3, 29]}]
    filepath = self.make_temp_file()
    fileobj = open(filepath, 'wb')
    util.json.dump(data, fileobj)
    fileobj.close()
    self.assertEquals(data, util.load_json_file(filepath))
    Errors = (tuf.FormatError, IOError)
    for bogus_arg in ['a', 1, ['a'], {'a':'b'}]:
      self.assertRaises(Errors, util.load_json_file, bogus_arg)



# Run unit test.
if __name__ == '__main__':
  unittest.main()
