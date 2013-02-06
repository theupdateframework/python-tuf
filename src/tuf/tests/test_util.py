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
import gzip
import shutil
import tempfile
import unittest
import unittest_toolbox

import tuf
import tuf.util as util



class TestUtil(unittest_toolbox.Modified_TestCase):

  def setUp(self):
    unittest_toolbox.Modified_TestCase.setUp(self)
    self.temp_fileobj = util.TempFile()


  def tearDown(self):
    unittest_toolbox.Modified_TestCase.tearDown(self)
    self.temp_fileobj.close_temp_file()


  def _verify_temp_dir(self, config_temp_dir=None):
    # Patching 'tuf.conf.temporary_directory'.
    util.tuf.conf.temporary_directory = config_temp_dir

    if config_temp_dir is None:
      # 'config_temp_dir' needs to be set to default.
      config_temp_dir = tempfile.gettempdir()

    # Patching 'tempfile.TemporaryFile()' (by substituting 
    # temfile.TemporaryFile() with tempfile.mkstemp()) in order to get the 
    # directory of the stored tempfile object.
    util.tempfile.TemporaryFile = tempfile.mkstemp
    _temp_fileobj = util.TempFile()
    junk, _tempfilepath = _temp_fileobj.temporary_file
    _tempfile_dir = os.path.dirname(_tempfilepath)

    # In the case when 'config_temp_dir' is None or some other discrepancy,
    # '_temp_fileobj' needs to be closed manually since tempfile.mkstemp() 
    # was used.
    if os.path.exists(_tempfilepath):
      os.remove(_tempfilepath)

    return config_temp_dir, _tempfile_dir

 
  def test_init(self):
    """TempFile initialization"""
    # Goal: To verify temporary fileobj store directories.  

    # Test: Expected input verification.
    config_temp_dirs = [None, self.make_temp_directory()]
    for config_temp_dir in config_temp_dirs:
      config_temp_dir, actual_dir = self._verify_temp_dir(config_temp_dir)
      self.assertEquals(config_temp_dir, actual_dir)
    
    # Test: Unexpected input handling.
    config_temp_dirs = [self.random_string(), 123, ['a'], {'a':1}]
    for config_temp_dir in config_temp_dirs:
      config_temp_dir, actual_dir = self._verify_temp_dir(config_temp_dir)
      self.assertEquals(tempfile.gettempdir(), actual_dir)

   
  def testTempFile_read(self):
    pass


  def testTempFile_write(self):
    pass

  
  def testTempFile_move(self):
    """Expected behaviour of 'move' method"""
    # Destination directory to save the temporary file in.
    dest_temp_dir = self.make_temp_directory()
    dest_path = os.path.join(dest_temp_dir, self.random_string())
    self.temp_fileobj.write(self.random_string())

    self.temp_fileobj.move(dest_path)
    self.assertTrue(dest_path)


  def _compress_existing_file(self, filepath):
    """Compresses file 'filepath' and returns file path of 
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
    if os.path.exists(compressed_filepath):
      f = gzip.open(compressed_filepath, 'rb')
      file_content = f.read()
      f.close()
      return file_content
    else:
      print 'Decompression of '+repr(compressed_filepath)+' failed. '+\
            'Path does not exist.'
      sys.exit(1)


  def testTempFile_decompress_temp_file_object_1(self):
    """Expected behaviour of 'decompress_temp_file_object' method"""
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

    self.temp_fileobj.decompress_temp_file_object('gzip')  # Decompress!
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
    

  def testUtil_get_file_details_1(self):
    pass








# Run unit test.

suite = unittest.TestLoader().loadTestsFromTestCase(TestUtil)
unittest.TextTestRunner(verbosity=2).run(suite)
