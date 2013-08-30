#!/usr/bin/env python

"""
<Program>
  test_download.py
  
<Author>
  Konstantin Andrianov
  
<Started>
  March 26, 2012.
  
<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Test download.py module.


NOTE: Make sure test_download.py is ran in 'tuf/tests/' directory.
Otherwise, module that launches simple server would not be found.  
"""

import tuf
import tuf.conf as conf
import tuf.download as download
import tuf.tests.unittest_toolbox as unittest_toolbox

import hashlib
import logging
import os
import random
import subprocess
import time
import unittest


# Disable/Enable logging.  Comment-out to Enable logging.
logging.getLogger('tuf')
logging.disable(logging.CRITICAL)


class TestDownload(unittest_toolbox.Modified_TestCase):
  def setUp(self):
    """ 
    Create a temporary file and launch a simple server in the
    current working directory.
    """

    unittest_toolbox.Modified_TestCase.setUp(self)

    # Making a temporary file.
    current_dir = os.getcwd()
    target_filepath = self.make_temp_data_file(directory=current_dir)
    self.target_fileobj = open(target_filepath, 'r')
    self.target_data = self.target_fileobj.read()
    self.target_data_length = len(self.target_data)

    # Launch a SimpleHTTPServer (servers files in the current dir).
    self.PORT = random.randint(30000, 45000)
    command = ['python', 'simple_server.py', str(self.PORT)]
    self.server_proc = subprocess.Popen(command, stderr=subprocess.PIPE)
    print '\n\tServer process started.'
    print '\tServer process id: '+str(self.server_proc.pid)
    print '\tServing on port: '+str(self.PORT)
    junk, rel_target_filepath = os.path.split(target_filepath)
    self.url = 'http://localhost:'+str(self.PORT)+'/'+rel_target_filepath

    # NOTE: Following error is raised if delay is not applied:
    #    <urlopen error [Errno 111] Connection refused>
    time.sleep(.1)

    # Computing hash of target file data.
    m = hashlib.md5()
    m.update(self.target_data)
    digest = m.hexdigest()
    self.target_hash = {'md5':digest}  


  # Stop server process and perform clean up.
  def tearDown(self):
    unittest_toolbox.Modified_TestCase.tearDown(self)
    if self.server_proc.returncode is None:
      print '\tServer process '+str(self.server_proc.pid)+' terminated.'
      self.server_proc.kill()
    self.target_fileobj.close()


  # Test: Normal case.
  def test_safe_and_unsafe_download_url_to_tempfileobj(self):
    
    # Test the safe mode download function.
    download_file = download.safe_download_url_to_tempfileobj

    temp_fileobj = download_file(self.url, self.target_data_length,
                                 required_hashes=self.target_hash)
    self.assertEquals(self.target_data, temp_fileobj.read())
    self.assertEquals(self.target_data_length, len(temp_fileobj.read()))
    temp_fileobj.close_temp_file()
    
    # Test the unsafe mode download function.
    download_file = download.unsafe_download_url_to_tempfileobj

    temp_fileobj = download_file(self.url)
    self.assertEquals(self.target_data, temp_fileobj.read())
    self.assertEquals(self.target_data_length, len(temp_fileobj.read()))
    temp_fileobj.close_temp_file()


  # Test: Incorrect hashes.
  def test_safe_download_url_to_tempfileobj_and_hashes(self):
    
    # Only safe mode download function has required_hashes passes in.
    download_file = download.safe_download_url_to_tempfileobj

    # Test: Incorrect cases without supplying hash arguments.
    self.assertRaises(tuf.FormatError,
                      download_file, self.url, self.target_data_length, None)

    # What happens when we pass bad hashes to check the downloaded file?
    self.assertRaises(tuf.BadHashError,
                      download_file, self.url, self.target_data_length,
                      required_hashes={'md5':self.random_string()})


  # Test: Incorrect lengths.
  def test_safe_download_url_to_tempfileobj_and_lengths(self):
    
    download_file = download.safe_download_url_to_tempfileobj

    # NOTE: We catch tuf.BadHashError here because the file, shorter by a byte,
    # would not match the expected hashes. We log a warning when we find that
    # the server-reported length of the file does not match our
    # required_length.
    self.assertRaises(tuf.BadHashError, 
                      download_file, self.url, self.target_data_length - 1,
                      required_hashes=self.target_hash)

    # Test: Incorrect cases without supplying length arguments.
    self.assertRaises(tuf.FormatError,
                      download_file, self.url, None, self.target_hash)

    # NOTE: We catch tuf.DownloadError here because the STRICT_REQUIRED_LENGTH,
    # which is True by default, mandates that we must download exactly what is
    # required.
    exception_message = 'Downloaded '+str(self.target_data_length)+\
                        ' bytes, but expected '+\
                        str(self.target_data_length+1)+\
                        ' bytes. There is a difference of 1 bytes!'
    self.assertRaisesRegexp(tuf.DownloadError, exception_message,
                      download_file, self.url, self.target_data_length + 1,
                      required_hashes=self.target_hash)


  # Test: Incorrect cases without supplying length and hashes arguments.    
  def test_safe_download_url_to_tempfileobj_without_lengths_and_hashes(self):

    download_file = download.safe_download_url_to_tempfileobj

    self.assertRaises(tuf.FormatError,
                      download_file, self.url, None, None)


  def test_safe_download_url_to_tempfileobj_and_performance(self):

    download_file = download.safe_download_url_to_tempfileobj

    """
    # Measuring performance of 'auto_flush = False' vs. 'auto_flush = True'
    # in download_url_to_tempfileobj() during write. No change was observed.
    star_cpu = time.clock()
    star_real = time.time()

    temp_fileobj = download_file(self.url, 
                                 self.target_data_length,
                                 required_hashes=self.target_hash)

    end_cpu = time.clock()
    end_real = time.time()  
 
    self.assertEquals(self.target_data, temp_fileobj.read())
    self.assertEquals(self.target_data_length, len(temp_fileobj.read()))
    temp_fileobj.close_temp_file()

    print "Performance cpu time: "+str(end_cpu - star_cpu)
    print "Performance real time: "+str(end_real - star_real)

    # TODO: [Not urgent] Show the difference by setting write(auto_flush=False)
    """


  # Test: Incorrect/Unreachable URLs.
  def test_safe_and_unsafe_download_url_to_tempfileobj_and_urls(self):

    # Test: safe download function.
    download_file = download.safe_download_url_to_tempfileobj

    self.assertRaises(tuf.FormatError,
                      download_file, None, self.target_data_length,
                      required_hashes=self.target_hash)

    self.assertRaises(tuf.DownloadError,
                      download_file,
                      self.random_string(), self.target_data_length,
                      required_hashes=self.target_hash)

    self.assertRaises(tuf.DownloadError,
                      download_file,
                      'http://localhost:'+str(self.PORT)+'/'+self.random_string(), 
                      self.target_data_length,
                      required_hashes=self.target_hash)

    self.assertRaises(tuf.DownloadError,
                      download_file,
                      'http://localhost:'+str(self.PORT+1)+'/'+self.random_string(), 
                      self.target_data_length,
                      required_hashes=self.target_hash)

    # Test: unsafe download function.
    download_file = download.unsafe_download_url_to_tempfileobj

    self.assertRaises(tuf.FormatError, download_file, None)

    self.assertRaises(tuf.DownloadError, download_file, self.random_string())

    self.assertRaises(tuf.DownloadError, download_file,
                      'http://localhost:'+str(self.PORT)+'/'+self.random_string())

    self.assertRaises(tuf.DownloadError, download_file,
                      'http://localhost:'+str(self.PORT+1)+'/'+self.random_string())

# Run unit test.
suite = unittest.TestLoader().loadTestsFromTestCase(TestDownload)
unittest.TextTestRunner(verbosity=2).run(suite)


