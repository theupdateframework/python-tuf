#!/usr/bin/env python

"""
<Program>
  test_download.py
  
<Author>
  Konstantin Andrianov.
  
<Started>
  March 26, 2012.
  
<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Unit test for 'download.py'.

  NOTE: Make sure test_download.py is ran in 'tuf/tests/' directory.
  Otherwise, module that launches simple server would not be found.  
"""

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import hashlib
import logging
import os
import random
import subprocess
import time
import unittest

import tuf
import tuf.conf as conf
import tuf.download as download
import tuf.log
import tuf.unittest_toolbox as unittest_toolbox
import tuf._vendor.six as six

logger = logging.getLogger('tuf.test_download')


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
    logger.info('\n\tServer process started.')
    logger.info('\tServer process id: '+str(self.server_proc.pid))
    logger.info('\tServing on port: '+str(self.PORT))
    junk, rel_target_filepath = os.path.split(target_filepath)
    self.url = 'http://localhost:'+str(self.PORT)+'/'+rel_target_filepath

    # NOTE: Following error is raised if delay is not applied:
    #    <urlopen error [Errno 111] Connection refused>
    time.sleep(1)

    # Computing hash of target file data.
    m = hashlib.md5()
    m.update(self.target_data.encode('utf-8'))
    digest = m.hexdigest()
    self.target_hash = {'md5':digest}  


  # Stop server process and perform clean up.
  def tearDown(self):
    unittest_toolbox.Modified_TestCase.tearDown(self)
    if self.server_proc.returncode is None:
      logger.info('\tServer process '+str(self.server_proc.pid)+' terminated.')
      self.server_proc.kill()
    self.target_fileobj.close()


  # Test: Normal case.
  def test_download_url_to_tempfileobj(self):

    download_file = download.safe_download

    temp_fileobj = download_file(self.url, self.target_data_length)
    self.assertEqual(self.target_data, temp_fileobj.read().decode('utf-8'))
    self.assertEqual(self.target_data_length, len(temp_fileobj.read()))
    temp_fileobj.close_temp_file()


  # Test: Incorrect lengths.
  def test_download_url_to_tempfileobj_and_lengths(self):

    # NOTE: We catch tuf.BadHashError here because the file, shorter by a byte,
    # would not match the expected hashes. We log a warning when we find that
    # the server-reported length of the file does not match our
    # required_length. We also see that STRICT_REQUIRED_LENGTH does not change
    # the outcome of the previous test.
    download.safe_download(self.url, self.target_data_length - 1)
    download.unsafe_download(self.url, self.target_data_length - 1)

    # NOTE: We catch tuf.DownloadLengthMismatchError here because the
    # STRICT_REQUIRED_LENGTH, which is True by default, mandates that we must
    # download exactly what is required.
    self.assertRaises(tuf.DownloadLengthMismatchError, download.safe_download,
    #self.assertRaises(tuf.SlowRetrievalError, download.safe_download,
                      self.url, self.target_data_length + 1)

    # NOTE: However, we do not catch a tuf.DownloadLengthMismatchError here for
    # the same test as the previous one because we have disabled
    # STRICT_REQUIRED_LENGTH.
    temp_fileobj = download.unsafe_download(self.url,
                                            self.target_data_length + 1)
    self.assertEqual(self.target_data, temp_fileobj.read().decode('utf-8'))
    self.assertEqual(self.target_data_length, len(temp_fileobj.read()))
    temp_fileobj.close_temp_file()


  def test_download_url_to_tempfileobj_and_performance(self):

    """
    # Measuring performance of 'auto_flush = False' vs. 'auto_flush = True'
    # in download._download_file() during write. No change was observed.
    star_cpu = time.clock()
    star_real = time.time()

    temp_fileobj = download_file(self.url, 
                                 self.target_data_length)

    end_cpu = time.clock()
    end_real = time.time()  
 
    self.assertEqual(self.target_data, temp_fileobj.read())
    self.assertEqual(self.target_data_length, len(temp_fileobj.read()))
    temp_fileobj.close_temp_file()

    print "Performance cpu time: "+str(end_cpu - star_cpu)
    print "Performance real time: "+str(end_real - star_real)

    # TODO: [Not urgent] Show the difference by setting write(auto_flush=False)
    """


  # Test: Incorrect/Unreachable URLs.
  def test_download_url_to_tempfileobj_and_urls(self):

    download_file = download.safe_download

    self.assertRaises(tuf.FormatError,
                      download_file, None, self.target_data_length)

    self.assertRaises(ValueError,
                      download_file,
                      self.random_string(), self.target_data_length)

    self.assertRaises(six.moves.urllib.error.HTTPError,
                      download_file,
                      'http://localhost:' + str(self.PORT) + '/' + self.random_string(), 
                      self.target_data_length)

    self.assertRaises(six.moves.urllib.error.URLError,
                      download_file,
                      'http://localhost:' + str(self.PORT+1) + '/' + self.random_string(), 
                      self.target_data_length)
 


  def test__get_opener(self):
    # Test normal case.
    # A simple https server should be used to test the rest of the optional
    # ssl-related functions of 'tuf.download.py'.
    fake_cacert = self.make_temp_data_file()
    
    with open(fake_cacert, 'wt') as file_object:
      file_object.write('fake cacert')
    
    tuf.conf.ssl_certificates = fake_cacert
    tuf.download._get_opener('https')
    


# Run unit test.
if __name__ == '__main__':
  unittest.main()
