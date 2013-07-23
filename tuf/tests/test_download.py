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
import tuf.download as download
import tuf.tests.unittest_toolbox as unittest_toolbox

import os
import sys
import time
import random
import hashlib
import logging
import unittest
import subprocess
import SocketServer
import SimpleHTTPServer

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


  # Unit Test.
  def test_download_url_to_tempfileobj(self):
    # Test: Normal cases without supplying hash arguments.

    temp_fileobj = download.download_url_to_tempfileobj(self.url,
                      required_length=self.target_data_length)
    self.assertEquals(self.target_data, temp_fileobj.read())
    self.assertEquals(self.target_data_length, len(temp_fileobj.read()))
    temp_fileobj.close_temp_file();

    # Test: Normal case.
    temp_fileobj = download.download_url_to_tempfileobj(self.url,
                      required_hashes=self.target_hash, 
                      required_length=self.target_data_length)
    self.assertEquals(self.target_data, temp_fileobj.read())
    self.assertEquals(self.target_data_length, len(temp_fileobj.read()))
    temp_fileobj.close_temp_file()

    # Test: Incorrect length.
    self.assertRaises(tuf.DownloadError, 
                      download.download_url_to_tempfileobj, self.url,
                      required_hashes=self.target_hash, 
                      required_length=self.target_data_length - 1)

    self.assertRaises(tuf.DownloadError, 
                      download.download_url_to_tempfileobj, self.url,
                      required_hashes=self.target_hash, 
                      required_length=self.target_data_length + 1)

    # Test: Incorrect hashs.
    self.assertRaises(tuf.DownloadError, 
                      download.download_url_to_tempfileobj, self.url,
                      required_hashes={'md5':self.random_string()},
                      required_length=self.target_data_length)

    # Test: Incorrect/Unreachable url.
    self.assertRaises(tuf.FormatError,
                      download.download_url_to_tempfileobj, None,
                      required_hashes=self.target_hash, 
                      required_length=self.target_data_length)

    self.assertRaises(tuf.DownloadError,
                      download.download_url_to_tempfileobj,
                      self.random_string(),
                      required_hashes=self.target_hash, 
                      required_length=self.target_data_length)

    self.assertRaises(tuf.DownloadError,
                      download.download_url_to_tempfileobj,
                      'http://localhost:'+str(self.PORT)+'/'+self.random_string(),
                      required_hashes=self.target_hash, 
                      required_length=self.target_data_length)

    self.assertRaises(tuf.DownloadError,
                      download.download_url_to_tempfileobj,
                      'http://localhost:'+str(self.PORT+1)+'/'+self.random_string(),
                      required_hashes=self.target_hash, 
                      required_length=self.target_data_length)

    # Test: Set the required_length to default value.

    temp_fileobj = download.download_url_to_tempfileobj(self.url,required_length=2000,
                                                      SET_DEFAULT_REQUIRED_LENGTH=True)
    self.assertEquals(self.target_data, temp_fileobj.read())
    self.assertEquals(self.target_data_length, len(temp_fileobj.read()))
    temp_fileobj.close_temp_file();

    """
    # Measuring performance of 'auto_flush = False' vs. 'auto_flush = True'
    # in download_url_to_tempfileobj() during write. No change was observed.
    star_cpu = time.clock()
    star_real = time.time()

    temp_fileobj = download.download_url_to_tempfileobj(self.url,
                      required_hashes=self.target_hash, 
                      required_length=self.target_data_length)

    end_cpu = time.clock()
    end_real = time.time()  
 
    self.assertEquals(self.target_data, temp_fileobj.read())
    self.assertEquals(self.target_data_length, len(temp_fileobj.read()))
    temp_fileobj.close_temp_file()

    print "Performance cpu time: "+str(end_cpu - star_cpu)
    print "Performance real time: "+str(end_real - star_real)

    # TODO: [Not urgent] Show the difference by setting write(auto_flush=False)
    """



# Run unit test.
suite = unittest.TestLoader().loadTestsFromTestCase(TestDownload)
unittest.TextTestRunner(verbosity=2).run(suite)
