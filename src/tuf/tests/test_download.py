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

NOTE: launch test_download_server.py before running.  
"""

import tuf
import tuf.download as download
import tuf.tests.unittest_toolbox as unittest_toolbox

import os
import time
import unittest
import hashlib
import urllib2
import SimpleHTTPServer
import SocketServer


class TestDownload(unittest_toolbox.Modified_TestCase):
  def setUp(self):
    """ 
    Create a temporary file and launch a simple server in the
    current working directory.
    """

    unittest_toolbox.Modified_TestCase.setUp(self)

    # Making a temporary file.
    current_dir = os.getcwd()
    target_filepath = \
    self.make_temp_data_file(directory=current_dir)
    self.target_length = len(target_filepath)
    self.target_fileobj = open(target_filepath, 'r')

    print target_filepath
    
    # Launch a SimpleHTTPServer (servers files in the current dir).
    # TODO: CREATE A SAMPLE SERVER MODULE with TWO TO LAUNCH AND CLOSE THE SERVER. 
    PORT = 8080
    Handler = SimpleHTTPServer.SimpleHTTPRequestHandler
    self.httpd = SocketServer.TCPServer(("", PORT), Handler)
    self.httpd.serve_forever(poll_interval=0.1)
    self.url = "http://localhost:"+str(PORT)+"/"+target_filepath

    print self.url

    # Computing hash of the target file.
    # md5 algorithm is used here, any algorithm can be used. If changed to some 
    # other algorithm don't forget to edit the key in 'self.target_hash' 
    # dictionary.
    d = hashlib.md5()
    d.update(self.target_filepath)
    digest = self.hexdigest()
    self.target_hash = {"md5":digest}  



  def tearDown(self):
    print 'check 2'
    unittest_toolbox.Modified_TestCase.tearDown(self)
    self.httpd.shutdown()
    self.target_data.close()



  def test_download_url_to_tempfileobj(self):
    # Test: normal case.
    print 'check 0'
    temp_fileobj = download.download_url_to_tempfileobj(self.url, 
                                                        self.target_hash,
                                                        self.target_length)
    print 'check 1'
    self.assertEquals(self.target_length, len(temp_fileobj))
    self.assertEquals(self.target_fileobj, temp_fileobj)






 
'''
#TARGET = 'test_target_file.txt'
#PORT = 8080
#EXC = (tuf.FormatError, tuf.DownloadError, tuf.BadHashError, 
#       urllib2.URLError, urllib2.HTTPError)


# Unit tests
class TestDownload_url_to_tempfileobj(unittest.TestCase):
  def setUp(self):
    """
    <Initialized Variables>
      self.url:
        A url string that composed of localhost, port # and target name.
      self.target_file:
        A string of an entire target file.
      target_length:
        Integer value representing the length of the target file.
      self.target_hash:
        A dictionary consisting of the hash algorithm as a key and a hexdigest 
        as its value.
      self.digest:
        A hexadecimal hash value.
      
    """

    if not os.path.isfile(TARGET):
      self._fileobject = open(TARGET, 'w')
      data = 'file containing data'
      self._fileobject.write(data)
      self._fileobject.close()

    else:
      msg = '\'TARGET\': '+TARGET+'. File already exists! Try renaming TARGET.'
      raise tuf.Error, msg

    self.url = "http://localhost:"+str(PORT)+"/"+TARGET
 
    self._fileobject = open(TARGET, 'r')
    self.target_file = self._fileobject.read()
    self.target_length = len(self.target_file)
  
    # Computing hash of the target file.
    # md5 algorithm is used here, any algorithm can be used. If changed to some 
    # other algorithm don't forget to edit the key in 'self.target_hash' 
    # dictionary.
    self.d = hashlib.md5()
    self.d.update(self.target_file)
    self.digest = self.d.hexdigest()
    self.target_hash = {"md5":self.digest}  
  
  
  def tearDown(self):
    self._fileobject.close()
    os.remo













  def testNormal(self):
    # temp_file is a 'file-like' object
    # I took measurement of performance when using 'auto_flush = False' vs. 
    # 'auto_flush = True' in the download_url_to_file(). No change was observed.
    star_cpu = time.clock()
    star_real = time.time()
    _temp_file = tuf.download.download_url_to_tempfileobj(self.url, 
                                                          self.target_hash,
                                                          self.target_length)
    end_cpu = time.clock()
    end_real = time.time()
    print "Performance cpu time: "+str(end_cpu - star_cpu)
    print "Performance real time: "+str(end_real - star_real)
    _temp_file.seek(0)
    data = _temp_file.read()
    _temp_file.close_temp_file()
    self.assertEqual(data, self.target_file)


  def testWrongLength_lessthenactual(self):
    wronglength = self.target_length - 1
    self.assertRaises(tuf.DownloadError, 
                      tuf.download.download_url_to_tempfileobj,
                      self.url, self.target_hash, wronglength)


  def testWrongLength(self):
    wronglength = self.target_length + 1
    self.assertRaises(tuf.DownloadError, 
                      tuf.download.download_url_to_tempfileobj,
                      self.url, self.target_hash, wronglength)


  def testWrongHash(self):
    wronghash = {"md5":"fffffffffffffff"}
    self.assertRaises(tuf.DownloadError, 
                      tuf.download.download_url_to_tempfileobj,
                      self.url, wronghash, self.target_length)


  def testEmptyArgs_url(self):
    url = None
    self.assertRaises(EXC, tuf.download.download_url_to_tempfileobj,
                      url, self.target_hash, self.target_length)


  def testEmptyArgs_hashes(self):
    _hash = None
    self.assertRaises(EXC, tuf.download.download_url_to_tempfileobj,
                      self.url, _hash, self.target_length)
  

  def testEmptyArgs_length(self):
    length = None
    self.assertRaises(EXC, tuf.download.download_url_to_tempfileobj,
                      self.url, self.target_hash,length)


  def testWrongFile(self):
    url = self.url = "http://localhost:"+str(PORT)+"/"+"non_existing.sh"
    self.assertRaises(EXC, tuf.download.download_url_to_tempfileobj,
                      url, self.target_hash, self.target_length)


  def testWrongPort(self):
    wrongPort = 8081
    url = self.url = "http://localhost:"+str(wrongPort)+"/"+TARGET
    self.assertRaises(EXC, tuf.download.download_url_to_tempfileobj,
                      url, self.target_hash, self.target_length)


  # This function takes time to complete.
  def testWrongURL(self):
    url = self.url = "http://192.168.12.12:"+str(PORT)+"/"+"non_existing.sh"
    self.assertRaises(EXC, tuf.download.download_url_to_tempfileobj,
                      url, self.target_hash, self.target_length)
'''


# Run the unittests.  
if __name__ == '__main__':
  unittest.main()

