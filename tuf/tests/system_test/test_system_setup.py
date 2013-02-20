"""
<Program Name>
  repository_setup.py

<Author>
  Konstantin Andrianov

<Started>
  February 15, 2012

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Setup a repository structure.

simple server -->          repository_dir
                                 |
                     --------------------------
                     |                        |
            repository_file1path     repository_file2path

  This modules uses unittest module to provide easy setup and tear down
  capability.

Repository + Server    <--------------->    Client
Repository + TUF + Server    <--------->    TUF + Client

"""

# Repository setup.  Repository will consist of a temporary  directory
# with some files in it.

import os
import sys
import time
import shutil
import random
import urllib2
import tempfile
import unittest
import subprocess


class TestCase(unittest.TestCase):
  def setUp(self):
    unittest.TestCase.setUp(self)

    # Repository directory with few files in it.
    self.repository_dir = tempfile.mkdtemp(dir=os.getcwd())
    repository_file1 = tempfile.mkstemp(dir=self.repository_dir)
    repository_file2 = tempfile.mkstemp(dir=self.repository_dir)
    self.repository_file1path = os.path.basename(repository_file1[1])
    self.repository_file2path = os.path.basename(repository_file2[1])
    fileobj = open(repository_file1[1], 'wb')
    fileobj.write('System Test File 1')
    fileobj.close()
    fileobj = open(repository_file2[1], 'wb')
    fileobj.write('System Test File 1')
    fileobj.close()

    # Start a simple server pointing to the repository directory.
    port = random.randint(30000, 45000)
    command = ['python', '-m', 'SimpleHTTPServer', str(port)]
    self.server_process = subprocess.Popen(command, stderr=subprocess.PIPE)
    relative_repository_dir = os.path.basename(self.repository_dir)
    self.url = 'http://localhost:'+str(port)+'/'+relative_repository_dir+'/'

    # NOTE: The delay is needed make up for asynchronous subprocess.
    # Otherwise following error might be raised:
    #    <urlopen error [Errno 111] Connection refused>
    time.sleep(.1)



  def tearDown(self):
    unittest.TestCase.tearDown(self)

    if self.server_process.returncode is None:
      self.server_process.kill()

    # Removing repository directory.
    shutil.rmtree(self.repository_dir)



  @staticmethod
  def _open_connection(url):
    try:
      request = urllib2.Request(url)
      connection = urllib2.urlopen(request)
    except Exception, e:
      print 'Couldn\'t open connection: ' + repr(e)
      sys.exit(1)
    return connection



  def client_download(self, filename):
    connection = self._open_connection(self.url+filename)
    return connection.read()



  # Quick internal test to see if everything runs smoothly.
  def test_client_download(self):
    data = self.client_download(self.repository_file1path)
    self.assertEquals(data, 'System Test File 1')



if __name__=='__main__':
  unittest.main()