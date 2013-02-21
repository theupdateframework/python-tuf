"""
<Program Name>
  test_system_setup.py

<Author>
  Konstantin Andrianov

<Started>
  February 15, 2012

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Provide automatic setup and clean-up functionality.  This module is based on
  python's unittest.  In fact the main class TestCase inherits from 
  unittest.TestCase.

simple server -->          repository_dir
                                 |
                     --------------------------
                     |                        |
                  filename1               filename2

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
import logging
import tempfile
import unittest
import subprocess

import tuf.repo.signerlib as signerlib

# Disable/Enable logging.  Comment-out to Enable logging.
logging.getLogger('tuf')
logging.disable(logging.CRITICAL)


class TestCase(unittest.TestCase):
  """
  <Class Variables>
    TUF:
      Indicates whether or not TUF structure should be implemented.

  <Instance Variables>
    repository_dir:
      Repository directory, where updates are located.
    
    filename#:
      Name of the update, which is located in the repository directory.
    
    server_process:
      A subprocess object.

    url:
      URL pointing to the repository directory ('repository_dir').


    TUF related instance variables.  Refer to the diagram in tuf_setUp().

    tuf_repository_dir:
      A tuf repository that contains all tuf related directories, such as
      metadata, targets, and keystore. (Read docs on how to handle keys!)

    tuf_metadata_dir:
      Metadata directory that contains metadata files and is located in the 
      tuf repository directory ('tuf_repository_dir').

    tuf_keystore_dir:
      Contains all tuf keys, i.e. keys that are used to sign metadata roles.
      It's located in the tuf repository directory ('tuf_repository_dir').

    tuf_targets_dir:
      All target files (updates) are stored in tuf targets directory.
      It's populated using the content 'repository_dir' (devel's repository).
      It's located in the tuf repository directory ('tuf_repository_dir').

    tuf_client_dir:
      Client side tuf directory.  It contains current and previous metadata
      files.
    
    tuf_client_metadata_dir:
      Contains current and previous versions of metadata files.

    Note: metadata files are root.txt, targets.txt, release.txt and
    timestamp.txt.  There could be more metadata files such us mirrors.txt.
    The metadata files are signed by their corresponding roles i.e. root,
    targets etc.      

  """

  TUF = True

  def setUp(self):
    unittest.TestCase.setUp(self)

    # Repository directory with few files in it.
    self.repository_dir = tempfile.mkdtemp(dir=os.getcwd())
    repository_file1 = tempfile.mkstemp(dir=self.repository_dir)
    repository_file2 = tempfile.mkstemp(dir=self.repository_dir)
    self.filename1 = os.path.basename(repository_file1[1])
    self.filename2 = os.path.basename(repository_file2[1])
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

    if self.TUF is True:
      self.tuf_setUp()



  def tearDown(self):
    unittest.TestCase.tearDown(self)

    if self.server_process.returncode is None:
      print 'Server terminated.'
      self.server_process.kill()

    # Removing repository directory.
    shutil.rmtree(self.repository_dir)

    if self.TUF is True:
      self.tuf_tearDown()



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



  def tuf_setUp(self):
    """
    <Purpose>
      Setup TUF directory structure and populated it with TUF metadata and 
      congfiguration files.

                           tuf_repository_dir
                                  |
            --------------------------------------------
            |                     |                    |
         keystore              metadata             targets
            |                     |                    |
      key.key files         role.txt files       targets (updates)
           ...                   ...                  ...


                             tuf_client_dir
                                  |
                               metadata
                                  |
                      ---------------------------
                      |                         |  
                   current                   previous
                      |                         |
                role.txt files            role.txt files
                     ...                       ...

    """ 

    passwd = 'test'
    threshold = 1

    # Setup TUF directory structure.
    self.tuf_repository_dir = tempfile.mkdtemp(suffix='tuf_r', dir=os.getcwd())
    self.tuf_client_dir = tempfile.mkdtemp(suffix='tuf_c', dir=os.getcwd())
    self.tuf_keystore_dir = os.path.join(self.tuf_repository_dir, 'keystore')
    self.tuf_metadata_dir = os.path.join(self.tuf_repository_dir, 'metadata')
    os.mkdir(self.tuf_keystore_dir)
    os.mkdir(self.tuf_metadata_dir)
    self.tuf_targets_dir = os.path.join(self.tuf_repository_dir, 'targets')
    shutil.copytree(self.repository_dir, self.tuf_targets_dir)

    # Generate at least one rsa key.
    key = signerlib.generate_and_save_rsa_key(self.tuf_keystore_dir, passwd)

    # Set some role info.
    info = {'keyids': [key['keyid']], 'threshold': threshold}

    # Setup keystore.  'role_info' dictionary looks like this:
    # {'keyids : [keyid1, ...] , 'threshold' : 2}
    # In our case 'role_info[keyids]' will only have on entry since only one
    # is being used.
    role_info = {}
    role_list = ['root', 'targets', 'release', 'timestamp']
    for role in role_list:
      role_info[role] = info

    # At this point there is enough information to create TUF configuration 
    # and metadata files.

    # Build the configuration file.
    conf_filepath = signerlib.build_config_file(self.repository_dir, 365, role_info)

    # Generate the 'root.txt' metadata file.
    keyid = [key['keyid']]
    signerlib.build_root_file(conf_filepath, keyid, self.tuf_metadata_dir)

    # Generate the 'targets.txt' metadata file. 
    signerlib.build_targets_file(self.tuf_targets_dir, keyid, self.tuf_metadata_dir)

    # Generate the 'release.txt' metadata file.
    signerlib.build_release_file(keyid, self.tuf_metadata_dir)

    # Generate the 'timestamp.txt' metadata file.
    signerlib.build_timestamp_file(keyid, self.tuf_metadata_dir)

    # Setting up client's TUF directory structure.
    # 'tuf.client.updater.py' expects the 'current' and 'previous'
    # directories to exist under client's 'metadata' directory.
    self.tuf_client_metadata_dir = os.path.join(self.tuf_client_dir, 'metadata')
    os.mkdir(self.tuf_client_metadata_dir)

    # Move the metadata to the client's 'current' and 'previous' directories.
    self.client_current = os.path.join(self.tuf_client_metadata_dir, 'current')
    self.client_previous = os.path.join(self.tuf_client_metadata_dir, 'previous')
    shutil.copytree(self.tuf_metadata_dir, self.client_current)
    shutil.copytree(self.tuf_metadata_dir, self.client_previous)



  def tuf_tearDown(self):
    """
    <Purpose>
      The clean-up method, removes all TUF directories created using
      tuf_setUp().
    """
    shutil.rmtree(self.tuf_repository_dir)
    shutil.rmtree(self.tuf_client_dir)



  # Quick internal test to see if everything runs smoothly.
  def test_client_download(self):
    data = self.client_download(self.filename1)
    self.assertEquals(data, 'System Test File 1')

    # Verify that all necessary paths exist.
    for role in ['root', 'targets', 'release', 'timestamp']:
      # Repository side.
      role_file = os.path.join(self.tuf_metadata_dir, role+'.txt')
      self.assertTrue(os.path.isfile(role_file))

      # Client side.
      role_file = os.path.join(self.client_current, role+'.txt')
      self.assertTrue(os.path.isfile(role_file))

    target1 = os.path.join(self.tuf_targets_dir, self.filename1)
    target2 = os.path.join(self.tuf_targets_dir, self.filename2)
    self.assertTrue(os.path.isfile(target1))
    self.assertTrue(os.path.isfile(target2))





if __name__=='__main__':
  unittest.main()