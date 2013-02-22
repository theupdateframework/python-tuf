"""
<Program Name>
  test_system_setup.py

<Author>
  Konstantin Andrianov

<Started>
  February 19, 2012

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Provide automatic setup and clean-up functionality.  This module is based on
  python's unittest, the main class 'TestCase' inherits from 
  unittest.TestCase.

  Initial repository looks like this:
  simple server -->          repository_dir
                                   |
                       --------------------------
                       |                        |
                    filename1               filename2

  This modules uses unittest module to provide easy setup and tear down
  capability.

  Essentially there are two choices: either a system that simply performs
  update downloads without any protections or a system that utilizes TUF to
  perform secure update downloads.

  A structure that does NOT implementing TUF.  A direct download over http.
  Repository + Server    <--------------->    Client

  The TUF structure is described bellow in the class and tuf_tearDown() docs.
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
  <Class Methods>
    TestCase inherits from unittest.TestCase class.
    Not including setups, tear downs and tests.

    client_download(filename):
      Downloads a file ('filename') from 'url' (described bellow).
      Returns the contents of the file.

    add_or_change_file_at_repository(filename, data):
      Allows to add or change a file on the repository ('repository_dir').
      Returns full path of the added/changed file.

    delete_file_at_repository(filename):
      Deletes a file on the repository ('repository_dir').

    tuf_refresh()
      Updates TUF metadata files.


  <Class Variables>
    TUF:
      Indicates whether or not TUF is implemented.
      Boolean values that implements TUF if True.  Otherwise TUF is skipped. 

  <Class Instance Variables>
    repository_dir:
      Repository directory, where updates are located.
    
    filename#:
      Name of the update, which is located in the repository directory.
    
    server_process:
      A subprocess object.

    url:
      A loopback address pointing to the repository directory 
      ('repository_dir').


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
    filepath1 = self.add_or_change_file_at_repository(data='SystemTestFile1')
    filepath2 = self.add_or_change_file_at_repository(data='SystemTestFile2')
    self.filename1 = os.path.basename(filepath1)
    self.filename2 = os.path.basename(filepath2)

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


  


  def add_or_change_file_at_repository(self, filename=None, data=None):
    """
    <Purpose>
      Adds or changes a file named 'filename' at the repository 
      'repository_dir'.

    <Arguments>
      filename:
        Name of the file located on the repository 'repository_dir'.
        Ex: file1.txt

      data:
        A string to write to the indicated file.  If None, 'test' string is
        used.

    """

    if filename is not None and isinstance(filename, basestring):
      filepath = os.path.join(self.repository_dir, filename)
      if not os.path.isfile(filepath):
        print 'There is no filepath ' + repr(filepath)+' does not exit.\n'
        sys.exit(1)
      fileobj = open(filepath, 'wb')
    else:
      junk, filepath = tempfile.mkstemp(dir=self.repository_dir)
      filename = os.path.basename(filepath)
      fileobj = open(filepath, 'wb')

    if data is None or not isinstance(data, basestring):
      data = 'test'

    fileobj.write(data)
    fileobj.close()
    return filepath





  def delete_file_at_repository(self, filename):
    """
    <Purpose>
      Attempt to delete a file named 'filename' at the repository.
    """
    if isinstance(filename, basestring):
      filepath = os.path.join(self.repository_dir, filename)
      if os.path.isfile(filepath):
        os.remove(filepath)
      else:
        print 'There is no filepath ' + repr(filepath) + ' does not exit.\n'
        sys.exit(1)
    else:
      print 'Wrong type: ' + repr(filepath) + '\n'
      sys.exit(1)





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
    if not isinstance(filename, basestring):
      print 'Wrong type: ' + repr(filepath) + '\n'
      sys.exit(1)
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

    # 'role_info' dictionary looks like this:
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
    self._conf_filepath = signerlib.build_config_file(self.repository_dir,
                                                      365, role_info)

    # Generate the 'root.txt' metadata file.
    self._keyid = [key['keyid']]
    signerlib.build_root_file(self._conf_filepath, self._keyid, 
                              self.tuf_metadata_dir)

    # Generate the 'targets.txt' metadata file. 
    signerlib.build_targets_file(self.tuf_targets_dir, self._keyid, 
                                 self.tuf_metadata_dir)

    # Generate the 'release.txt' metadata file.
    signerlib.build_release_file(self._keyid, self.tuf_metadata_dir)

    # Generate the 'timestamp.txt' metadata file.
    signerlib.build_timestamp_file(self._keyid, self.tuf_metadata_dir)

    # Setting up client's TUF directory structure.
    # 'tuf.client.updater.py' expects the 'current' and 'previous'
    # directories to exist under client's 'metadata' directory.
    self.tuf_client_metadata_dir = os.path.join(self.tuf_client_dir,
                                                'metadata')
    os.mkdir(self.tuf_client_metadata_dir)

    # Move the metadata to the client's 'current' and 'previous' directories.
    self.client_current = os.path.join(self.tuf_client_metadata_dir, 
                                       'current')
    self.client_previous = os.path.join(self.tuf_client_metadata_dir,
                                        'previous')
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





  def tuf_refresh(self):
    """
    <Purpose>
      Update TUF metadata files.  Call this method whenever targets files have
      changed in the 'repository_dir'.

    """

    shutil.rmtree(self.tuf_targets_dir)
    shutil.copytree(self.repository_dir, self.tuf_targets_dir)

    # Regenerate the 'targets.txt' metadata file. 
    signerlib.build_targets_file(self.tuf_targets_dir, self._keyid,
                                 self.tuf_metadata_dir)

    # Regenerate the 'release.txt' metadata file.
    signerlib.build_release_file(self._keyid, self.tuf_metadata_dir)

    # Regenerate the 'timestamp.txt' metadata file.
    signerlib.build_timestamp_file(self._keyid, self.tuf_metadata_dir)





  # A few quick internal tests to see if everything runs smoothly.
  def test_client_download(self):
    data = self.client_download(self.filename1)
    self.assertEquals(data, 'SystemTestFile1')





  def test_tuf_setup(self):
    # Verify that all necessary TUF-paths exist.
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

    self.tuf_refresh()





  def test_methods(self):
    """
    Making sure following methods work as intended:
    - add_or_change_file_at_repository()
    - delete_file_at_repository()
    - tuf_refresh()
    """
    new_file = self.add_or_change_file_at_repository()
    fileobj = open(new_file, 'rb')
    self.assertTrue(os.path.exists(new_file))
    self.assertEquals('test', fileobj.read())

    old_file = self.add_or_change_file_at_repository(filename=self.filename1)
    fileobj = open(new_file, 'rb')
    self.assertTrue(os.path.exists(new_file))
    self.assertEquals('test', fileobj.read())

    old_file = self.add_or_change_file_at_repository(filename=self.filename1,
                                                     data='1234')
    fileobj = open(old_file, 'rb')
    self.assertTrue(os.path.exists(old_file))
    self.assertEquals('1234', fileobj.read())

    self.tuf_refresh()
    new_target = os.path.join(self.tuf_targets_dir, 
                              os.path.basename(new_file))
    self.assertTrue(os.path.exists(new_target))
    # Here it is assumed that all relevant metadata has been updated
    # successfully.  This is tested in signerlib and other unit tests.

    self.delete_file_at_repository(os.path.basename(new_file))
    self.assertFalse(os.path.exists(new_file))



if __name__=='__main__':
  unittest.main()