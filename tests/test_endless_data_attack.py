#!/usr/bin/env python

# Copyright 2012 - 2017, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
<Program Name>
  test_endless_data_attack.py

<Author>
  Konstantin Andrianov.

<Started>
  March 13, 2012.

  April 3, 2014.
    Refactored to use the 'unittest' module (test conditions in code, rather
    than verifying text output), use pre-generated repository files, and
    discontinue use of the old repository tools. Minor edits to the test cases.
    -vladimir.v.diaz

<Copyright>
  See LICENSE-MIT OR LICENSE for licensing information.

<Purpose>
  Simulate an endless data attack, where an updater client tries to download a
  target file modified by an attacker to contain a large amount of data (a TUF
  client should only download up to the file's expected length).  TUF and
  non-TUF client scenarios are tested.

  There is no difference between 'updates' and 'target' files.
"""

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import os
import tempfile
import random
import time
import shutil
import json
import subprocess
import logging
import sys
import unittest

import tuf
import tuf.formats
import tuf.log
import tuf.client.updater as updater
import tuf.unittest_toolbox as unittest_toolbox
import tuf.roledb

import securesystemslib
import six

logger = logging.getLogger(__name__)


class TestEndlessDataAttack(unittest_toolbox.Modified_TestCase):

  @classmethod
  def setUpClass(cls):
    # setUpClass() is called before any of the test cases are executed.

    # Create a temporary directory to store the repository, metadata, and target
    # files.  'temporary_directory' must be deleted in TearDownModule() so that
    # temporary files are always removed, even when exceptions occur.
    cls.temporary_directory = tempfile.mkdtemp(dir=os.getcwd())

    # Launch a SimpleHTTPServer (serves files in the current directory).
    # Test cases will request metadata and target files that have been
    # pre-generated in 'tuf/tests/repository_data', which will be served by the
    # SimpleHTTPServer launched here.  The test cases of this unit test assume
    # the pre-generated metadata files have a specific structure, such
    # as a delegated role 'targets/role1', three target files, five key files,
    # etc.
    cls.SERVER_PORT = random.randint(30000, 45000)
    command = ['python', 'simple_server.py', str(cls.SERVER_PORT)]
    cls.server_process = subprocess.Popen(command)
    logger.info('Server process started.')
    logger.info('Server process id: '+str(cls.server_process.pid))
    logger.info('Serving on port: '+str(cls.SERVER_PORT))
    cls.url = 'http://localhost:'+str(cls.SERVER_PORT) + os.path.sep

    # NOTE: Following error is raised if a delay is not applied:
    # <urlopen error [Errno 111] Connection refused>
    time.sleep(.8)



  @classmethod
  def tearDownClass(cls):
    # tearDownModule() is called after all the test cases have run.
    # http://docs.python.org/2/library/unittest.html#class-and-module-fixtures

    # Remove the temporary repository directory, which should contain all the
    # metadata, targets, and key files generated of all the test cases.
    shutil.rmtree(cls.temporary_directory)

    # Kill the SimpleHTTPServer process.
    if cls.server_process.returncode is None:
      logger.info('Server process '+str(cls.server_process.pid)+' terminated.')
      cls.server_process.kill()



  def setUp(self):
    # We are inheriting from custom class.
    unittest_toolbox.Modified_TestCase.setUp(self)

    self.repository_name = 'test_repository1'

    # Copy the original repository files provided in the test folder so that
    # any modifications made to repository files are restricted to the copies.
    # The 'repository_data' directory is expected to exist in 'tuf/tests/'.
    original_repository_files = os.path.join(os.getcwd(), 'repository_data')
    temporary_repository_root = \
      self.make_temp_directory(directory=self.temporary_directory)

    # The original repository, keystore, and client directories will be copied
    # for each test case.
    original_repository = os.path.join(original_repository_files, 'repository')
    original_client = os.path.join(original_repository_files, 'client')

    # Save references to the often-needed client repository directories.
    # Test cases need these references to access metadata and target files.
    self.repository_directory = \
      os.path.join(temporary_repository_root, 'repository')
    self.client_directory = os.path.join(temporary_repository_root, 'client')

    # Copy the original 'repository', 'client', and 'keystore' directories
    # to the temporary repository the test cases can use.
    shutil.copytree(original_repository, self.repository_directory)
    shutil.copytree(original_client, self.client_directory)

    # Set the url prefix required by the 'tuf/client/updater.py' updater.
    # 'path/to/tmp/repository' -> 'localhost:8001/tmp/repository'.
    repository_basepath = self.repository_directory[len(os.getcwd()):]
    url_prefix = \
      'http://localhost:' + str(self.SERVER_PORT) + repository_basepath

    # Setting 'tuf.settings.repository_directory' with the temporary client
    # directory copied from the original repository files.
    tuf.settings.repositories_directory = self.client_directory
    self.repository_mirrors = {'mirror1': {'url_prefix': url_prefix,
                                           'metadata_path': 'metadata',
                                           'targets_path': 'targets',
                                           'confined_target_dirs': ['']}}

    # Create the repository instance.  The test cases will use this client
    # updater to refresh metadata, fetch target files, etc.
    self.repository_updater = updater.Updater(self.repository_name,
                                              self.repository_mirrors)


  def tearDown(self):
    # Modified_TestCase.tearDown() automatically deletes temporary files and
    # directories that may have been created during each test case.
    unittest_toolbox.Modified_TestCase.tearDown(self)
    tuf.roledb.clear_roledb(clear_all=True)
    tuf.keydb.clear_keydb(clear_all=True)


  def test_without_tuf(self):
    # Verify that a target file replaced with a larger malicious version (to
    # simulate an endless data attack) is downloaded by a non-TUF client (i.e.,
    # a non-TUF client that does not verify hashes, detect mix-and-mix attacks,
    # etc.)  A tuf client, on the other hand, should only download target files
    # up to their expected lengths, as explicitly specified in metadata, or
    # 'tuf.settings.py' (when retrieving 'timestamp.json' and 'root.json unsafely'.)

    # Test: Download a valid target file from the repository.
    # Ensure the target file to be downloaded has not already been downloaded,
    # and generate its file size and digest.  The file size and digest is needed
    # to verify that the malicious file was indeed downloaded.
    target_path = os.path.join(self.repository_directory, 'targets', 'file1.txt')
    client_target_path = os.path.join(self.client_directory, 'file1.txt')
    self.assertFalse(os.path.exists(client_target_path))
    length, hashes = securesystemslib.util.get_file_details(target_path)
    fileinfo = tuf.formats.make_targets_fileinfo(length, hashes)

    url_prefix = self.repository_mirrors['mirror1']['url_prefix']
    url_file = os.path.join(url_prefix, 'targets', 'file1.txt')

    # On Windows, the URL portion should not contain backslashes.
    six.moves.urllib.request.urlretrieve(url_file.replace('\\', '/'), client_target_path)

    self.assertTrue(os.path.exists(client_target_path))
    length, hashes = securesystemslib.util.get_file_details(client_target_path)
    download_fileinfo = tuf.formats.make_targets_fileinfo(length, hashes)
    self.assertEqual(fileinfo, download_fileinfo)

    # Test: Download a target file that has been modified by an attacker with
    # extra data.
    with open(target_path, 'a') as file_object:
      file_object.write('append large amount of data' * 100000)
    large_length, hashes = securesystemslib.util.get_file_details(target_path)
    malicious_fileinfo = tuf.formats.make_targets_fileinfo(large_length, hashes)

    # Is the modified file actually larger?
    self.assertTrue(large_length > length)

    # On Windows, the URL portion should not contain backslashes.
    six.moves.urllib.request.urlretrieve(url_file.replace('\\', '/'), client_target_path)

    length, hashes = securesystemslib.util.get_file_details(client_target_path)
    download_fileinfo = tuf.formats.make_targets_fileinfo(length, hashes)

    # Verify 'download_fileinfo' is unequal to the original trusted version.
    self.assertNotEqual(download_fileinfo, fileinfo)

    # Verify 'download_fileinfo' is equal to the malicious version.
    self.assertEqual(download_fileinfo, malicious_fileinfo)



  def test_with_tuf(self):
    # Verify that a target file (on the remote repository) modified by an
    # attacker, to contain a large amount of extra data, is not downloaded by
    # the TUF client.  First test that the valid target file is successfully
    # downloaded.
    file1_fileinfo = self.repository_updater.get_one_valid_targetinfo('file1.txt')
    destination = os.path.join(self.client_directory)
    self.repository_updater.download_target(file1_fileinfo, destination)
    client_target_path = os.path.join(destination, 'file1.txt')
    self.assertTrue(os.path.exists(client_target_path))

    # Verify the client's downloaded file matches the repository's.
    target_path = os.path.join(self.repository_directory, 'targets', 'file1.txt')
    length, hashes = securesystemslib.util.get_file_details(client_target_path)
    fileinfo = tuf.formats.make_targets_fileinfo(length, hashes)

    length, hashes = securesystemslib.util.get_file_details(client_target_path)
    download_fileinfo = tuf.formats.make_targets_fileinfo(length, hashes)
    self.assertEqual(fileinfo, download_fileinfo)

    # Modify 'file1.txt' and confirm that the TUF client only downloads up to
    # the expected file length.
    with open(target_path, 'a') as file_object:
      file_object.write('append large amount of data' * 10000)

    # Is the modified file actually larger?
    large_length, hashes = securesystemslib.util.get_file_details(target_path)
    self.assertTrue(large_length > length)

    os.remove(client_target_path)
    self.repository_updater.download_target(file1_fileinfo, destination)

    # A large amount of data has been appended to the original content.  The
    # extra data appended should be discarded by the client, so the downloaded
    # file size and hash should not have changed.
    length, hashes = securesystemslib.util.get_file_details(client_target_path)
    download_fileinfo = tuf.formats.make_targets_fileinfo(length, hashes)
    self.assertEqual(fileinfo, download_fileinfo)

    # Test that the TUF client does not download large metadata files, as well.
    timestamp_path = os.path.join(self.repository_directory, 'metadata',
                                  'timestamp.json')

    original_length, hashes = securesystemslib.util.get_file_details(timestamp_path)

    with open(timestamp_path, 'r+') as file_object:
      timestamp_content = securesystemslib.util.load_json_file(timestamp_path)
      large_data = 'LargeTimestamp' * 10000
      timestamp_content['signed']['_type'] = large_data
      json.dump(timestamp_content, file_object, indent=1, sort_keys=True)


    modified_length, hashes = securesystemslib.util.get_file_details(timestamp_path)
    self.assertTrue(modified_length > original_length)

    # Does the TUF client download the upper limit of an unsafely fetched
    # 'timestamp.json'?  'timestamp.json' must not be greater than
    # 'tuf.settings.DEFAULT_TIMESTAMP_REQUIRED_LENGTH'.
    try:
      self.repository_updater.refresh()

    except tuf.exceptions.NoWorkingMirrorError as exception:
      for mirror_url, mirror_error in six.iteritems(exception.mirror_errors):
        self.assertTrue(isinstance(mirror_error, securesystemslib.exceptions.Error))

    else:
      self.fail('TUF did not prevent an endless data attack.')


if __name__ == '__main__':
  unittest.main()
