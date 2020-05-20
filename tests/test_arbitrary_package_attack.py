#!/usr/bin/env python

# Copyright 2012 - 2017, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
<Program Name>
  test_arbitrary_package_attack.py

<Author>
  Konstantin Andrianov.

<Started>
  February 22, 2012.

  March 21, 2014.
    Refactored to use the 'unittest' module (test conditions in code, rather
    than verifying text output), use pre-generated repository files, and
    discontinue use of the old repository tools. -vladimir.v.diaz

<Copyright>
  See LICENSE-MIT OR LICENSE for licensing information.

<Purpose>
  Simulate an arbitrary package attack, where an updater client attempts to
  download a malicious file.  TUF and non-TUF client scenarios are tested.

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
import tuf.roledb
import tuf.keydb
import tuf.log
import tuf.client.updater as updater
import tuf.unittest_toolbox as unittest_toolbox

import securesystemslib
import six

logger = logging.getLogger(__name__)


class TestArbitraryPackageAttack(unittest_toolbox.Modified_TestCase):

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
    logger.info('Server process id: ' + str(cls.server_process.pid))
    logger.info('Serving on port: ' + str(cls.SERVER_PORT))
    cls.url = 'http://localhost:' + str(cls.SERVER_PORT) + os.path.sep

    # NOTE: Following error is raised if a delay is not applied:
    # <urlopen error [Errno 111] Connection refused>
    time.sleep(1)



  @classmethod
  def tearDownClass(cls):
    # tearDownModule() is called after all the test cases have run.
    # http://docs.python.org/2/library/unittest.html#class-and-module-fixtures

    # Remove the temporary repository directory, which should contain all the
    # metadata, targets, and key files generated of all the test cases.
    shutil.rmtree(cls.temporary_directory)

    # Kill the SimpleHTTPServer process.
    if cls.server_process.returncode is None:
      logger.info('Server process ' + str(cls.server_process.pid) + ' terminated.')
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
    # updater.Updater() populates the roledb with the name "test_repository1"
    tuf.roledb.clear_roledb(clear_all=True)
    tuf.keydb.clear_keydb(clear_all=True)

  def test_without_tuf(self):
    # Verify that a target file replaced with a malicious version is downloaded
    # by a non-TUF client (i.e., a non-TUF client that does not verify hashes,
    # detect mix-and-mix attacks, etc.)  A tuf client, on the other hand, should
    # detect that the downloaded target file is invalid.

    # Test: Download a valid target file from the repository.
    # Ensure the target file to be downloaded has not already been downloaded,
    # and generate its file size and digest.  The file size and digest is needed
    # to check that the malicious file was indeed downloaded.
    target_path = os.path.join(self.repository_directory, 'targets', 'file1.txt')
    client_target_path = os.path.join(self.client_directory, 'file1.txt')
    self.assertFalse(os.path.exists(client_target_path))
    length, hashes = securesystemslib.util.get_file_details(target_path)
    fileinfo = tuf.formats.make_targets_fileinfo(length, hashes)

    url_prefix = self.repository_mirrors['mirror1']['url_prefix']
    url_file = os.path.join(url_prefix, 'targets', 'file1.txt')

    # On Windows, the URL portion should not contain back slashes.
    six.moves.urllib.request.urlretrieve(url_file.replace('\\', '/'), client_target_path)

    self.assertTrue(os.path.exists(client_target_path))
    length, hashes = securesystemslib.util.get_file_details(client_target_path)
    download_fileinfo = tuf.formats.make_targets_fileinfo(length, hashes)
    self.assertEqual(fileinfo, download_fileinfo)

    # Test: Download a target file that has been modified by an attacker.
    with open(target_path, 'wt') as file_object:
      file_object.write('add malicious content.')
    length, hashes = securesystemslib.util.get_file_details(target_path)
    malicious_fileinfo = tuf.formats.make_targets_fileinfo(length, hashes)

    # On Windows, the URL portion should not contain back slashes.
    six.moves.urllib.request.urlretrieve(url_file.replace('\\', '/'), client_target_path)

    length, hashes = securesystemslib.util.get_file_details(client_target_path)
    download_fileinfo = tuf.formats.make_targets_fileinfo(length, hashes)

    # Verify 'download_fileinfo' is unequal to the original trusted version.
    self.assertNotEqual(download_fileinfo, fileinfo)

    # Verify 'download_fileinfo' is equal to the malicious version.
    self.assertEqual(download_fileinfo, malicious_fileinfo)



  def test_with_tuf(self):
    # Verify that a target file (on the remote repository) modified by an
    # attacker is not downloaded by the TUF client.
    # First test that the valid target file is successfully downloaded.
    file1_fileinfo = self.repository_updater.get_one_valid_targetinfo('file1.txt')
    destination = os.path.join(self.client_directory)
    self.repository_updater.download_target(file1_fileinfo, destination)
    client_target_path = os.path.join(destination, 'file1.txt')
    self.assertTrue(os.path.exists(client_target_path))

    # Modify 'file1.txt' and confirm that the TUF client rejects it.
    target_path = os.path.join(self.repository_directory, 'targets', 'file1.txt')
    with open(target_path, 'wt') as file_object:
      file_object.write('malicious content, size 33 bytes.')

    try:
      self.repository_updater.download_target(file1_fileinfo, destination)

    except tuf.exceptions.NoWorkingMirrorError as exception:
      url_prefix = self.repository_mirrors['mirror1']['url_prefix']
      url_file = os.path.join(url_prefix, 'targets', 'file1.txt')

      # Verify that only one exception is raised for 'url_file'.
      self.assertTrue(len(exception.mirror_errors), 1)

      # Verify that the expected 'tuf.exceptions.DownloadLengthMismatchError' exception
      # is raised for 'url_file'.
      self.assertTrue(url_file.replace('\\', '/') in exception.mirror_errors)
      self.assertTrue(
          isinstance(exception.mirror_errors[url_file.replace('\\', '/')],
          securesystemslib.exceptions.BadHashError))

    else:
      self.fail('TUF did not prevent an arbitrary package attack.')


  def test_with_tuf_and_metadata_tampering(self):
    # Test that a TUF client does not download a malicious target file, and a
    # 'targets.json' metadata file that has also been modified by the attacker.
    # The attacker does not attach a valid signature to 'targets.json'

    # An attacker modifies 'file1.txt'.
    target_path = os.path.join(self.repository_directory, 'targets', 'file1.txt')
    with open(target_path, 'wt') as file_object:
      file_object.write('malicious content, size 33 bytes.')

    # An attacker also tries to add the malicious target's length and digest
    # to its metadata file.
    length, hashes = securesystemslib.util.get_file_details(target_path)

    metadata_path = \
      os.path.join(self.repository_directory, 'metadata', 'targets.json')

    metadata = securesystemslib.util.load_json_file(metadata_path)
    metadata['signed']['targets']['file1.txt']['hashes'] = hashes
    metadata['signed']['targets']['file1.txt']['length'] = length

    tuf.formats.check_signable_object_format(metadata)

    with open(metadata_path, 'wb') as file_object:
      file_object.write(json.dumps(metadata, indent=1,
          separators=(',', ': '), sort_keys=True).encode('utf-8'))

    # Verify that the malicious 'targets.json' is not downloaded.  Perform
    # a refresh of top-level metadata to demonstrate that the malicious
    # 'targets.json' is not downloaded.
    try:
      self.repository_updater.refresh()
      file1_fileinfo = self.repository_updater.get_one_valid_targetinfo('file1.txt')
      destination = os.path.join(self.client_directory)
      self.repository_updater.download_target(file1_fileinfo, destination)

    except tuf.exceptions.NoWorkingMirrorError as exception:
      url_prefix = self.repository_mirrors['mirror1']['url_prefix']
      url_file = os.path.join(url_prefix, 'targets', 'file1.txt')

      # Verify that an exception raised for only the malicious 'url_file'.
      self.assertTrue(len(exception.mirror_errors), 1)

      # Verify that the specific and expected mirror exception is raised.
      self.assertTrue(url_file.replace('\\', '/') in exception.mirror_errors)
      self.assertTrue(
          isinstance(exception.mirror_errors[url_file.replace('\\', '/')],
          securesystemslib.exceptions.BadHashError))

    else:
      self.fail('TUF did not prevent an arbitrary package attack.')


if __name__ == '__main__':
  unittest.main()
