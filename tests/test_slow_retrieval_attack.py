#!/usr/bin/env python

# Copyright 2012 - 2017, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
<Program Name>
  test_slow_retrieval_attack.py

<Author>
  Konstantin Andrianov.

<Started>
  March 13, 2012.

  April 5, 2014.
    Refactored to use the 'unittest' module (test conditions in code, rather
    than verifying text output), use pre-generated repository files, and
    discontinue use of the old repository tools. Expanded comments and modified
    previous setup. -vladimir.v.diaz

<Copyright>
  See LICENSE-MIT OR LICENSE for licensing information.

<Purpose>
  Simulate a slow retrieval attack, where an attacker is able to prevent clients
  from receiving updates by responding to client requests so slowly that updates
  never complete.  Test cases included for two types of slow retrievals: data
  that slowly trickles in, and data that is only returned after a long time
  delay.  TUF prevents slow retrieval attacks by ensuring the download rate
  does not fall below a required rate (tuf.settings.MIN_AVERAGE_DOWNLOAD_SPEED).

  Note: There is no difference between 'updates' and 'target' files.

  # TODO: Consider additional tests for slow metadata download. Tests here only
  use slow target download.
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
import shutil
import logging
import unittest
import sys

import tuf.log
import tuf.client.updater as updater
import tuf.unittest_toolbox as unittest_toolbox
import tuf.repository_tool as repo_tool
import tuf.roledb
import tuf.keydb

from tests import utils

import six

logger = logging.getLogger(__name__)
repo_tool.disable_console_log_messages()



class TestSlowRetrieval(unittest_toolbox.Modified_TestCase):

  def setUp(self):
    # We are inheriting from custom class.
    unittest_toolbox.Modified_TestCase.setUp(self)

    self.repository_name = 'test_repository1'

    # Create a temporary directory to store the repository, metadata, and target
    # files.  'temporary_directory' must be deleted in TearDownModule() so that
    # temporary files are always removed, even when exceptions occur.
    self.temporary_directory = tempfile.mkdtemp(dir=os.getcwd())

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
    original_keystore = os.path.join(original_repository_files, 'keystore')

    # Save references to the often-needed client repository directories.
    # Test cases need these references to access metadata and target files.
    self.repository_directory = \
      os.path.join(temporary_repository_root, 'repository')
    self.client_directory = os.path.join(temporary_repository_root, 'client')
    self.keystore_directory = os.path.join(temporary_repository_root, 'keystore')

    # Copy the original 'repository', 'client', and 'keystore' directories
    # to the temporary repository the test cases can use.
    shutil.copytree(original_repository, self.repository_directory)
    shutil.copytree(original_client, self.client_directory)
    shutil.copytree(original_keystore, self.keystore_directory)


    # Produce a longer target file than exists in the other test repository
    # data, to provide for a long-duration slow attack. Then we'll write new
    # top-level metadata that includes a hash over that file, and provide that
    # metadata to the client as well.

    # The slow retrieval server, in mode 2 (1 byte per second), will only
    # sleep for a  total of (target file size) seconds.  Add a target file
    # that contains sufficient number of bytes to trigger a slow retrieval
    # error. A transfer should not be permitted to take 1 second per byte
    # transferred. Because this test is currently expected to fail, I'm
    # limiting the size to 10 bytes (10 seconds) to avoid expected testing
    # delays.... Consider increasing again after fix, to, e.g. 400.
    total_bytes = 10

    repository = repo_tool.load_repository(self.repository_directory)
    file1_filepath = os.path.join(self.repository_directory, 'targets',
                                  'file1.txt')
    with open(file1_filepath, 'wb') as file_object:
      data = 'a' * int(round(total_bytes))
      file_object.write(data.encode('utf-8'))

    key_file = os.path.join(self.keystore_directory, 'timestamp_key')
    timestamp_private = repo_tool.import_ed25519_privatekey_from_file(key_file,
                                                                  'password')
    key_file = os.path.join(self.keystore_directory, 'snapshot_key')
    snapshot_private = repo_tool.import_ed25519_privatekey_from_file(key_file,
                                                                  'password')
    key_file = os.path.join(self.keystore_directory, 'targets_key')
    targets_private = repo_tool.import_ed25519_privatekey_from_file(key_file,
                                                                  'password')

    repository.targets.load_signing_key(targets_private)
    repository.snapshot.load_signing_key(snapshot_private)
    repository.timestamp.load_signing_key(timestamp_private)

    repository.writeall()

    # Move the staged metadata to the "live" metadata.
    shutil.rmtree(os.path.join(self.repository_directory, 'metadata'))
    shutil.copytree(os.path.join(self.repository_directory, 'metadata.staged'),
                    os.path.join(self.repository_directory, 'metadata'))

    # Since we've changed the repository metadata in this setup (by lengthening
    # a target file and then writing new metadata), we also have to update the
    # client metadata to get to the expected initial state, where the client
    # knows the right target info (and so expects the right, longer target
    # length.
    # We'll skip using updater.refresh since we don't have a server running,
    # and we'll update the metadata locally, manually.
    shutil.rmtree(os.path.join(
        self.client_directory, self.repository_name, 'metadata', 'current'))
    shutil.copytree(os.path.join(self.repository_directory, 'metadata'),
        os.path.join(self.client_directory, self.repository_name, 'metadata',
        'current'))

    # Set the url prefix required by the 'tuf/client/updater.py' updater.
    # 'path/to/tmp/repository' -> 'localhost:8001/tmp/repository'.
    repository_basepath = self.repository_directory[len(os.getcwd()):]

    self.server_process_handler = utils.TestServerProcess(log=logger,
        server='slow_retrieval_server.py')

    logger.info('Slow Retrieval Server process started.')

    url_prefix = 'http://localhost:' \
      + str(self.server_process_handler.port) + repository_basepath

    # Setting 'tuf.settings.repository_directory' with the temporary client
    # directory copied from the original repository files.
    tuf.settings.repositories_directory = self.client_directory
    self.repository_mirrors = {'mirror1': {'url_prefix': url_prefix,
                                           'metadata_path': 'metadata',
                                           'targets_path': 'targets'}}

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

    # Cleans the resources and flush the logged lines (if any).
    self.server_process_handler.clean()

    # Remove the temporary repository directory, which should contain all the
    # metadata, targets, and key files generated of all the test cases.
    shutil.rmtree(self.temporary_directory)



  def test_delay_before_send(self):
    # Simulate a slow retrieval attack.
    # When download begins,the server blocks the download for a long
    # time by doing nothing before it sends the first byte of data.

    # Verify that the TUF client detects replayed metadata and refuses to
    # continue the update process.
    try:
      file1_target = self.repository_updater.get_one_valid_targetinfo('file1.txt')
      self.repository_updater.download_target(file1_target, self.client_directory)

    # Verify that the specific 'tuf.exceptions.SlowRetrievalError' exception is raised by
    # each mirror.
    except tuf.exceptions.NoWorkingMirrorError as exception:
      for mirror_url, mirror_error in six.iteritems(exception.mirror_errors):
        url_prefix = self.repository_mirrors['mirror1']['url_prefix']
        url_file = os.path.join(url_prefix, 'targets', 'file1.txt')

        # Verify that 'file1.txt' is the culprit.
        self.assertEqual(url_file.replace('\\', '/'), mirror_url)
        self.assertTrue(isinstance(mirror_error, tuf.exceptions.SlowRetrievalError))

    else:
      self.fail('TUF did not prevent a slow retrieval attack.')



if __name__ == '__main__':
  utils.configure_test_logging(sys.argv)
  unittest.main()
