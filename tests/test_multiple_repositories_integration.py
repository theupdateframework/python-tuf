#!/usr/bin/env python

# Copyright 2017, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
<Program Name>
  test_multiple_repositories_integration.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  February 2, 2017

<Copyright>
  See LICENSE-MIT OR LICENSE for licensing information.

<Purpose>
  Verify that clients and the repository tools are able to keep track of
  multiple repositories and separate sets of metadata for each.
"""

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import os
import sys
import tempfile
import random
import subprocess
import logging
import time
import shutil
import unittest
import json

import tuf
import tuf.log
import tuf.roledb
import tuf.client.updater as updater
import tuf.settings
import securesystemslib
import tuf.unittest_toolbox as unittest_toolbox
import tuf.repository_tool as repo_tool

import six
import securesystemslib

logger = logging.getLogger(__name__)

repo_tool.disable_console_log_messages()


class TestMultipleRepositoriesIntegration(unittest_toolbox.Modified_TestCase):

  def setUp(self):
    # We are inheriting from custom class.
    unittest_toolbox.Modified_TestCase.setUp(self)

    self.temporary_directory = tempfile.mkdtemp(dir=os.getcwd())

    # Copy the original repository files provided in the test folder so that
    # any modifications made to repository files are restricted to the copies.
    # The 'repository_data' directory is expected to exist in 'tuf/tests/'.
    original_repository_files = os.path.join(os.getcwd(), 'repository_data')

    self.temporary_repository_root = self.make_temp_directory(directory=
        self.temporary_directory)

    # The original repository, keystore, and client directories will be copied
    # for each test case.
    original_repository = os.path.join(original_repository_files, 'repository')
    original_client = os.path.join(original_repository_files, 'client', 'test_repository1')
    original_keystore = os.path.join(original_repository_files, 'keystore')
    original_map_file = os.path.join(original_repository_files, 'map.json')

    # Save references to the often-needed client repository directories.
    # Test cases need these references to access metadata and target files.
    self.repository_directory = os.path.join(self.temporary_repository_root,
        'repository_server1')
    self.repository_directory2 = os.path.join(self.temporary_repository_root,
        'repository_server2')

    # Setting 'tuf.settings.repositories_directory' with the temporary client
    # directory copied from the original repository files.
    tuf.settings.repositories_directory = self.temporary_repository_root

    self.repository_name = 'test_repository1'
    self.repository_name2 = 'test_repository2'

    self.client_directory = os.path.join(self.temporary_repository_root,
        self.repository_name)
    self.client_directory2 = os.path.join(self.temporary_repository_root,
        self.repository_name2)

    self.keystore_directory = os.path.join(self.temporary_repository_root, 'keystore')
    self.map_file = os.path.join(self.client_directory, 'map.json')
    self.map_file2 = os.path.join(self.client_directory2, 'map.json')

    # Copy the original 'repository', 'client', and 'keystore' directories
    # to the temporary repository the test cases can use.
    shutil.copytree(original_repository, self.repository_directory)
    shutil.copytree(original_repository, self.repository_directory2)
    shutil.copytree(original_client, self.client_directory)
    shutil.copytree(original_client, self.client_directory2)
    shutil.copyfile(original_map_file, self.map_file)
    shutil.copyfile(original_map_file, self.map_file2)
    shutil.copytree(original_keystore, self.keystore_directory)

    # Launch a SimpleHTTPServer (serves files in the current directory).
    # Test cases will request metadata and target files that have been
    # pre-generated in 'tuf/tests/repository_data', which will be served by the
    # SimpleHTTPServer launched here.  The test cases of this unit test assume
    # the pre-generated metadata files have a specific structure, such
    # as a delegated role 'targets/role1', three target files, five key files,
    # etc.
    self.SERVER_PORT = random.SystemRandom().randint(30000, 45000)
    self.SERVER_PORT2 = random.SystemRandom().randint(30000, 45000)

    # Avoid duplicate port numbers, to prevent multiple localhosts from
    # listening on the same port.
    while self.SERVER_PORT == self.SERVER_PORT2:
      self.SERVER_PORT2 = random.SystemRandom().randint(30000, 45000)

    # Needed because in some tests simple_server.py cannot be found.
    # The reason is that the current working directory
    # has been changed when executing a subprocess.
    SIMPLE_SERVER_PATH = os.path.join(os.getcwd(), 'simple_server.py')

    command = ['python', SIMPLE_SERVER_PATH, str(self.SERVER_PORT)]
    command2 = ['python', SIMPLE_SERVER_PATH, str(self.SERVER_PORT2)]

    self.server_process = subprocess.Popen(command,
        cwd=self.repository_directory)

    logger.debug('Server process started.')
    logger.debug('Server process id: ' + str(self.server_process.pid))
    logger.debug('Serving on port: ' + str(self.SERVER_PORT))

    self.server_process2 = subprocess.Popen(command2,
        cwd=self.repository_directory2)


    logger.debug('Server process 2 started.')
    logger.debug('Server 2 process id: ' + str(self.server_process2.pid))
    logger.debug('Serving 2 on port: ' + str(self.SERVER_PORT2))
    self.url = 'http://localhost:' + str(self.SERVER_PORT) + os.path.sep
    self.url2 = 'http://localhost:' + str(self.SERVER_PORT2) + os.path.sep

    # NOTE: Following error is raised if a delay is not long enough:
    # <urlopen error [Errno 111] Connection refused>
    # or, on Windows:
    # Failed to establish a new connection: [Errno 111] Connection refused'
    # 0.3s led to occasional failures in automated builds, primarily on
    # AppVeyor, so increasing this to 2s, sadly.
    time.sleep(2)

    url_prefix = 'http://localhost:' + str(self.SERVER_PORT)
    url_prefix2 = 'http://localhost:' + str(self.SERVER_PORT2)

    self.repository_mirrors = {'mirror1': {'url_prefix': url_prefix,
                                           'metadata_path': 'metadata',
                                           'targets_path': 'targets',
                                           'confined_target_dirs': ['']}}

    self.repository_mirrors2 = {'mirror1': {'url_prefix': url_prefix2,
                                           'metadata_path': 'metadata',
                                           'targets_path': 'targets',
                                           'confined_target_dirs': ['']}}

    # Create the repository instances.  The test cases will use these client
    # updaters to refresh metadata, fetch target files, etc.
    self.repository_updater = updater.Updater(self.repository_name,
        self.repository_mirrors)
    self.repository_updater2 = updater.Updater(self.repository_name2,
        self.repository_mirrors2)


  def tearDown(self):
    # Modified_TestCase.tearDown() automatically deletes temporary files and
    # directories that may have been created during each test case.
    unittest_toolbox.Modified_TestCase.tearDown(self)

    # Kill the SimpleHTTPServer process.
    if self.server_process.returncode is None:
      logger.info('Server process ' + str(self.server_process.pid) + ' terminated.')
      self.server_process.kill()

    if self.server_process2.returncode is None:
      logger.info('Server 2 process ' + str(self.server_process2.pid) + ' terminated.')
      self.server_process2.kill()

    # updater.Updater() populates the roledb with the name "test_repository1"
    tuf.roledb.clear_roledb(clear_all=True)
    tuf.keydb.clear_keydb(clear_all=True)

    # Remove the temporary repository directory, which should contain all the
    # metadata, targets, and key files generated of all the test cases.
    # sleep for a bit to allow the kill'd server processes to terminate.
    time.sleep(.3)
    shutil.rmtree(self.temporary_directory)



  def test_update(self):
    self.assertEqual('test_repository1', str(self.repository_updater))
    self.assertEqual('test_repository2', str(self.repository_updater2))

    self.assertEqual(sorted(['role1', 'root', 'snapshot', 'targets', 'timestamp']),
        sorted(tuf.roledb.get_rolenames('test_repository1')))

    self.assertEqual(sorted(['role1', 'root', 'snapshot', 'targets', 'timestamp']),
        sorted(tuf.roledb.get_rolenames('test_repository2')))

    # Note: refresh() resets the known metadata and updates the latest
    # top-level metadata.
    self.repository_updater.refresh()

    self.assertEqual(sorted(['root', 'snapshot', 'targets', 'timestamp']),
        sorted(tuf.roledb.get_rolenames('test_repository1')))

    # test_repository2 wasn't refreshed and should still know about delegated
    # roles.
    self.assertEqual(sorted(['root', 'role1', 'snapshot', 'targets', 'timestamp']),
        sorted(tuf.roledb.get_rolenames('test_repository2')))

    # 'role1.json' should be downloaded, because it provides info for the
    # requested 'file3.txt'.
    valid_targetinfo = self.repository_updater.get_one_valid_targetinfo('file3.txt')

    self.assertEqual(sorted(['role2', 'role1', 'root', 'snapshot', 'targets', 'timestamp']),
        sorted(tuf.roledb.get_rolenames('test_repository1')))




  def test_repository_tool(self):

    self.assertEqual(self.repository_name, str(self.repository_updater))
    self.assertEqual(self.repository_name2, str(self.repository_updater2))

    repository = repo_tool.load_repository(self.repository_directory,
        self.repository_name)
    repository2 = repo_tool.load_repository(self.repository_directory2,
        self.repository_name2)

    repository.timestamp.version = 88
    self.assertEqual(['timestamp'], tuf.roledb.get_dirty_roles(
        self.repository_name))
    self.assertEqual([], tuf.roledb.get_dirty_roles(self.repository_name2))

    repository2.timestamp.version = 100
    self.assertEqual(['timestamp'], tuf.roledb.get_dirty_roles(
        self.repository_name2))

    key_file = os.path.join(self.keystore_directory, 'timestamp_key')
    timestamp_private = repo_tool.import_ed25519_privatekey_from_file(key_file, "password")

    repository.timestamp.load_signing_key(timestamp_private)
    repository2.timestamp.load_signing_key(timestamp_private)

    repository.write('timestamp', increment_version_number=False)
    repository2.write('timestamp', increment_version_number=False)

    # And move the staged metadata to the "live" metadata.
    shutil.rmtree(os.path.join(self.repository_directory, 'metadata'))
    shutil.rmtree(os.path.join(self.repository_directory2, 'metadata'))

    shutil.copytree(os.path.join(self.repository_directory, 'metadata.staged'),
        os.path.join(self.repository_directory, 'metadata'))
    shutil.copytree(os.path.join(self.repository_directory2, 'metadata.staged'),
        os.path.join(self.repository_directory2, 'metadata'))

    # Verify that the client retrieves the expected updates.
    logger.info('Downloading timestamp from server 1.')
    self.repository_updater.refresh()

    self.assertEqual(
        88, self.repository_updater.metadata['current']['timestamp']['version'])
    logger.info('Downloading timestamp from server 2.')
    self.repository_updater2.refresh()

    self.assertEqual(
        100, self.repository_updater2.metadata['current']['timestamp']['version'])

    # Test the behavior of the multi-repository updater.
    map_file = securesystemslib.util.load_json_file(self.map_file)
    map_file['repositories'][self.repository_name] = ['http://localhost:' + str(self.SERVER_PORT)]
    map_file['repositories'][self.repository_name2] = ['http://localhost:' + str(self.SERVER_PORT2)]
    with open(self.map_file, 'w') as file_object:
      file_object.write(json.dumps(map_file))

    # Try to load a non-existent map file.
    self.assertRaises(tuf.exceptions.Error, updater.MultiRepoUpdater, 'bad_path')

    multi_repo_updater = updater.MultiRepoUpdater(self.map_file)
    valid_targetinfo = multi_repo_updater.get_valid_targetinfo('file3.txt')

    for my_updater, my_targetinfo in six.iteritems(valid_targetinfo):
      my_updater.download_target(my_targetinfo, self.temporary_directory)
      self.assertTrue(os.path.exists(os.path.join(self.temporary_directory, 'file3.txt')))



if __name__ == '__main__':
  unittest.main()
