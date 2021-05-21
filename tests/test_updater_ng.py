#!/usr/bin/env python

# Copyright 2021, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Test Updater class
"""

import os
import time
import shutil
import copy
import tempfile
import logging
import errno
import sys
import unittest
import json
import tracemalloc

if sys.version_info >= (3, 3):
  import unittest.mock as mock
else:
  import mock

import tuf
import tuf.exceptions
import tuf.log
import tuf.repository_tool as repo_tool
import tuf.unittest_toolbox as unittest_toolbox

from tests import utils
from tuf.api import metadata
from tuf import ngclient

import securesystemslib

logger = logging.getLogger(__name__)


class TestUpdater(unittest_toolbox.Modified_TestCase):

  @classmethod
  def setUpClass(cls):
    # Create a temporary directory to store the repository, metadata, and target
    # files.  'temporary_directory' must be deleted in TearDownModule() so that
    # temporary files are always removed, even when exceptions occur.
    cls.temporary_directory = tempfile.mkdtemp(dir=os.getcwd())

    # Needed because in some tests simple_server.py cannot be found.
    # The reason is that the current working directory
    # has been changed when executing a subprocess.
    cls.SIMPLE_SERVER_PATH = os.path.join(os.getcwd(), 'simple_server.py')

    # Launch a SimpleHTTPServer (serves files in the current directory).
    # Test cases will request metadata and target files that have been
    # pre-generated in 'tuf/tests/repository_data', which will be served
    # by the SimpleHTTPServer launched here.  The test cases of 'test_updater.py'
    # assume the pre-generated metadata files have a specific structure, such
    # as a delegated role 'targets/role1', three target files, five key files,
    # etc.
    cls.server_process_handler = utils.TestServerProcess(log=logger,
        server=cls.SIMPLE_SERVER_PATH)



  @classmethod
  def tearDownClass(cls):
    # Cleans the resources and flush the logged lines (if any).
    cls.server_process_handler.clean()

    # Remove the temporary repository directory, which should contain all the
    # metadata, targets, and key files generated for the test cases
    shutil.rmtree(cls.temporary_directory)



  def setUp(self):
    # We are inheriting from custom class.
    unittest_toolbox.Modified_TestCase.setUp(self)

    # Copy the original repository files provided in the test folder so that
    # any modifications made to repository files are restricted to the copies.
    # The 'repository_data' directory is expected to exist in 'tuf.tests/'.
    original_repository_files = os.path.join(os.getcwd(), 'repository_data')
    temporary_repository_root = \
      self.make_temp_directory(directory=self.temporary_directory)

    # The original repository, keystore, and client directories will be copied
    # for each test case.
    original_repository = os.path.join(original_repository_files, 'repository')
    original_keystore = os.path.join(original_repository_files, 'keystore')
    original_client = os.path.join(original_repository_files, 'client', 'test_repository1', 'metadata', 'current')

    # Save references to the often-needed client repository directories.
    # Test cases need these references to access metadata and target files.
    self.repository_directory = \
      os.path.join(temporary_repository_root, 'repository')
    self.keystore_directory = \
      os.path.join(temporary_repository_root, 'keystore')

    self.client_directory = os.path.join(temporary_repository_root, 'client')

    # Copy the original 'repository', 'client', and 'keystore' directories
    # to the temporary repository the test cases can use.
    shutil.copytree(original_repository, self.repository_directory)
    shutil.copytree(original_client, self.client_directory)
    shutil.copytree(original_keystore, self.keystore_directory)

    # 'path/to/tmp/repository' -> 'localhost:8001/tmp/repository'.
    repository_basepath = self.repository_directory[len(os.getcwd()):]
    url_prefix = 'http://' + utils.TEST_HOST_ADDRESS + ':' \
        + str(self.server_process_handler.port) + repository_basepath

    metadata_url = f"{url_prefix}/metadata/"
    targets_url = f"{url_prefix}/targets/"
    # Creating a repository instance.  The test cases will use this client
    # updater to refresh metadata, fetch target files, etc.
    self.repository_updater = ngclient.Updater(self.client_directory,
                                              metadata_url,
                                              targets_url)

  def tearDown(self):
    # We are inheriting from custom class.
    unittest_toolbox.Modified_TestCase.tearDown(self)

    # Logs stdout and stderr from the sever subprocess.
    self.server_process_handler.flush_log()

  def test_refresh(self):
    # All metadata is in local directory already
    self.repository_updater.refresh()

    # Get targetinfo for 'file1.txt' listed in targets
    targetinfo1 = self.repository_updater.get_one_valid_targetinfo('file1.txt')
    # Get targetinfo for 'file3.txt' listed in the delegated role1
    targetinfo3= self.repository_updater.get_one_valid_targetinfo('file3.txt')

    destination_directory = self.make_temp_directory()
    updated_targets = self.repository_updater.updated_targets([targetinfo1, targetinfo3],
                                                      destination_directory)

    self.assertListEqual(updated_targets, [targetinfo1, targetinfo3])

    self.repository_updater.download_target(targetinfo1, destination_directory)
    updated_targets = self.repository_updater.updated_targets(updated_targets,
                                                      destination_directory)

    self.assertListEqual(updated_targets, [targetinfo3])


    self.repository_updater.download_target(targetinfo3, destination_directory)
    updated_targets = self.repository_updater.updated_targets(updated_targets,
                                                  destination_directory)

    self.assertListEqual(updated_targets, [])

  def test_refresh_with_only_local_root(self):
    os.remove(os.path.join(self.client_directory, "timestamp.json"))
    os.remove(os.path.join(self.client_directory, "snapshot.json"))
    os.remove(os.path.join(self.client_directory, "targets.json"))
    os.remove(os.path.join(self.client_directory, "role1.json"))

    self.repository_updater.refresh()

    # Get targetinfo for 'file3.txt' listed in the delegated role1
    targetinfo3= self.repository_updater.get_one_valid_targetinfo('file3.txt')

if __name__ == '__main__':
  utils.configure_test_logging(sys.argv)
  unittest.main()
