#!/usr/bin/env python

"""
<Program Name>
  test_multiple_repositories_integration.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  February 2, 2017

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Verify that clients are able to keep track of multiple repositories and
  separate sets of metadata for each.

  TODO: Verify that multiple repositories can be set for the repository tool.
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

import tuf
import tuf.log
import tuf.roledb
import tuf.client.updater as updater
import tuf.settings
import tuf.unittest_toolbox as unittest_toolbox
import tuf.repository_tool as repo_tool

logger = logging.getLogger('test_multiple_repositories_integration')
repo_tool.disable_console_log_messages()


class TestMultipleRepositoriesIntegration(unittest_toolbox.Modified_TestCase):

  @classmethod
  def setUpClass(cls):
    # setUpClass() is called before any of the test cases are executed.

    # Create a temporary directory to store the repository, metadata, and
    # target files.  'temporary_directory' must be deleted in TearDownModule()
    # so that temporary files are always removed, even when exceptions occur.
    cls.temporary_directory = tempfile.mkdtemp(dir=os.getcwd())

    # Launch a SimpleHTTPServer (serves files in the current directory).
    # Test cases will request metadata and target files that have been
    # pre-generated in 'tuf/tests/repository_data', which will be served by the
    # SimpleHTTPServer launched here.  The test cases of this unit test assume
    # the pre-generated metadata files have a specific structure, such
    # as a delegated role 'targets/role1', three target files, five key files,
    # etc.
    cls.SERVER_PORT = random.randint(30000, 45000)
    cls.SERVER_PORT2 = random.randint(30000, 45000)
    command = ['python', 'simple_server.py', str(cls.SERVER_PORT)]
    command2 = ['python', 'simple_server.py', str(cls.SERVER_PORT2)]
    cls.server_process = subprocess.Popen(command, stderr=subprocess.PIPE)
    cls.server_process2 = subprocess.Popen(command2, stderr=subprocess.PIPE)
    logger.info('Server processes started.')
    logger.info('Server process id: ' + str(cls.server_process.pid))
    logger.info('Serving on port: ' + str(cls.SERVER_PORT))
    logger.info('Server 2 process id: ' + str(cls.server_process2.pid))
    logger.info('Serving 2  on port: ' + str(cls.SERVER_PORT2))
    cls.url = 'http://localhost:' + str(cls.SERVER_PORT) + os.path.sep
    cls.url2 = 'http://localhost:' + str(cls.SERVER_PORT2) + os.path.sep

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

    if cls.server_process2.returncode is None:
      logger.info('Server 2 process ' + str(cls.server_process2.pid) + ' terminated.')
      cls.server_process2.kill()



  def setUp(self):
    # We are inheriting from custom class.
    unittest_toolbox.Modified_TestCase.setUp(self)

    # Copy the original repository files provided in the test folder so that
    # any modifications made to repository files are restricted to the copies.
    # The 'repository_data' directory is expected to exist in 'tuf/tests/'.
    original_repository_files = os.path.join(os.getcwd(), 'repository_data')
    temporary_repository_root = self.make_temp_directory(directory=
        self.temporary_directory)

    # The original repository, keystore, and client directories will be copied
    # for each test case.
    original_repository = os.path.join(original_repository_files, 'repository')
    original_client = os.path.join(original_repository_files, 'client', 'test_repository')

    # Save references to the often-needed client repository directories.
    # Test cases need these references to access metadata and target files.
    self.repository_directory = os.path.join(temporary_repository_root,
        'repository_server1')
    self.repository_directory2 = os.path.join(temporary_repository_root,
        'repository_server2')

    # Setting 'tuf.settings.repositories_directory' with the temporary client
    # directory copied from the original repository files.
    tuf.settings.repositories_directory = temporary_repository_root

    repository_name = 'repository1'
    repository_name2 = 'repository2'
    self.client_directory = os.path.join(temporary_repository_root, repository_name)
    self.client_directory2 = os.path.join(temporary_repository_root, repository_name2)

    # Copy the original 'repository', 'client', and 'keystore' directories
    # to the temporary repository the test cases can use.
    shutil.copytree(original_repository, self.repository_directory)
    shutil.copytree(original_repository, self.repository_directory2)
    shutil.copytree(original_client, self.client_directory)
    shutil.copytree(original_client, self.client_directory2)

    # Set the url prefix required by the 'tuf/client/updater.py' updater.
    # 'path/to/tmp/repository' -> 'localhost:8001/tmp/repository'.
    repository_basepath = self.repository_directory[len(os.getcwd()):]
    url_prefix = \
      'http://localhost:' + str(self.SERVER_PORT) + repository_basepath
    url_prefix2 = \
      'http://localhost:' + str(self.SERVER_PORT2) + repository_basepath

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
    self.repository_updater = updater.Updater(repository_name,
        self.repository_mirrors)
    self.repository_updater2 = updater.Updater(repository_name2,
        self.repository_mirrors2)


  def tearDown(self):
    # Modified_TestCase.tearDown() automatically deletes temporary files and
    # directories that may have been created during each test case.
    unittest_toolbox.Modified_TestCase.tearDown(self)

    # updater.Updater() populates the roledb with the name "test_repository"
    tuf.roledb.clear_roledb(clear_all=True)
    tuf.keydb.clear_keydb(clear_all=True)


  def test_update(self):
    self.assertEqual('repository1', str(self.repository_updater))
    self.assertEqual('repository2', str(self.repository_updater2))

    self.assertEqual(sorted(['role1', 'root', 'snapshot', 'targets', 'timestamp']),
        sorted(tuf.roledb.get_rolenames('repository1')))

    self.assertEqual(sorted(['role1', 'root', 'snapshot', 'targets', 'timestamp']),
        sorted(tuf.roledb.get_rolenames('repository2')))

    self.repository_updater.refresh()

    self.assertEqual(sorted(['role1', 'root', 'snapshot', 'targets', 'timestamp']),
        sorted(tuf.roledb.get_rolenames('repository1')))
    self.assertEqual(sorted(['role1', 'root', 'snapshot', 'targets', 'timestamp']),
        sorted(tuf.roledb.get_rolenames('repository2')))

    # 'role1.json' should be downloaded, because it provides info for the
    # requested 'file3.txt'.
    valid_targetinfo = self.repository_updater.get_one_valid_targetinfo('file3.txt')

    self.assertEqual(sorted(['role2', 'role1', 'root', 'snapshot', 'targets', 'timestamp']),
        sorted(tuf.roledb.get_rolenames('repository1')))


  def test_repository_tool(self):
    repository_name1 = 'repository1'
    repository_name2 = 'repository2'

    self.assertEqual(repository_name1, str(self.repository_updater))
    self.assertEqual(repository_name2, str(self.repository_updater2))

    repository1 = repo_tool.load_repository(self.repository_directory, repository_name1)
    repository2 = repo_tool.load_repository(self.repository_directory2, repository_name2)

    repository2.timestamp.version = 2
    self.assertEqual([], tuf.roledb.get_dirty_roles(repository_name1))
    self.assertEqual(['timestamp'], tuf.roledb.get_dirty_roles(repository_name2))


if __name__ == '__main__':
  unittest.main()
