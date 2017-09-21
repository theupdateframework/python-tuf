#!/usr/bin/env python

"""
<Program Name>
  test_interpose_updater.py

<Author>
  Pankhuri Goyal <pankhurigoyal02@gmail.com>

<Started>
  August 2014.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Unit test for 'tuf.interposition.updater.py'.
"""

from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import os
import sys
import tempfile
import subprocess
import random
import shutil
import logging
import time
import copy
import json
import unittest

import tuf
import tuf.roledb
import tuf.keydb
import tuf.log
import tuf.interposition.updater as updater
import tuf.interposition.configuration as configuration
import tuf.unittest_toolbox as unittest_toolbox

import securesystemslib

logger = logging.getLogger('tuf.test_interpose_updater')


class TestUpdaterController(unittest_toolbox.Modified_TestCase):

  @classmethod
  def setUpClass(cls):
    # This method is called before tests in individual class are executed.

    # Create a temporary directory to store the repository, metadata, and
    # target files. 'temporary_directory' must be deleted in TearDownModule()
    # so that temporary files are always removed, even when exceptions occur.
    cls.temporary_directory = tempfile.mkdtemp(dir=os.getcwd())

    # Launch a SimpleHTTPServer (serves files in the current directory).
    # Test cases will request metadata and target files that have been
    # pre-generated in 'tuf/tests/repository_data', which will be served
    # by the SimpleHTTPServer launched here.  The test cases of
    # 'test_updater.py' assume the pre-generated metadata files have a specific
    # structure, such   as a delegated role 'targets/role1', three target
    # files, five key files,  etc.
    cls.SERVER_PORT = random.randint(30000, 45000)
    command = ['python', 'simple_server.py', str(cls.SERVER_PORT)]
    cls.server_process = subprocess.Popen(command, stderr=subprocess.PIPE)
    logger.info('\n\tServer process started.')
    logger.info('\tServer process id: '+str(cls.server_process.pid))
    logger.info('\tServing on port: '+str(cls.SERVER_PORT))
    cls.url = 'http://localhost:'+str(cls.SERVER_PORT) + os.path.sep

    time.sleep(1)



  @classmethod
  def tearDownClass(cls):
    # Remove the temporary directory after all the tests are done.
    shutil.rmtree(cls.temporary_directory)

    # Kill the SimpleHTTPServer Process
    if cls.server_process is None:
      message = '\tServer process ' + str(cls.server_process.pid) + \
                ' terminated.'
      logger.info(message)
      cls.server_process.kill()



  def setUp(self):
    # We are inheriting from custom class.
    unittest_toolbox.Modified_TestCase.setUp(self)

    self.repository_name = 'localhost'

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
    original_client = os.path.join(original_repository_files, 'client', 'test_repository')

    # Save references to the often-needed client repository directories.
    # Test cases need these references to access metadata and target files.
    self.repository_directory = \
      os.path.join(temporary_repository_root, 'repository')
    self.keystore_directory = \
      os.path.join(temporary_repository_root, 'keystore')
    self.client_directory = os.path.join(temporary_repository_root, 'client')
    self.client_metadata = os.path.join(self.client_directory,
        self.repository_name, 'metadata')
    self.client_metadata_current = os.path.join(self.client_metadata, 'current')
    self.client_metadata_previous = os.path.join(self.client_metadata, 'previous')

    # Copy the original 'repository', 'client', and 'keystore' directories
    # to the temporary repository the test cases can use.
    shutil.copytree(original_repository, self.repository_directory)
    shutil.copytree(original_client, os.path.join(self.client_directory, self.repository_name))
    shutil.copytree(original_keystore, self.keystore_directory)

    # 'path/to/tmp/repository' -> 'localhost:8001/tmp/repository'.
    repository_basepath = self.repository_directory[len(os.getcwd()):]

    # Test Set 1 -
    port = self.SERVER_PORT
    url_prefix = 'http://localhost:' + str(port) + repository_basepath

    # Setting 'tuf.settings.repository_directory' with the temporary client
    # directory copied from the original repository files.

    tuf.settings.repositories_directory = self.client_directory
    self.repository_mirrors = {'mirror': {'url_prefix': url_prefix,
                                           'metadata_path': 'metadata',
                                           'targets_path': 'targets',
                                           'confined_target_dirs': ['']}
                              }

    self.target_filepath = [{".*/targets":"/file1.txt"}]

    self.good_configuration = configuration.Configuration('localhost', 8001,
                                      self.client_directory,
                                      self.repository_mirrors,
                                      self.target_filepath, None)

    self.test1_configuration = configuration.Configuration('localhost', port,
                                      self.client_directory,
                                      self.repository_mirrors,
                                      'targets', None)

    self.test2_configuration = configuration.Configuration('localhost', 8002,
                                      self.client_directory,
                                      self.repository_mirrors,
                                      'targets', None)

    test_server_port=random.randint(30000, 45000)

    self.test3_configuration = configuration.Configuration('localhost',
                                                        test_server_port,
                                                        self.client_directory,
                                                        self.repository_mirrors,
                                                        'targets', None)

    url_prefix_test = \
      'http://localhost:' + str(test_server_port) + repository_basepath


    self.repository_mirrors = {'mirror': {'url_prefix': url_prefix_test,
                                          'metadata_path': 'metadata',
                                          'targets_path': 'targets',
                                          'confined_target_dirs': ['']}
                              }

    self.test4_configuration = configuration.Configuration('localhost', 8004,
                                      self.client_directory,
                                      self.repository_mirrors,
                                      'targets', None)



  def tearDown(self):
    # We are inheriting from custom class.
    unittest_toolbox.Modified_TestCase.tearDown(self)
    tuf.roledb.clear_roledb(clear_all=True)
    tuf.keydb.clear_keydb(clear_all=True)


  # Unit Tests
  def test_add(self):
    updater_controller = updater.UpdaterController()

    # Given good configuration, the UpdaterController.add() should work.
    updater_controller.add(self.good_configuration)

    # Instead of configuration, if some number is given.
    self.assertRaises(tuf.exceptions.InvalidConfigurationError, updater_controller.add, 8)

    # Hostname already exists, should raise exception.
    self.assertRaises(securesystemslib.exceptions.FormatError, updater_controller.add,
                      self.good_configuration)

    # Hostname already exists as a mirror, should raise an exception.
    self.assertRaises(securesystemslib.exceptions.FormatError, updater_controller.add,
                      self.test1_configuration)

    # Repository mirror already exists as another mirror.
    self.assertRaises(securesystemslib.exceptions.FormatError, updater_controller.add,
                      self.test2_configuration)

    # Remove the old updater.
    updater_controller.remove(self.good_configuration)

    # Add a new updater for this test.
    updater_controller.add(self.test3_configuration)

    # Repository mirror already exists as an updater.
    self.assertRaises(securesystemslib.exceptions.FormatError, updater_controller.add,
                      self.test4_configuration)

    # Remove the updater once the testing is completed.
    updater_controller.remove(self.test3_configuration)


  def test_refresh(self):
    updater_controller = updater.UpdaterController()

    # To check refresh() method, add a configuration for test.
    updater_controller.add(self.good_configuration)

    updater_controller.refresh(self.good_configuration)

    # Check for invalid configuration error.
    self.assertRaises(tuf.exceptions.InvalidConfigurationError,
                      updater_controller.refresh, 8)

    # Check if the updater not added in the updater list is refreshed, gives an
    # error or not.
    self.assertRaises(tuf.exceptions.NotFoundError, updater_controller.refresh,
                      self.test1_configuration)

    # Giving the same port number and network location as good_configuration.
    self.test4_configuration.port = 8001
    self.test4_configuration.network_location = 'localhost:8001'

    # Check if the mirror not added is refreshed, gives an error or not.
    self.assertRaises(tuf.exceptions.NotFoundError, updater_controller.refresh,
                      self.test4_configuration)

    # Make an object of tuf.interposition.updater.Updater of good configuration
    # for testing.
    good_updater = updater.Updater(self.good_configuration)
    good_updater.refresh()

    self.good_configuration.repository_mirrors['mirror']['url_prefix'] = \
      'http://localhost:99999999'

    # To check if a bad url_prefix of a mirror raises an exception or not.
    self.assertRaises(tuf.exceptions.NoWorkingMirrorError, good_updater.refresh)



  def test_get(self):
    updater_controller = updater.UpdaterController()

    updater_controller.add(self.good_configuration)

    url = 'http://localhost:8001'
    updater_controller.get(url)

    wrong_url = 'http://localhost:9999'
    updater_controller.get(wrong_url)

    good_updater = updater.Updater(self.good_configuration)
    self.assertRaises(tuf.exceptions.URLMatchesNoPatternError,
                      good_updater.get_target_filepath, url)



  def test_remove(self):
    updater_controller = updater.UpdaterController()

    # To check remove() method, add a configuration for test.
    updater_controller.add(self.good_configuration)

    # Check for invalid configuration error.
    self.assertRaises(tuf.exceptions.InvalidConfigurationError,
                      updater_controller.remove, 8)

    self.assertRaises(tuf.exceptions.NotFoundError, updater_controller.remove,
                      self.test1_configuration)

    # Giving the same port number and network location as good_configuration.
    self.test4_configuration.port = 8001
    self.test4_configuration.network_location = 'localhost:8001'

    self.assertRaises(tuf.exceptions.NotFoundError, updater_controller.remove,
                      self.test4_configuration)


class TestUpdater(unittest_toolbox.Modified_TestCase):

  @classmethod
  def setUpClass(cls):
    # This method is called before tests in individual class are executed.

    # Create a temporary directory to store the repository, metadata, and
    # target files. 'temporary_directory' must be deleted in TearDownModule()
    # so that temporary files are always removed, even when exceptions occur.
    cls.temporary_directory = tempfile.mkdtemp(dir=os.getcwd())

    # Launch a SimpleHTTPServer (serves files in the current directory).
    # Test cases will request metadata and target files that have been
    # pre-generated in 'tuf/tests/repository_data', which will be served
    # by the SimpleHTTPServer launched here.  The test cases of
    # 'test_updater.py' assume the pre-generated metadata files have a specific
    # structure, such   as a delegated role 'targets/role1', three target
    # files, five key files,  etc.
    cls.SERVER_PORT = random.randint(30000, 45000)
    command = ['python', 'simple_server.py', str(cls.SERVER_PORT)]
    cls.server_process = subprocess.Popen(command, stderr=subprocess.PIPE)
    logger.info('\n\tServer process started.')
    logger.info('\tServer process id: '+str(cls.server_process.pid))
    logger.info('\tServing on port: '+str(cls.SERVER_PORT))
    cls.url = 'http://localhost:'+str(cls.SERVER_PORT) + os.path.sep

    time.sleep(1)

  @classmethod
  def tearDownClass(cls):
    # Remove the temporary directory after all the tests are done.
    shutil.rmtree(cls.temporary_directory)

    # Kill the SimpleHTTPServer Process
    if cls.server_process is None:
      message = '\tServer process ' + str(cls.server_process.pid) + \
                ' terminated.'
      logger.info(message)
      cls.server_process.kill()


  def setUp(self):
    # We are inheriting from custom class.
    unittest_toolbox.Modified_TestCase.setUp(self)

    self.repository_name = 'localhost'

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
    original_client = os.path.join(original_repository_files, 'client', 'test_repository')

    # Save references to the often-needed client repository directories.
    # Test cases need these references to access metadata and target files.
    self.repository_directory = \
      os.path.join(temporary_repository_root, 'repository')
    self.keystore_directory = \
      os.path.join(temporary_repository_root, 'keystore')
    self.client_directory = os.path.join(temporary_repository_root, 'client')
    self.client_metadata = os.path.join(self.client_directory, 'metadata')
    self.client_metadata_current = os.path.join(self.client_metadata, 'current')
    self.client_metadata_previous = os.path.join(self.client_metadata, 'previous')

    # Copy the original 'repository', 'client', and 'keystore' directories
    # to the temporary repository the test cases can use.
    shutil.copytree(original_repository, self.repository_directory)
    shutil.copytree(original_client, os.path.join(self.client_directory, self.repository_name))
    shutil.copytree(original_keystore, self.keystore_directory)

    # 'path/to/tmp/repository' -> 'localhost:8001/tmp/repository'.
    repository_basepath = self.repository_directory[len(os.getcwd()):]

    # Test Set 1 -
    port = self.SERVER_PORT
    url_prefix = 'http://localhost:' + str(port) + repository_basepath

    # Setting 'tuf.settings.repository_directory' with the temporary client
    # directory copied from the original repository files.
    tuf.settings.repositories_directory = self.client_directory

    self.repository_mirrors = {'mirror': {'url_prefix': url_prefix,
                                          'metadata_path': 'metadata',
                                          'targets_path': 'targets',
                                          'confined_target_dirs': ['']}
                              }

    self.target_paths = [{".*/targets":"/file1.txt"}]

    self.good_configuration = configuration.Configuration('localhost', 8001,
                                      self.client_directory,
                                      self.repository_mirrors,
                                      self.target_paths, None)



  def tearDown(self):
    # We are inheriting from custom class.
    unittest_toolbox.Modified_TestCase.tearDown(self)
    tuf.roledb.clear_roledb('localhost')
    tuf.keydb.clear_keydb('localhost')


  # Unit Tests
  def test_download_target(self):
    myUpdater = updater.Updater(self.good_configuration)

    target_filepath = 'file.txt'
    self.assertRaises(tuf.exceptions.UnknownTargetError, myUpdater.download_target,
                      target_filepath)

    self.assertRaises(securesystemslib.exceptions.FormatError, myUpdater.download_target, 8)

    target_filepath = 'file1.txt'
    myUpdater.download_target(target_filepath)


  def test_get_target_filepath(self):
    myUpdater = updater.Updater(self.good_configuration)

    self.assertRaises(AttributeError, myUpdater.get_target_filepath, 8)

    test_source_url = 'http://localhost:9999'
    self.assertRaises(tuf.exceptions.URLMatchesNoPatternError,
                      myUpdater.get_target_filepath, test_source_url)

    test_source_url = 'http://localhost:8001/targets/file.txt'
    myUpdater.get_target_filepath(test_source_url)


  def test_open(self):
    myUpdater = updater.Updater(self.good_configuration)

    self.assertRaises(AttributeError, myUpdater.open, 8)

    url = 'http://localhost:8001/targets/file1.txt'
    interposition_file = \
      os.path.join(self.temporary_directory, 'interposition.json')
    myUpdater.open(url, interposition_file)


  def test_retrieve(self):
    myUpdater = updater.Updater(self.good_configuration)

    self.assertRaises(AttributeError, myUpdater.retrieve, 8)

    test_source_url = 'http://localhost:8001/targets/file1.txt'
    interposition_file = \
      os.path.join(self.temporary_directory, 'interposition.json')
    myUpdater.retrieve(test_source_url, interposition_file)

    #self.assertRaises(tuf.exceptions.NoWorkingMirrorError, myUpdater.retrieve, test_source_url)

    test_source_url = 'http://6767:localhost'
    self.assertRaises(tuf.exceptions.URLMatchesNoPatternError, myUpdater.retrieve,
                      test_source_url)

    test_source_url = 'http://localhost:8001/targets/file1.txt'
    myUpdater.retrieve(test_source_url)


if __name__ == '__main__':
  unittest.main()
