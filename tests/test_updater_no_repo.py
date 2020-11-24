#!/usr/bin/env python

# Copyright 2012 - 2017, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
<Program Name>
  test_updater.py

<Author>
  Konstantin Andrianov.

<Started>
  October 15, 2012.

  March 11, 2014.
    Refactored to remove mocked modules and old repository tool dependence, use
    exact repositories, and add realistic retrieval of files. -vladimir.v.diaz

<Copyright>
  See LICENSE-MIT OR LICENSE for licensing information.

<Purpose>
  'test_updater.py' provides a collection of methods that test the public /
  non-public methods and functions of 'tuf.client.updater.py'.

  The 'unittest_toolbox.py' module was created to provide additional testing
  tools, such as automatically deleting temporary files created in test cases.
  For more information, see 'tests/unittest_toolbox.py'.

<Methodology>
  Test cases here should follow a specific order (i.e., independent methods are
  tested before dependent methods). More accurately, least dependent methods
  are tested before most dependent methods.  There is no reason to rewrite or
  construct other methods that replicate already-tested methods solely for
  testing purposes.  This is possible because the 'unittest.TestCase' class
  guarantees the order of unit tests.  The 'test_something_A' method would
  be tested before 'test_something_B'.  To ensure the expected order of tests,
  a number is placed after 'test' and before methods name like so:
  'test_1_check_directory'.  The number is a measure of dependence, where 1 is
  less dependent than 2.
"""

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import os
import time
import shutil
import copy
import tempfile
import logging
import errno
import sys
import unittest

import tuf
import tuf.exceptions
import tuf.log
import tuf.unittest_toolbox as unittest_toolbox
import tuf.client.updater as updater

import utils

import securesystemslib
import six

from securesystemslib.interface import (
    import_ed25519_publickey_from_file,
    import_ed25519_privatekey_from_file,
    import_rsa_publickey_from_file,
    import_rsa_privatekey_from_file
)

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
        # Kills the server subprocess and closes the temp file used for logging.
        cls.server_process_handler.clean()

        # Remove the temporary repository directory, which should contain all the
        # metadata, targets, and key files generated for the test cases
        shutil.rmtree(cls.temporary_directory)



    def setUp(self):
        # We are inheriting from custom class.
        unittest_toolbox.Modified_TestCase.setUp(self)
        self.repository_name = 'test_repository1'

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
        original_client = os.path.join(original_repository_files, 'client')

        # Save references to the often-needed client repository directories.
        # Test cases need these references to access metadata and target files.
        self.repository_directory = \
        os.path.join(temporary_repository_root, 'repository')
        self.keystore_directory = \
        os.path.join(temporary_repository_root, 'keystore')

        self.client_directory = os.path.join(temporary_repository_root,
            'client')
        self.client_metadata = os.path.join(self.client_directory,
            self.repository_name, 'metadata', 'current')

        # Copy the original 'repository', 'client', and 'keystore' directories
        # to the temporary repository the test cases can use.
        shutil.copytree(original_repository, self.repository_directory)
        shutil.copytree(original_client, self.client_directory)
        shutil.copytree(original_keystore, self.keystore_directory)

        # 'path/to/tmp/repository' -> 'localhost:8001/tmp/repository'.
        repository_basepath = self.repository_directory[len(os.getcwd()):]
        url_prefix = 'http://localhost:' \
            + str(self.server_process_handler.port) + repository_basepath

        # Setting 'tuf.settings.repository_directory' with the temporary client
        # directory copied from the original repository files.
        tuf.settings.repositories_directory = self.client_directory

        self.repository_mirrors = {'mirror1': {'url_prefix': url_prefix,
                                            'metadata_path': 'metadata',
                                            'targets_path': 'targets',
                                            'confined_target_dirs': ['']}}

        # Creating a repository instance.  The test cases will use this client
        # updater to refresh metadata, fetch target files, etc.
        self.repository_updater = updater.Updater(self.repository_name,
                                                self.repository_mirrors)    

        # Metadata role keys are needed by the test cases to make changes to the
        # repository (e.g., adding a new target file to 'targets.json' and then
        # requesting a refresh()).
        self.role_keys = _load_role_keys(self.keystore_directory)



    def tearDown(self):
        # We are inheriting from custom class.
        unittest_toolbox.Modified_TestCase.tearDown(self)

        # Logs stdout and stderr from the sever subprocess.
        self.server_process_handler.flush_log()


    # UNIT TESTS.
    def test_refresh(self):
        self.repository_updater.refresh()




def _load_role_keys(keystore_directory):

    # Populating 'self.role_keys' by importing the required public and private
    # keys of 'tuf/tests/repository_data/'.  The role keys are needed when
    # modifying the remote repository used by the test cases in this unit test.

    # The pre-generated key files in 'repository_data/keystore' are all encrypted with
    # a 'password' passphrase.
    EXPECTED_KEYFILE_PASSWORD = 'password'

    # Store and return the cryptography keys of the top-level roles, including 1
    # delegated role.
    role_keys = {}

    root_key_file = os.path.join(keystore_directory, 'root_key')
    targets_key_file = os.path.join(keystore_directory, 'targets_key')
    snapshot_key_file = os.path.join(keystore_directory, 'snapshot_key')
    timestamp_key_file = os.path.join(keystore_directory, 'timestamp_key')
    delegation_key_file = os.path.join(keystore_directory, 'delegation_key')

    role_keys = {'root': {}, 'targets': {}, 'snapshot': {}, 'timestamp': {},
               'role1': {}}

    # Import the top-level and delegated role public keys.
    role_keys['root']['public'] = \
        import_rsa_publickey_from_file(root_key_file+'.pub')
    role_keys['targets']['public'] = \
        import_ed25519_publickey_from_file(targets_key_file+'.pub')
    role_keys['snapshot']['public'] = \
        import_ed25519_publickey_from_file(snapshot_key_file+'.pub')
    role_keys['timestamp']['public'] = \
        import_ed25519_publickey_from_file(timestamp_key_file+'.pub')
    role_keys['role1']['public'] = \
        import_ed25519_publickey_from_file(delegation_key_file+'.pub')

    # Import the private keys of the top-level and delegated roles.
    role_keys['root']['private'] = \
        import_rsa_privatekey_from_file(root_key_file,
                                              EXPECTED_KEYFILE_PASSWORD)
    role_keys['targets']['private'] = \
        import_ed25519_privatekey_from_file(targets_key_file,
                                              EXPECTED_KEYFILE_PASSWORD)
    role_keys['snapshot']['private'] = \
        import_ed25519_privatekey_from_file(snapshot_key_file,
                                              EXPECTED_KEYFILE_PASSWORD)
    role_keys['timestamp']['private'] = \
        import_ed25519_privatekey_from_file(timestamp_key_file,
                                              EXPECTED_KEYFILE_PASSWORD)
    role_keys['role1']['private'] = \
        import_ed25519_privatekey_from_file(delegation_key_file,
                                              EXPECTED_KEYFILE_PASSWORD)

    return role_keys


if __name__ == '__main__':
  utils.configure_test_logging(sys.argv)
  unittest.main()
