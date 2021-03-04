#!/usr/bin/env python

# Copyright 2013 - 2017, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
<Program Name>
  test_extraneous_dependencies_attack.py

<Author>
  Zane Fisher.

<Started>
  August 19, 2013.

  April 6, 2014.
    Refactored to use the 'unittest' module (test conditions in code, rather
    than verifying text output), use pre-generated repository files, and
    discontinue use of the old repository tools.  Modify the previous scenario
    simulated for the mix-and-match attack.  The metadata that specified the
    dependencies of a project modified (previously a text file.)
    -vladimir.v.diaz

<Copyright>
  See LICENSE-MIT OR LICENSE for licensing information.

<Purpose>
  Simulate an extraneous dependencies attack.  The client attempts to download
  a file, which lists all the target dependencies, with one legitimate
  dependency, and one extraneous dependency.  A client should not download a
  target dependency even if it is found on the repository.  Valid targets are
  listed and verified by TUF metadata, such as 'targets.txt'.

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
import shutil
import json
import logging
import unittest
import sys

import tuf.formats
import tuf.log
import tuf.client.updater as updater
import tuf.roledb
import tuf.keydb
from tuf import unittest_toolbox

from tests import utils

import securesystemslib
import six

logger = logging.getLogger(__name__)



class TestExtraneousDependenciesAttack(unittest_toolbox.Modified_TestCase):

  @classmethod
  def setUpClass(cls):

    # Launch a SimpleHTTPServer (serves files in the current directory).
    # Test cases will request metadata and target files that have been
    # pre-generated in 'tuf/tests/repository_data', which will be served by the
    # SimpleHTTPServer launched here.  The test cases of this unit test assume
    # the pre-generated metadata files have a specific structure, such
    # as a delegated role 'targets/role1', three target files, five key files,
    # etc.
    cls.server_process_handler = utils.TestServerProcess(log=logger)



  @classmethod
  def tearDownClass(cls):
    # Cleans the resources and flush the logged lines (if any).
    cls.server_process_handler.clean()




  def setUp(self):
    super().setUp()

    self.repository_name = 'test_repository1'

    # Copy the original repository files provided in the test folder so that
    # any modifications made to repository files are restricted to the copies.
    # The 'repository_data' directory is expected to exist in 'tuf/tests/'.
    original_repository_files = os.path.join(os.getcwd(), 'repository_data')
    temporary_repository_root = \
        self.make_temp_directory(directory=os.getcwd())

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

    # Set the url prefix required by the 'tuf/client/updater.py' updater.
    # 'path/to/tmp/repository' -> 'localhost:8001/tmp/repository'.
    repository_basepath = self.repository_directory[len(os.getcwd()):]
    url_prefix = 'http://' + utils.TEST_HOST_ADDRESS + ':' \
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
    super().tearDown()
    tuf.roledb.clear_roledb(clear_all=True)
    tuf.keydb.clear_keydb(clear_all=True)

    # Logs stdout and stderr from the sever subprocess.
    self.server_process_handler.flush_log()


  def test_with_tuf(self):
    # An attacker tries to trick a client into installing an extraneous target
    # file (a valid file on the repository, in this case) by listing it in the
    # project's metadata file.  For the purposes of test_with_tuf(),
    # 'role1.json' is treated as the metadata file that indicates all
    # the files needed to install/update the 'role1' project.  The attacker
    # simply adds the extraneous target file to 'role1.json', which the TUF
    # client should reject as improperly signed.
    role1_filepath = os.path.join(self.repository_directory, 'metadata',
                                  'role1.json')
    file1_filepath = os.path.join(self.repository_directory, 'targets',
                                  'file1.txt')
    length, hashes = securesystemslib.util.get_file_details(file1_filepath)

    role1_metadata = securesystemslib.util.load_json_file(role1_filepath)
    role1_metadata['signed']['targets']['/file2.txt'] = {}
    role1_metadata['signed']['targets']['/file2.txt']['hashes'] = hashes
    role1_metadata['signed']['targets']['/file2.txt']['length'] = length

    tuf.formats.check_signable_object_format(role1_metadata)

    with open(role1_filepath, 'wt') as file_object:
      json.dump(role1_metadata, file_object, indent=1, sort_keys=True)

    # Un-install the metadata of the top-level roles so that the client can
    # download and detect the invalid 'role1.json'.
    os.remove(os.path.join(self.client_directory, self.repository_name,
        'metadata', 'current', 'snapshot.json'))
    os.remove(os.path.join(self.client_directory, self.repository_name,
        'metadata', 'current', 'targets.json'))
    os.remove(os.path.join(self.client_directory, self.repository_name,
        'metadata', 'current', 'timestamp.json'))
    os.remove(os.path.join(self.client_directory, self.repository_name,
        'metadata', 'current', 'role1.json'))

    # Verify that the TUF client rejects the invalid metadata and refuses to
    # continue the update process.
    self.repository_updater.refresh()

    try:
      with utils.ignore_deprecation_warnings('tuf.client.updater'):
        self.repository_updater.targets_of_role('role1')

    # Verify that the specific 'tuf.exceptions.ForbiddenTargetError' exception is raised
    # by each mirror.
    except tuf.exceptions.NoWorkingMirrorError as exception:
      for mirror_url, mirror_error in six.iteritems(exception.mirror_errors):
        url_prefix = self.repository_mirrors['mirror1']['url_prefix']
        url_file = os.path.join(url_prefix, 'metadata', 'role1.json')

        # Verify that 'role1.json' is the culprit.
        self.assertEqual(url_file.replace('\\', '/'), mirror_url)
        self.assertTrue(isinstance(mirror_error, securesystemslib.exceptions.BadSignatureError))

    else:
      self.fail('TUF did not prevent an extraneous dependencies attack.')


if __name__ == '__main__':
  utils.configure_test_logging(sys.argv)
  unittest.main()
