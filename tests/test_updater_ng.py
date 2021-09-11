#!/usr/bin/env python

# Copyright 2021, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Test Updater class
"""

import os
import shutil
import tempfile
import logging
import sys
from typing import List
import unittest
import tuf.unittest_toolbox as unittest_toolbox

from tests import utils
from tuf.api.metadata import Metadata
from tuf import exceptions, ngclient
from securesystemslib.signer import SSlibSigner
from securesystemslib.interface import import_rsa_privatekey_from_file

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
        cls.SIMPLE_SERVER_PATH = os.path.join(os.getcwd(), "simple_server.py")

        # Launch a SimpleHTTPServer (serves files in the current directory).
        # Test cases will request metadata and target files that have been
        # pre-generated in 'tuf/tests/repository_data', which will be served
        # by the SimpleHTTPServer launched here.
        cls.server_process_handler = utils.TestServerProcess(
            log=logger, server=cls.SIMPLE_SERVER_PATH
        )

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
        original_repository_files = os.path.join(os.getcwd(), "repository_data")
        temporary_repository_root = self.make_temp_directory(
            directory=self.temporary_directory
        )

        # The original repository, keystore, and client directories will be copied
        # for each test case.
        original_repository = os.path.join(
            original_repository_files, "repository"
        )
        original_keystore = os.path.join(original_repository_files, "keystore")
        original_client = os.path.join(
            original_repository_files,
            "client",
            "test_repository1",
            "metadata",
            "current",
        )

        # Save references to the often-needed client repository directories.
        # Test cases need these references to access metadata and target files.
        self.repository_directory = os.path.join(
            temporary_repository_root, "repository"
        )
        self.keystore_directory = os.path.join(
            temporary_repository_root, "keystore"
        )

        self.client_directory = os.path.join(
            temporary_repository_root, "client"
        )

        # Copy the original 'repository', 'client', and 'keystore' directories
        # to the temporary repository the test cases can use.
        shutil.copytree(original_repository, self.repository_directory)
        shutil.copytree(original_client, self.client_directory)
        shutil.copytree(original_keystore, self.keystore_directory)

        # 'path/to/tmp/repository' -> 'localhost:8001/tmp/repository'.
        repository_basepath = self.repository_directory[len(os.getcwd()) :]
        url_prefix = (
            "http://"
            + utils.TEST_HOST_ADDRESS
            + ":"
            + str(self.server_process_handler.port)
            + repository_basepath
        )

        self.metadata_url = f"{url_prefix}/metadata/"
        self.targets_url = f"{url_prefix}/targets/"
        self.destination_directory = self.make_temp_directory()
        # Creating a repository instance.  The test cases will use this client
        # updater to refresh metadata, fetch target files, etc.
        self.repository_updater = ngclient.Updater(
            self.client_directory, self.metadata_url, self.targets_url
        )

    def tearDown(self):
        # We are inheriting from custom class.
        unittest_toolbox.Modified_TestCase.tearDown(self)

        # Logs stdout and stderr from the sever subprocess.
        self.server_process_handler.flush_log()

    def _create_consistent_target(
        self, targetname: str, target_hash: str
    ) -> None:
        """Create consistent targets copies of their non-consistent counterparts
        inside the repository directory.

        Args:
          targetname: A string denoting the name of the target file.
          target_hash: A string denoting the hash of the target.

        """
        consistent_target_name = f"{target_hash}.{targetname}"
        source_path = os.path.join(
            self.repository_directory, "targets", targetname
        )
        destination_path = os.path.join(
            self.repository_directory, "targets", consistent_target_name
        )
        shutil.copy(source_path, destination_path)

    def _modify_repository_root(
        self, modification_func, bump_version=False
    ) -> None:
        """Apply 'modification_func' to root and persist it."""
        role_path = os.path.join(
            self.repository_directory, "metadata", "root.json"
        )
        root = Metadata.from_file(role_path)
        modification_func(root)
        if bump_version:
            root.signed.bump_version()
        root_key_path = os.path.join(self.keystore_directory, "root_key")
        root_key_dict = import_rsa_privatekey_from_file(
            root_key_path, password="password"
        )
        signer = SSlibSigner(root_key_dict)
        root.sign(signer)
        root.to_file(
            os.path.join(self.repository_directory, "metadata", "root.json")
        )
        root.to_file(
            os.path.join(
                self.repository_directory,
                "metadata",
                f"{root.signed.version}.root.json",
            )
        )

    def _assert_files(self, roles: List[str]):
        """Assert that local metadata files exist for 'roles'"""
        expected_files = [f"{role}.json" for role in roles]
        client_files = sorted(os.listdir(self.client_directory))
        self.assertEqual(client_files, expected_files)

    def test_refresh_on_consistent_targets(self):
        # Generate a new root version where consistent_snapshot is set to true
        def consistent_snapshot_modifier(root):
            root.signed.consistent_snapshot = True

        self._modify_repository_root(
            consistent_snapshot_modifier, bump_version=True
        )
        self.repository_updater = ngclient.Updater(
            self.client_directory, self.metadata_url, self.targets_url
        )

        # All metadata is in local directory already
        self.repository_updater.refresh()
        # Make sure that consistent snapshot is enabled
        self.assertTrue(
            self.repository_updater._trusted_set.root.signed.consistent_snapshot
        )
        # Get targetinfo for "file1.txt" listed in targets
        targetinfo1 = self.repository_updater.get_one_valid_targetinfo(
            "file1.txt"
        )
        # Get targetinfo for "file3.txt" listed in the delegated role1
        targetinfo3 = self.repository_updater.get_one_valid_targetinfo(
            "file3.txt"
        )

        # Create consistent targets with file path HASH.FILENAME.EXT
        target1_hash = list(targetinfo1.hashes.values())[0]
        target3_hash = list(targetinfo3.hashes.values())[0]
        self._create_consistent_target("file1.txt", target1_hash)
        self._create_consistent_target("file3.txt", target3_hash)

        updated_targets = self.repository_updater.updated_targets(
            [targetinfo1, targetinfo3], self.destination_directory
        )

        self.assertListEqual(updated_targets, [targetinfo1, targetinfo3])
        self.repository_updater.download_target(
            targetinfo1, self.destination_directory
        )
        updated_targets = self.repository_updater.updated_targets(
            updated_targets, self.destination_directory
        )

        self.assertListEqual(updated_targets, [targetinfo3])

        self.repository_updater.download_target(
            targetinfo3, self.destination_directory
        )
        updated_targets = self.repository_updater.updated_targets(
            updated_targets, self.destination_directory
        )

        self.assertListEqual(updated_targets, [])

    def test_refresh_and_download(self):
        # Test refresh without consistent targets - targets without hash prefixes.

        # top-level targets are already in local cache (but remove others)
        os.remove(os.path.join(self.client_directory, "role1.json"))
        os.remove(os.path.join(self.client_directory, "role2.json"))
        os.remove(os.path.join(self.client_directory, "1.root.json"))

        # top-level metadata is in local directory already
        self.repository_updater.refresh()
        self._assert_files(["root", "snapshot", "targets", "timestamp"])

        # Get targetinfo for 'file1.txt' listed in targets
        targetinfo1 = self.repository_updater.get_one_valid_targetinfo(
            "file1.txt"
        )
        self._assert_files(["root", "snapshot", "targets", "timestamp"])
        # Get targetinfo for 'file3.txt' listed in the delegated role1
        targetinfo3 = self.repository_updater.get_one_valid_targetinfo(
            "file3.txt"
        )
        expected_files = ["role1", "root", "snapshot", "targets", "timestamp"]
        self._assert_files(expected_files)

        updated_targets = self.repository_updater.updated_targets(
            [targetinfo1, targetinfo3], self.destination_directory
        )

        self.assertListEqual(updated_targets, [targetinfo1, targetinfo3])

        self.repository_updater.download_target(
            targetinfo1, self.destination_directory
        )
        updated_targets = self.repository_updater.updated_targets(
            updated_targets, self.destination_directory
        )

        self.assertListEqual(updated_targets, [targetinfo3])

        # Check that duplicates are excluded
        updated_targets = self.repository_updater.updated_targets(
            [targetinfo3, targetinfo3], self.destination_directory
        )
        self.assertListEqual(updated_targets, [targetinfo3])

        self.repository_updater.download_target(
            targetinfo3, self.destination_directory
        )
        updated_targets = self.repository_updater.updated_targets(
            updated_targets, self.destination_directory
        )

        self.assertListEqual(updated_targets, [])

    def test_refresh_with_only_local_root(self):
        os.remove(os.path.join(self.client_directory, "timestamp.json"))
        os.remove(os.path.join(self.client_directory, "snapshot.json"))
        os.remove(os.path.join(self.client_directory, "targets.json"))
        os.remove(os.path.join(self.client_directory, "role1.json"))
        os.remove(os.path.join(self.client_directory, "role2.json"))
        os.remove(os.path.join(self.client_directory, "1.root.json"))
        self._assert_files(["root"])

        self.repository_updater.refresh()
        self._assert_files(["root", "snapshot", "targets", "timestamp"])

        # Get targetinfo for 'file3.txt' listed in the delegated role1
        targetinfo3 = self.repository_updater.get_one_valid_targetinfo(
            "file3.txt"
        )
        expected_files = ["role1", "root", "snapshot", "targets", "timestamp"]
        self._assert_files(expected_files)

    def test_both_target_urls_not_set(self):
        # target_base_url = None and Updater._target_base_url = None
        self.repository_updater = ngclient.Updater(
            self.client_directory, self.metadata_url
        )
        with self.assertRaises(ValueError):
            self.repository_updater.download_target(
                [], self.destination_directory
            )

    def test_external_targets_url(self):
        self.repository_updater.refresh()
        targetinfo = self.repository_updater.get_one_valid_targetinfo(
            "file1.txt"
        )
        self.repository_updater.download_target(
            targetinfo, self.destination_directory, self.targets_url
        )

    def test_length_hash_mismatch(self):
        self.repository_updater.refresh()
        targetinfo = self.repository_updater.get_one_valid_targetinfo(
            "file1.txt"
        )
        length = targetinfo.length
        with self.assertRaises(exceptions.RepositoryError):
            targetinfo.length = 44
            self.repository_updater.download_target(
                targetinfo, self.destination_directory
            )

        with self.assertRaises(exceptions.RepositoryError):
            targetinfo.length = length
            targetinfo.hashes = {"sha256": "abcd"}
            self.repository_updater.download_target(
                targetinfo, self.destination_directory
            )

    def test_updating_root(self):
        # Bump root version, resign and refresh
        self._modify_repository_root(lambda root: None, bump_version=True)
        self.repository_updater.refresh()
        self.assertEqual(
            self.repository_updater._trusted_set.root.signed.version, 2
        )

    def test_missing_targetinfo(self):
        self.repository_updater.refresh()

        # Get targetinfo for non-existing file
        targetinfo = self.repository_updater.get_one_valid_targetinfo(
            "file33.txt"
        )
        self.assertIsNone(targetinfo)


if __name__ == "__main__":
    utils.configure_test_logging(sys.argv)
    unittest.main()
