#!/usr/bin/env python

# Copyright 2021, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Test Updater class
"""

import logging
import os
import shutil
import sys
import tempfile
import unittest
from typing import Callable, ClassVar, List

from securesystemslib.interface import import_rsa_privatekey_from_file
from securesystemslib.signer import SSlibSigner

from tests import utils
from tuf import exceptions, ngclient, unittest_toolbox
from tuf.api.metadata import (
    Metadata,
    Root,
    Snapshot,
    TargetFile,
    Targets,
    Timestamp,
)

logger = logging.getLogger(__name__)


class TestUpdater(unittest_toolbox.Modified_TestCase):
    """Test the Updater class from 'tuf/ngclient/updater.py'."""

    temporary_directory: ClassVar[str]
    server_process_handler: ClassVar[utils.TestServerProcess]

    @classmethod
    def setUpClass(cls) -> None:
        # Create a temporary directory to store the repository, metadata, and
        # target files. 'temporary_directory' must be deleted in
        # TearDownModule() so that temporary files are always removed, even when
        # exceptions occur.
        cls.temporary_directory = tempfile.mkdtemp(dir=os.getcwd())

        # Needed because in some tests simple_server.py cannot be found.
        # The reason is that the current working directory
        # has been changed when executing a subprocess.
        simple_server_path = os.path.join(os.getcwd(), "simple_server.py")

        # Launch a SimpleHTTPServer (serves files in the current directory).
        # Test cases will request metadata and target files that have been
        # pre-generated in 'tuf/tests/repository_data', which will be served
        # by the SimpleHTTPServer launched here.
        cls.server_process_handler = utils.TestServerProcess(
            log=logger, server=simple_server_path
        )

    @classmethod
    def tearDownClass(cls) -> None:
        # Cleans the resources and flush the logged lines (if any).
        cls.server_process_handler.clean()

        # Remove the temporary repository directory, which should contain all
        # the metadata, targets, and key files generated for the test cases
        shutil.rmtree(cls.temporary_directory)

    def setUp(self) -> None:
        # We are inheriting from custom class.
        unittest_toolbox.Modified_TestCase.setUp(self)

        # Copy the original repository files provided in the test folder so that
        # any modifications are restricted to the copies.
        # The 'repository_data' directory is expected to exist in 'tuf.tests/'.
        original_repository_files = os.path.join(os.getcwd(), "repository_data")
        temporary_repository_root = self.make_temp_directory(
            directory=self.temporary_directory
        )

        # The original repository, keystore, and client directories will be
        # copied for each test case.
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
            + repository_basepath.replace("\\", "/")
        )

        self.metadata_url = f"{url_prefix}/metadata/"
        self.targets_url = f"{url_prefix}/targets/"
        self.dl_dir = self.make_temp_directory()
        # Creating a repository instance.  The test cases will use this client
        # updater to refresh metadata, fetch target files, etc.
        self.updater = ngclient.Updater(
            metadata_dir=self.client_directory,
            metadata_base_url=self.metadata_url,
            target_dir=self.dl_dir,
            target_base_url=self.targets_url,
        )

    def tearDown(self) -> None:
        # We are inheriting from custom class.
        unittest_toolbox.Modified_TestCase.tearDown(self)

        # Logs stdout and stderr from the sever subprocess.
        self.server_process_handler.flush_log()

    def _modify_repository_root(
        self,
        modification_func: Callable[[Metadata], None],
        bump_version: bool = False,
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

    def _assert_files(self, roles: List[str]) -> None:
        """Assert that local metadata files exist for 'roles'"""
        expected_files = [f"{role}.json" for role in roles]
        client_files = sorted(os.listdir(self.client_directory))
        self.assertEqual(client_files, expected_files)

    def test_refresh_and_download(self) -> None:
        # Test refresh without consistent targets - targets without hash prefix.

        # top-level targets are already in local cache (but remove others)
        os.remove(os.path.join(self.client_directory, "role1.json"))
        os.remove(os.path.join(self.client_directory, "role2.json"))
        os.remove(os.path.join(self.client_directory, "1.root.json"))

        # top-level metadata is in local directory already
        self.updater.refresh()
        self._assert_files(
            [Root.type, Snapshot.type, Targets.type, Timestamp.type]
        )

        # Get targetinfos, assert that cache does not contain files
        info1 = self.updater.get_targetinfo("file1.txt")
        assert isinstance(info1, TargetFile)
        self._assert_files(
            [Root.type, Snapshot.type, Targets.type, Timestamp.type]
        )

        # Get targetinfo for 'file3.txt' listed in the delegated role1
        info3 = self.updater.get_targetinfo("file3.txt")
        assert isinstance(info3, TargetFile)
        expected_files = [
            "role1",
            Root.type,
            Snapshot.type,
            Targets.type,
            Timestamp.type,
        ]
        self._assert_files(expected_files)
        self.assertIsNone(self.updater.find_cached_target(info1))
        self.assertIsNone(self.updater.find_cached_target(info3))

        # Download files, assert that cache has correct files
        self.updater.download_target(info1)
        path = self.updater.find_cached_target(info1)
        self.assertEqual(path, os.path.join(self.dl_dir, info1.path))
        self.assertIsNone(self.updater.find_cached_target(info3))

        self.updater.download_target(info3)
        path = self.updater.find_cached_target(info1)
        self.assertEqual(path, os.path.join(self.dl_dir, info1.path))
        path = self.updater.find_cached_target(info3)
        self.assertEqual(path, os.path.join(self.dl_dir, info3.path))

    def test_refresh_with_only_local_root(self) -> None:
        os.remove(os.path.join(self.client_directory, "timestamp.json"))
        os.remove(os.path.join(self.client_directory, "snapshot.json"))
        os.remove(os.path.join(self.client_directory, "targets.json"))
        os.remove(os.path.join(self.client_directory, "role1.json"))
        os.remove(os.path.join(self.client_directory, "role2.json"))
        os.remove(os.path.join(self.client_directory, "1.root.json"))
        self._assert_files([Root.type])

        self.updater.refresh()
        self._assert_files(
            [Root.type, Snapshot.type, Targets.type, Timestamp.type]
        )

        # Get targetinfo for 'file3.txt' listed in the delegated role1
        self.updater.get_targetinfo("file3.txt")
        expected_files = [
            "role1",
            Root.type,
            Snapshot.type,
            Targets.type,
            Timestamp.type,
        ]
        self._assert_files(expected_files)

    def test_implicit_refresh_with_only_local_root(self) -> None:
        os.remove(os.path.join(self.client_directory, "timestamp.json"))
        os.remove(os.path.join(self.client_directory, "snapshot.json"))
        os.remove(os.path.join(self.client_directory, "targets.json"))
        os.remove(os.path.join(self.client_directory, "role1.json"))
        os.remove(os.path.join(self.client_directory, "role2.json"))
        os.remove(os.path.join(self.client_directory, "1.root.json"))
        self._assert_files(["root"])

        # Get targetinfo for 'file3.txt' listed in the delegated role1
        self.updater.get_targetinfo("file3.txt")
        expected_files = ["role1", "root", "snapshot", "targets", "timestamp"]
        self._assert_files(expected_files)

    def test_both_target_urls_not_set(self) -> None:
        # target_base_url = None and Updater._target_base_url = None
        updater = ngclient.Updater(
            self.client_directory, self.metadata_url, self.dl_dir
        )
        info = TargetFile(1, {"sha256": ""}, "targetpath")
        with self.assertRaises(ValueError):
            updater.download_target(info)

    def test_no_target_dir_no_filepath(self) -> None:
        # filepath = None and Updater.target_dir = None
        updater = ngclient.Updater(self.client_directory, self.metadata_url)
        info = TargetFile(1, {"sha256": ""}, "targetpath")
        with self.assertRaises(ValueError):
            updater.find_cached_target(info)
        with self.assertRaises(ValueError):
            updater.download_target(info)

    def test_external_targets_url(self) -> None:
        self.updater.refresh()
        info = self.updater.get_targetinfo("file1.txt")
        assert isinstance(info, TargetFile)

        self.updater.download_target(info, target_base_url=self.targets_url)

    def test_length_hash_mismatch(self) -> None:
        self.updater.refresh()
        targetinfo = self.updater.get_targetinfo("file1.txt")
        assert isinstance(targetinfo, TargetFile)

        length = targetinfo.length
        with self.assertRaises(exceptions.RepositoryError):
            targetinfo.length = 44
            self.updater.download_target(targetinfo)

        with self.assertRaises(exceptions.RepositoryError):
            targetinfo.length = length
            targetinfo.hashes = {"sha256": "abcd"}
            self.updater.download_target(targetinfo)

    # pylint: disable=protected-access
    def test_updating_root(self) -> None:
        # Bump root version, resign and refresh
        self._modify_repository_root(lambda root: None, bump_version=True)
        self.updater.refresh()
        self.assertEqual(self.updater._trusted_set.root.signed.version, 2)

    def test_missing_targetinfo(self) -> None:
        self.updater.refresh()

        # Get targetinfo for non-existing file
        self.assertIsNone(self.updater.get_targetinfo("file33.txt"))


if __name__ == "__main__":
    utils.configure_test_logging(sys.argv)
    unittest.main()
