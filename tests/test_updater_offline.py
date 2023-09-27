#!/usr/bin/env python

# Copyright 2021, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0


"""Test ngclient Updater offline mode"""

import datetime
import os
import sys
import tempfile
import unittest
from typing import Optional
from unittest.mock import Mock, patch

from tests import utils
from tests.repository_simulator import RepositorySimulator
from tuf.api.exceptions import DownloadError, ExpiredMetadataError
from tuf.api.metadata import SPECIFICATION_VERSION, DelegatedRole, Targets
from tuf.ngclient import Updater, UpdaterConfig


class TestOffline(unittest.TestCase):
    """Test Updater in offline mode"""

    # set dump_dir to trigger repository state dumps
    dump_dir: Optional[str] = None

    def setUp(self) -> None:
        # pylint: disable=consider-using-with
        self.temp_dir = tempfile.TemporaryDirectory()
        self.metadata_dir = os.path.join(self.temp_dir.name, "metadata")
        self.targets_dir = os.path.join(self.temp_dir.name, "targets")
        os.mkdir(self.metadata_dir)
        os.mkdir(self.targets_dir)

        self.sim = RepositorySimulator()

        # Add a delegated role and two targets to repository
        self.sim.targets.version += 1
        spec_version = ".".join(SPECIFICATION_VERSION)
        targets = Targets(1, spec_version, self.sim.safe_expiry, {}, None)
        role = DelegatedRole("delegated", [], 1, False, ["delegated/*"], None)
        self.sim.add_delegation("targets", role, targets)
        self.sim.add_target("targets", b"hello world", "file")
        self.sim.add_target("delegated", b"content", "delegated/file2")
        self.sim.update_snapshot()

        # boostrap client with initial root metadata
        with open(os.path.join(self.metadata_dir, "root.json"), "bw") as f:
            f.write(self.sim.signed_roots[0])

        if self.dump_dir is not None:
            # create test specific dump directory
            name = self.id().split(".")[-1]
            self.sim.dump_dir = os.path.join(self.dump_dir, name)
            os.mkdir(self.sim.dump_dir)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _run_refresh(self) -> Updater:
        """Create a new Updater instance and refresh"""
        if self.dump_dir is not None:
            self.sim.write()

        updater = Updater(
            self.metadata_dir,
            "https://example.com/metadata/",
            self.targets_dir,
            "https://example.com/targets/",
            self.sim,
        )
        updater.refresh()
        return updater

    def _run_offline_refresh(self) -> Updater:
        """Create a new Updater instance and refresh"""
        if self.dump_dir is not None:
            self.sim.write()

        updater = Updater(
            self.metadata_dir,
            "https://example.com/metadata/",
            self.targets_dir,
            "https://example.com/targets/",
            self.sim,
            UpdaterConfig(offline=True),
        )
        updater.refresh()
        return updater

    @patch.object(datetime, "datetime", wraps=datetime.datetime)
    def test_refresh(self, mock_time: Mock) -> None:
        """Test metadata refresh refresh()in offline mode"""
        # Run a "online" updater refresh to get toplevel metadata in local cache
        self._run_refresh()

        self.sim.fetch_tracker.metadata.clear()

        # Refresh works in Offline mode (at this point metadata is not expired)
        self._run_offline_refresh()
        # Expect no download attempts
        self.assertListEqual(self.sim.fetch_tracker.metadata, [])

        # Move current time a year into the future: all metadata is now expired
        mock_time.utcnow.return_value = (
            datetime.datetime.utcnow() + datetime.timedelta(weeks=52)
        )

        # Refresh in default online mode fails when metadata has expired
        with self.assertRaises(ExpiredMetadataError):
            self._run_refresh()

        self.sim.fetch_tracker.metadata.clear()

        # Refresh in offline mode succeeds when local metadata has expired
        self._run_offline_refresh()
        # Expect no download attempts
        self.assertListEqual(self.sim.fetch_tracker.metadata, [])

    def test_refresh_with_missing_top_level_metadata(self) -> None:
        """Test metadata refresh in offline mode when cache does not contain all top level metadata"""
        # Run a "online" updater refresh to get toplevel metadata in local cache
        self._run_refresh()

        self.sim.fetch_tracker.metadata.clear()

        for role in ["targets", "snapshot", "timestamp"]:
            fname = os.path.join(self.metadata_dir, f"{role}.json")
            os.remove(fname)

            # Refresh in offline mode fails since top level metadata is not in cache
            with self.assertRaises(DownloadError):
                self._run_offline_refresh()
            # Expect no download attempts
            self.assertListEqual(self.sim.fetch_tracker.metadata, [])

    def test_download(self) -> None:
        """Test download in offline mode"""

        # Run a "online" updater refresh to get toplevel metadata in local cache
        self._run_refresh()

        self.sim.fetch_tracker.metadata.clear()
        self.sim.fetch_tracker.targets.clear()

        # Downloading a target file while in offline mode fails
        updater = self._run_offline_refresh()
        info = updater.get_targetinfo("file")
        assert info
        with self.assertRaises(DownloadError):
            updater.download_target(info)

        # Expect no download attempts
        self.assertListEqual(self.sim.fetch_tracker.metadata, [])
        self.assertListEqual(self.sim.fetch_tracker.targets, [])

    def test_find_cached_target(self) -> None:
        """Test find_cached_target() in offline mode"""

        # Run a "online" refresh to get metadata in local cache
        updater = self._run_refresh()

        # offline find_cached_target() returns None because target is not cached
        updater = self._run_offline_refresh()
        info = updater.get_targetinfo("file")
        assert info
        self.assertIsNone(updater.find_cached_target(info))

        # Run a "online" download to get target in local cache
        updater = self._run_refresh()
        info = updater.get_targetinfo("file")
        assert info
        updater.download_target(info)

        self.sim.fetch_tracker.metadata.clear()
        self.sim.fetch_tracker.targets.clear()

        # offline find_cached_target() succeeds now
        updater = self._run_offline_refresh()
        info = updater.get_targetinfo("file")
        assert info
        self.assertIsNotNone(updater.find_cached_target(info))
        # Expect no download attempts
        self.assertListEqual(self.sim.fetch_tracker.metadata, [])
        self.assertListEqual(self.sim.fetch_tracker.targets, [])

    def test_get_targetinfo_with_delegated_metadata(self) -> None:
        # Run a "online" refresh to get toplevel metadata in local cache
        updater = self._run_refresh()

        # offline find_cached_target() fails because delegated metadata is not cached
        updater = self._run_offline_refresh()
        with self.assertRaises(DownloadError):
            updater.get_targetinfo("delegated/file2")


if __name__ == "__main__":
    if "--dump" in sys.argv:
        TestOffline.dump_dir = tempfile.mkdtemp()
        print(f"Repository Simulator dumps in {TestOffline.dump_dir}")
        sys.argv.remove("--dump")

    utils.configure_test_logging(sys.argv)
    unittest.main()
