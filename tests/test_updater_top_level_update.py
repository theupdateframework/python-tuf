#!/usr/bin/env python

# Copyright 2021, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Test ngclient Updater top-level metadata update workflow"""

import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta

from tests import utils
from tests.repository_simulator import RepositorySimulator
from tuf.api.metadata import Metadata
from tuf.exceptions import (
    BadVersionNumberError,
    ExpiredMetadataError,
    ReplayedMetadataError,
    RepositoryError,
    UnsignedMetadataError,
)
from tuf.ngclient import Updater

class TestRefresh(unittest.TestCase):
    """Test update of top-level metadata following
    'Detailed client workflow' in the specification."""

    past_datetime = datetime.utcnow().replace(microsecond=0) - timedelta(days=5)

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.metadata_dir = os.path.join(self.temp_dir.name, "metadata")
        self.targets_dir = os.path.join(self.temp_dir.name, "targets")
        os.mkdir(self.metadata_dir)
        os.mkdir(self.targets_dir)

        self.sim = RepositorySimulator()

        with open(os.path.join(self.metadata_dir, "root.json"), "bw") as f:
            root = self.sim.download_bytes(
                "https://example.com/metadata/1.root.json", 100000
            )
            f.write(root)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _run_refresh(self) -> Updater:
        """Create a new Updater instance and refresh"""
        updater = Updater(
            self.metadata_dir,
            "https://example.com/metadata/",
            self.targets_dir,
            "https://example.com/targets/",
            self.sim,
        )
        updater.refresh()
        return updater

    def _init_updater(self) -> Updater:
        """Create a new Updater instance"""
        return Updater(
            self.metadata_dir,
            "https://example.com/metadata/",
            self.targets_dir,
            "https://example.com/targets/",
            self.sim,
        )

    def test_first_time_refresh(self) -> None:
        # Metadata dir contains only the mandatory initial root.json
        metadata_files = os.listdir(self.metadata_dir)
        self.assertListEqual(metadata_files, ["root.json"])

        # Add one more root version to repository so that
        # refresh() updates from local trusted root (v1) to
        # remote root (v2)
        self.sim.root.version += 1
        self.sim.publish_root()

        self._run_refresh()

        # Top-level metadata can be found in metadata dir
        metadata_files_after_refresh = os.listdir(self.metadata_dir)
        metadata_files_after_refresh.sort()
        self.assertListEqual(
            metadata_files_after_refresh,
            ["root.json", "snapshot.json", "targets.json", "timestamp.json"],
        )

    def test_trusted_root_missing(self) -> None:
        os.remove(os.path.join(self.metadata_dir, "root.json"))
        with self.assertRaises(OSError):
            self._run_refresh()

    def test_trusted_root_expired(self) -> None:
        # Create an expired root version
        self.sim.root.expires = self.past_datetime
        self.sim.root.version += 1
        self.sim.publish_root()

        # Update to latest root which is expired but still
        # saved as a local root.
        updater = self._init_updater()
        with self.assertRaises(ExpiredMetadataError):
            updater.refresh()

        with open(os.path.join(self.metadata_dir, "root.json"), "rb") as f:
            self.assertEqual(f.read(), self.sim.signed_roots[-1])

        # Local root metadata can be loaded even if expired
        updater = self._init_updater()

        # Create a non-expired root version and refresh
        self.sim.root.expires = self.sim.safe_expiry
        self.sim.root.version += 1
        self.sim.publish_root()

        updater.refresh()

        with open(os.path.join(self.metadata_dir, "root.json"), "rb") as f:
            self.assertEqual(f.read(), self.sim.signed_roots[-1])

    def test_trusted_root_unsigned(self) -> None:
        # Local trusted root is not signed
        root_path = os.path.join(self.metadata_dir, "root.json")
        md_root = Metadata.from_file(root_path)
        md_root.signatures.clear()
        md_root.to_file(root_path)

        with self.assertRaises(UnsignedMetadataError):
            self._run_refresh()

    def test_max_root_rotations(self) -> None:
        # Root must stop looking for new versions after Y number of
        # intermediate files were downloaded.
        updater = self._init_updater()
        updater.config.max_root_rotations = 3

        # Create some number of roots greater than 'max_root_rotations'
        while self.sim.root.version < updater.config.max_root_rotations + 3:
            self.sim.root.version += 1
            self.sim.publish_root()

        root_path = os.path.join(self.metadata_dir, "root.json")
        md_root = Metadata.from_file(root_path)
        initial_root_version = md_root.signed.version

        updater.refresh()

        # Assert that root version was increased with no more than 'max_root_rotations'
        md_root = Metadata.from_file(root_path)
        self.assertEqual(
            md_root.signed.version,
            initial_root_version + updater.config.max_root_rotations,
        )

    def test_intermediate_root_incorrectly_signed(self) -> None:
        # Check for an arbitrary software attack

        # Intermediate root v2 is unsigned
        self.sim.root.version += 1
        root_signers = self.sim.signers["root"].copy()
        self.sim.signers["root"].clear()
        self.sim.publish_root()

        # Final root v3 is correctly signed
        self.sim.root.version += 1
        self.sim.signers["root"] = root_signers
        self.sim.publish_root()

        # Incorrectly signed intermediate root is detected
        with self.assertRaises(UnsignedMetadataError):
            self._run_refresh()

    def test_intermediate_root_expired(self) -> None:
        # The expiration of the new (intermediate) root metadata file
        # does not matter yet

        # Intermediate root v2 is expired
        self.sim.root.expires = self.past_datetime
        self.sim.root.version += 1
        self.sim.publish_root()

        # Final root v3 is up to date
        self.sim.root.expires = self.sim.safe_expiry
        self.sim.root.version += 1
        self.sim.publish_root()

        self._run_refresh()
        md_root = Metadata.from_file(
            os.path.join(self.metadata_dir, "root.json")
        )
        self.assertEqual(md_root.signed.version, self.sim.root.version)

    def test_final_root_incorrectly_signed(self) -> None:
        # Check for an arbitrary software attack
        self.sim.root.version += 1
        self.sim.signers["root"].clear()
        self.sim.publish_root()

        with self.assertRaises(UnsignedMetadataError):
            self._run_refresh()

    def test_new_root_same_version(self) -> None:
        # Check for a rollback_attack
        # Repository serves a root file with the same version as previous
        self.sim.publish_root()
        with self.assertRaises(ReplayedMetadataError):
            self._run_refresh()

    def test_new_root_nonconsecutive_version(self) -> None:
        # Repository serves non-consecutive root version
        self.sim.root.version += 2
        self.sim.publish_root()
        with self.assertRaises(ReplayedMetadataError):
            self._run_refresh()

    def test_final_root_expired(self) -> None:
        # Check for a freeze attack
        # Final root is expired
        self.sim.root.expires = self.past_datetime
        self.sim.root.version += 1
        self.sim.publish_root()

        with self.assertRaises(ExpiredMetadataError):
            self._run_refresh()

    def test_new_timestamp_unsigned(self) -> None:
        # Check for an arbitrary software attack
        self.sim.signers["timestamp"].clear()
        with self.assertRaises(UnsignedMetadataError):
            self._run_refresh()

    def test_new_timestamp_version_rollback(self) -> None:
        # Check for a rollback attack
        self.sim.timestamp.version = 2
        self._run_refresh()

        self.sim.timestamp.version = 1
        with self.assertRaises(ReplayedMetadataError):
            self._run_refresh()

    def test_new_timestamp_snapshot_rollback(self) -> None:
        # Check for a rollback attack.
        self.sim.snapshot.version = 2
        self.sim.update_timestamp()
        self._run_refresh()

        # Snapshot meta version is smaller than previous
        self.sim.timestamp.snapshot_meta.version = 1
        self.sim.timestamp.version += 1

        with self.assertRaises(ReplayedMetadataError):
            self._run_refresh()

    def test_new_timestamp_expired(self) -> None:
        # Check for a freeze attack
        self.sim.timestamp.expires = self.past_datetime
        self.sim.update_timestamp()

        with self.assertRaises(ExpiredMetadataError):
            self._run_refresh()

    def test_new_snapshot_hash_mismatch(self) -> None:
        # Check against timestamp role’s snapshot hash

        # Update timestamp with snapshot's hashes
        self.sim.compute_metafile_hashes_length = True
        self.sim.update_timestamp() # timestamp v2
        self._run_refresh()

        # Modify snapshot contents without updating
        # timestamp's snapshot hash
        self.sim.snapshot.expires += timedelta(days=1)
        self.sim.snapshot.version += 1  # snapshot v2
        self.sim.timestamp.snapshot_meta.version = self.sim.snapshot.version
        self.sim.timestamp.version += 1 # timestamp v3

        # Hash mismatch error
        with self.assertRaises(RepositoryError):
            self._run_refresh()

    def test_new_snapshot_unsigned(self) -> None:
        # Check for an arbitrary software attack
        self.sim.signers["snapshot"].clear()
        with self.assertRaises(UnsignedMetadataError):
            self._run_refresh()

    # TODO: RepositorySimulator works always with consistent snapshot
    # enabled which forces the client to look for the snapshot version
    # written in timestamp (which leads to "Unknown snapshot version").
    # This fails the test for a snapshot version mismatch.

    # def test_new_snapshot_version_mismatch(self):
    #     # Check against timestamp role’s snapshot version

    #     # Increase snapshot version without updating
    #     # timestamp's snapshot version
    #     self.sim.snapshot.version += 1
    #     with self.assertRaises(BadVersionNumberError):
    #         self._run_refresh()

    def test_new_snapshot_version_rollback(self) -> None:
        # Check for a rollback attack
        self.sim.snapshot.version = 2
        self.sim.update_timestamp()
        self._run_refresh()

        self.sim.snapshot.version = 1
        self.sim.update_timestamp()

        with self.assertRaises(ReplayedMetadataError):
            self._run_refresh()

    def test_new_snapshot_expired(self) -> None:
        # Check for a freeze attack
        self.sim.snapshot.expires = self.past_datetime
        self.sim.update_snapshot()

        with self.assertRaises(ExpiredMetadataError):
            self._run_refresh()

    def test_new_targets_hash_mismatch(self) -> None:
        # Check against snapshot role’s targets hashes

        # Update snapshot with target's hashes
        self.sim.compute_metafile_hashes_length = True
        self.sim.update_snapshot()
        self._run_refresh()

        # Modify targets contents without updating
        # snapshot's targets hashes
        self.sim.targets.version += 1
        self.sim.snapshot.meta["targets.json"].version = self.sim.targets.version
        self.sim.snapshot.version += 1
        self.sim.update_timestamp()

        with self.assertRaises(RepositoryError):
            self._run_refresh()

    def test_new_targets_unsigned(self) -> None:
        # Check for an arbitrary software attack
        self.sim.signers["targets"].clear()
        with self.assertRaises(UnsignedMetadataError):
            self._run_refresh()

    # TODO: RepositorySimulator works always with consistent snapshot
    # enabled which forces the client to look for the targets version
    # written in snapshot (which leads to "Unknown targets version").
    # This fails the test for a targets version mismatch.

    # def test_new_targets_version_mismatch(self):
    #     # Check against snapshot role’s targets version
    #     self.sim.targets.version += 1
    #     with self.assertRaises(BadVersionNumberError):
    #         self._run_refresh()

    def test_new_targets_expired(self) -> None:
        # Check for a freeze attack.
        self.sim.targets.expires = self.past_datetime
        self.sim.update_snapshot()

        with self.assertRaises(ExpiredMetadataError):
            self._run_refresh()


if __name__ == "__main__":

    utils.configure_test_logging(sys.argv)
    unittest.main()
