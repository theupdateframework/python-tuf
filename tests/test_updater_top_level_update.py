# Copyright 2021, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Test ngclient Updater top-level metadata update workflow"""

from __future__ import annotations

import builtins
import datetime
import os
import sys
import tempfile
import unittest
from datetime import timezone
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, call, patch

import freezegun

from tests import utils
from tests.repository_simulator import RepositorySimulator
from tuf.api.exceptions import (
    BadVersionNumberError,
    DownloadLengthMismatchError,
    ExpiredMetadataError,
    LengthOrHashMismatchError,
    UnsignedMetadataError,
)
from tuf.api.metadata import (
    SPECIFICATION_VERSION,
    TOP_LEVEL_ROLE_NAMES,
    DelegatedRole,
    Metadata,
    Root,
    Snapshot,
    Targets,
    Timestamp,
)
from tuf.ngclient import Updater

if TYPE_CHECKING:
    from collections.abc import Iterable


class TestRefresh(unittest.TestCase):
    """Test update of top-level metadata following
    'Detailed client workflow' in the specification."""

    # set dump_dir to trigger repository state dumps
    dump_dir: str | None = None

    past_datetime = datetime.datetime.now(timezone.utc).replace(
        microsecond=0
    ) - datetime.timedelta(days=5)

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.metadata_dir = os.path.join(self.temp_dir.name, "metadata")
        self.targets_dir = os.path.join(self.temp_dir.name, "targets")

        self.sim = RepositorySimulator()

        if self.dump_dir is not None:
            # create test specific dump directory
            name = self.id().split(".")[-1]
            self.sim.dump_dir = os.path.join(self.dump_dir, name)
            os.mkdir(self.sim.dump_dir)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _run_refresh(self, skip_bootstrap: bool = False) -> Updater:
        """Create a new Updater instance and refresh"""
        updater = self._init_updater(skip_bootstrap)
        updater.refresh()
        return updater

    def _init_updater(self, skip_bootstrap: bool = False) -> Updater:
        """Create a new Updater instance"""
        if self.dump_dir is not None:
            self.sim.write()

        return Updater(
            self.metadata_dir,
            "https://example.com/metadata/",
            self.targets_dir,
            "https://example.com/targets/",
            self.sim,
            bootstrap=None if skip_bootstrap else self.sim.signed_roots[0],
        )

    def _assert_files_exist(self, roles: Iterable[str]) -> None:
        """Assert that local metadata files match 'roles'"""
        expected_files = [f"{role}.json" for role in roles]
        found_files = [
            e.name for e in os.scandir(self.metadata_dir) if e.is_file()
        ]

        self.assertListEqual(sorted(found_files), sorted(expected_files))

    def _assert_content_equals(
        self, role: str, version: int | None = None
    ) -> None:
        """Assert that local file content is the expected"""
        expected_content = self.sim.fetch_metadata(role, version)
        with open(os.path.join(self.metadata_dir, f"{role}.json"), "rb") as f:
            self.assertEqual(f.read(), expected_content)

    def _assert_version_equals(self, role: str, expected_version: int) -> None:
        """Assert that local metadata version is the expected"""
        md = Metadata.from_file(os.path.join(self.metadata_dir, f"{role}.json"))
        self.assertEqual(md.signed.version, expected_version)

    def test_first_time_refresh(self) -> None:
        # Add one more root version to repository so that
        # refresh() updates from local trusted root (v1) to
        # remote root (v2)
        self.sim.root.version += 1
        self.sim.publish_root()

        self._run_refresh()

        self._assert_files_exist(TOP_LEVEL_ROLE_NAMES)
        for role in TOP_LEVEL_ROLE_NAMES:
            version = 2 if role == Root.type else None
            self._assert_content_equals(role, version)

    def test_cached_root_missing_without_bootstrap(self) -> None:
        # Run update without a bootstrap, with empty cache: this fails since there is no
        # trusted root
        with self.assertRaises(OSError):
            self._run_refresh(skip_bootstrap=True)

        # Metadata dir is empty
        with self.assertRaises(FileNotFoundError):
            os.listdir(self.metadata_dir)

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

        self._assert_files_exist([Root.type])
        self._assert_content_equals(Root.type, 2)

        # Local root metadata can be loaded even if expired
        updater = self._init_updater()

        # Create a non-expired root version and refresh
        self.sim.root.expires = self.sim.safe_expiry
        self.sim.root.version += 1
        self.sim.publish_root()
        updater.refresh()

        # Root is successfully updated to latest version
        self._assert_files_exist(TOP_LEVEL_ROLE_NAMES)
        self._assert_content_equals(Root.type, 3)

    def test_trusted_root_unsigned_without_bootstrap(self) -> None:
        # Cached root is not signed, bootstrap root is not used
        Path(self.metadata_dir).mkdir(parents=True)
        root_path = os.path.join(self.metadata_dir, "root.json")
        md_root = Metadata.from_bytes(self.sim.signed_roots[0])
        md_root.signatures.clear()
        md_root.to_file(root_path)

        with self.assertRaises(UnsignedMetadataError):
            self._run_refresh(skip_bootstrap=True)

        # The update failed, no changes in metadata
        self._assert_files_exist([Root.type])
        md_root_after = Metadata.from_file(root_path)
        self.assertEqual(md_root.to_bytes(), md_root_after.to_bytes())

    def test_max_root_rotations(self) -> None:
        # Root must stop looking for new versions after Y number of
        # intermediate files were downloaded.
        updater = self._init_updater()
        updater.config.max_root_rotations = 3

        # Create some number of roots greater than 'max_root_rotations'
        while self.sim.root.version < updater.config.max_root_rotations + 3:
            self.sim.root.version += 1
            self.sim.publish_root()

        initial_root_version = 1

        updater.refresh()

        # Assert that root version was increased with no more
        # than 'max_root_rotations'
        self._assert_version_equals(
            Root.type, initial_root_version + updater.config.max_root_rotations
        )

    def test_intermediate_root_incorrectly_signed(self) -> None:
        # Check for an arbitrary software attack

        # Intermediate root v2 is unsigned
        self.sim.root.version += 1
        root_signers = self.sim.signers[Root.type].copy()
        self.sim.signers[Root.type].clear()
        self.sim.publish_root()

        # Final root v3 is correctly signed
        self.sim.root.version += 1
        self.sim.signers[Root.type] = root_signers
        self.sim.publish_root()

        # Incorrectly signed intermediate root is detected
        with self.assertRaises(UnsignedMetadataError):
            self._run_refresh()

        # The update failed, latest root version is v1
        self._assert_files_exist([Root.type])
        self._assert_content_equals(Root.type, 1)

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

        # Successfully updated to root v3
        self._assert_files_exist(TOP_LEVEL_ROLE_NAMES)
        self._assert_content_equals(Root.type, 3)

    def test_final_root_incorrectly_signed(self) -> None:
        # Check for an arbitrary software attack
        self.sim.root.version += 1  # root v2
        self.sim.signers[Root.type].clear()
        self.sim.publish_root()

        with self.assertRaises(UnsignedMetadataError):
            self._run_refresh()

        # The update failed, latest root version is v1
        self._assert_files_exist([Root.type])
        self._assert_content_equals(Root.type, 1)

    def test_new_root_same_version(self) -> None:
        # Check for a rollback_attack
        # Repository serves a root file with the same version as previous
        self.sim.publish_root()
        with self.assertRaises(BadVersionNumberError):
            self._run_refresh()

        # The update failed, latest root version is v1
        self._assert_files_exist([Root.type])
        self._assert_content_equals(Root.type, 1)

    def test_new_root_nonconsecutive_version(self) -> None:
        # Repository serves non-consecutive root version
        self.sim.root.version += 2
        self.sim.publish_root()
        with self.assertRaises(BadVersionNumberError):
            self._run_refresh()

        # The update failed, latest root version is v1
        self._assert_files_exist([Root.type])
        self._assert_content_equals(Root.type, 1)

    def test_final_root_expired(self) -> None:
        # Check for a freeze attack
        # Final root is expired
        self.sim.root.expires = self.past_datetime
        self.sim.root.version += 1
        self.sim.publish_root()

        with self.assertRaises(ExpiredMetadataError):
            self._run_refresh()

        # The update failed but final root is persisted on the file system
        self._assert_files_exist([Root.type])
        self._assert_content_equals(Root.type, 2)

    def test_new_timestamp_unsigned(self) -> None:
        # Check for an arbitrary software attack
        self.sim.signers[Timestamp.type].clear()
        with self.assertRaises(UnsignedMetadataError):
            self._run_refresh()

        self._assert_files_exist([Root.type])

    def test_expired_timestamp_version_rollback(self) -> None:
        """Verifies that local timestamp is used in rollback checks even if it is expired.

        The timestamp updates and rollback checks are performed
        with the following timing:
         - Timestamp v1 expiry set to day 7
         - First updater refresh performed on day 0
         - Repository publishes timestamp v2 on day 0
         - Timestamp v2 expiry set to day 21
         - Second updater refresh performed on day 18:
           assert that rollback check uses expired timestamp v1"""

        now = datetime.datetime.now(timezone.utc)
        self.sim.timestamp.expires = now + datetime.timedelta(days=7)

        self.sim.timestamp.version = 2

        # Make a successful update of valid metadata which stores it in cache
        self._run_refresh()

        self.sim.timestamp.expires = now + datetime.timedelta(days=21)

        self.sim.timestamp.version = 1

        patcher = freezegun.freeze_time(
            datetime.datetime.now(timezone.utc) + datetime.timedelta(days=18)
        )
        # Check that a rollback protection is performed even if
        # local timestamp has expired
        with patcher, self.assertRaises(BadVersionNumberError):
            self._run_refresh()

        self._assert_version_equals(Timestamp.type, 2)

    def test_expired_timestamp_snapshot_rollback(self) -> None:
        """Verifies that rollback protection is done even if local timestamp has expired.

        The snapshot updates and rollback protection checks are performed
        with the following timing:
         - Timestamp v1 expiry set to day 7
         - Repository bumps snapshot to v3 on day 0
         - First updater refresh performed on day 0
         - Timestamp v2 expiry set to day 21
         - Second updater refresh performed on day 18:
           assert that rollback protection is done with expired timestamp v1"""

        now = datetime.datetime.now(timezone.utc)
        self.sim.timestamp.expires = now + datetime.timedelta(days=7)

        # Bump the snapshot version number to 3
        self.sim.update_snapshot()
        self.sim.update_snapshot()

        # Make a successful update of valid metadata which stores it in cache
        self._run_refresh()

        self.sim.snapshot.version = 1
        # Snapshot version number is set to 2, which is still less than 3
        self.sim.update_snapshot()
        self.sim.timestamp.expires = now + datetime.timedelta(days=21)

        patcher = freezegun.freeze_time(
            datetime.datetime.now(timezone.utc) + datetime.timedelta(days=18)
        )
        # Assert that rollback protection is done even if
        # local timestamp has expired
        with patcher, self.assertRaises(BadVersionNumberError):
            self._run_refresh()

        self._assert_version_equals(Timestamp.type, 3)

    def test_new_timestamp_version_rollback(self) -> None:
        # Check for a rollback attack
        self.sim.timestamp.version = 2
        self._run_refresh()

        self.sim.timestamp.version = 1
        with self.assertRaises(BadVersionNumberError):
            self._run_refresh()

        self._assert_version_equals(Timestamp.type, 2)

    def test_new_timestamp_snapshot_rollback(self) -> None:
        # Check for a rollback attack.
        self.sim.snapshot.version = 2
        self.sim.update_timestamp()  # timestamp v2
        self._run_refresh()

        # Snapshot meta version is smaller than previous
        self.sim.timestamp.snapshot_meta.version = 1
        self.sim.timestamp.version += 1  # timestamp v3

        with self.assertRaises(BadVersionNumberError):
            self._run_refresh()

        self._assert_version_equals(Timestamp.type, 2)

    def test_new_timestamp_expired(self) -> None:
        # Check for a freeze attack
        self.sim.timestamp.expires = self.past_datetime
        self.sim.update_timestamp()

        with self.assertRaises(ExpiredMetadataError):
            self._run_refresh()

        self._assert_files_exist([Root.type])

    def test_new_timestamp_fast_forward_recovery(self) -> None:
        """Test timestamp fast-forward recovery using key rotation.

        The timestamp recovery is made by the following steps
         - Remove the timestamp key
         - Create and add a new key for timestamp
         - Bump and publish root
         - Rollback the timestamp version
        """

        # attacker updates to a higher version
        self.sim.timestamp.version = 99999

        # client refreshes the metadata and see the new timestamp version
        self._run_refresh()
        self._assert_version_equals(Timestamp.type, 99999)

        # repository rotates timestamp keys, rolls back timestamp version
        self.sim.rotate_keys(Timestamp.type)
        self.sim.root.version += 1
        self.sim.publish_root()
        self.sim.timestamp.version = 1

        # client refresh the metadata and see the initial timestamp version
        self._run_refresh()
        self._assert_version_equals(Timestamp.type, 1)

    def test_new_snapshot_hash_mismatch(self) -> None:
        # Check against timestamp role's snapshot hash

        # Update timestamp with snapshot's hashes
        self.sim.compute_metafile_hashes_length = True
        self.sim.update_timestamp()  # timestamp v2
        self._run_refresh()

        # Modify snapshot contents without updating
        # timestamp's snapshot hash
        self.sim.snapshot.expires += datetime.timedelta(days=1)
        self.sim.snapshot.version += 1  # snapshot v2
        self.sim.timestamp.snapshot_meta.version = self.sim.snapshot.version
        self.sim.timestamp.version += 1  # timestamp v3

        # Hash mismatch error
        with self.assertRaises(LengthOrHashMismatchError):
            self._run_refresh()

        self._assert_version_equals(Timestamp.type, 3)
        self._assert_version_equals(Snapshot.type, 1)

    def test_new_snapshot_unsigned(self) -> None:
        # Check for an arbitrary software attack
        self.sim.signers[Snapshot.type].clear()
        with self.assertRaises(UnsignedMetadataError):
            self._run_refresh()

        self._assert_files_exist([Root.type, Timestamp.type])

    def test_new_snapshot_version_mismatch(self) -> None:
        # Check against timestamp role's snapshot version

        # Increase snapshot version without updating timestamp
        self.sim.snapshot.version += 1
        with self.assertRaises(BadVersionNumberError):
            self._run_refresh()

        self._assert_files_exist([Root.type, Timestamp.type])

    def test_new_snapshot_version_rollback(self) -> None:
        # Check for a rollback attack
        self.sim.snapshot.version = 2
        self.sim.update_timestamp()
        self._run_refresh()

        self.sim.snapshot.version = 1
        self.sim.update_timestamp()

        with self.assertRaises(BadVersionNumberError):
            self._run_refresh()

        self._assert_version_equals(Snapshot.type, 2)

    def test_new_snapshot_fast_forward_recovery(self) -> None:
        """Test snapshot fast-forward recovery using key rotation.

        The snapshot recovery requires the snapshot and timestamp key rotation.
        It is made by the following steps:
        - Remove the snapshot and timestamp keys
        - Create and add a new key for snapshot and timestamp
        - Rollback snapshot version
        - Bump and publish root
        - Bump the timestamp
        """

        # attacker updates to a higher version (bumping timestamp is required)
        self.sim.snapshot.version = 99999
        self.sim.update_timestamp()

        # client refreshes the metadata and see the new snapshot version
        self._run_refresh()
        self._assert_version_equals(Snapshot.type, 99999)

        # repository rotates snapshot & timestamp keys, rolls back snapshot
        self.sim.rotate_keys(Snapshot.type)
        self.sim.rotate_keys(Timestamp.type)
        self.sim.root.version += 1
        self.sim.publish_root()

        self.sim.snapshot.version = 1
        self.sim.update_timestamp()

        # client refresh the metadata and see the initial snapshot version
        self._run_refresh()
        self._assert_version_equals(Snapshot.type, 1)

    def test_new_snapshot_expired(self) -> None:
        # Check for a freeze attack
        self.sim.snapshot.expires = self.past_datetime
        self.sim.update_snapshot()

        with self.assertRaises(ExpiredMetadataError):
            self._run_refresh()

        self._assert_files_exist([Root.type, Timestamp.type])

    def test_new_targets_hash_mismatch(self) -> None:
        # Check against snapshot role's targets hashes

        # Update snapshot with target's hashes
        self.sim.compute_metafile_hashes_length = True
        self.sim.update_snapshot()
        self._run_refresh()

        # Modify targets contents without updating
        # snapshot's targets hashes
        self.sim.targets.version += 1
        self.sim.snapshot.meta[
            "targets.json"
        ].version = self.sim.targets.version
        self.sim.snapshot.version += 1
        self.sim.update_timestamp()

        with self.assertRaises(LengthOrHashMismatchError):
            self._run_refresh()

        self._assert_version_equals(Snapshot.type, 3)
        self._assert_version_equals(Targets.type, 1)

    def test_new_targets_unsigned(self) -> None:
        # Check for an arbitrary software attack
        self.sim.signers[Targets.type].clear()
        with self.assertRaises(UnsignedMetadataError):
            self._run_refresh()

        self._assert_files_exist([Root.type, Timestamp.type, Snapshot.type])

    def test_new_targets_version_mismatch(self) -> None:
        # Check against snapshot role's targets version

        # Increase targets version without updating snapshot
        self.sim.targets.version += 1
        with self.assertRaises(BadVersionNumberError):
            self._run_refresh()

        self._assert_files_exist([Root.type, Timestamp.type, Snapshot.type])

    def test_new_targets_expired(self) -> None:
        # Check for a freeze attack.
        self.sim.targets.expires = self.past_datetime
        self.sim.update_snapshot()

        with self.assertRaises(ExpiredMetadataError):
            self._run_refresh()

        self._assert_files_exist([Root.type, Timestamp.type, Snapshot.type])

    def test_compute_metafile_hashes_length(self) -> None:
        self.sim.compute_metafile_hashes_length = True
        self.sim.update_snapshot()
        self._run_refresh()
        self._assert_version_equals(Timestamp.type, 2)
        self._assert_version_equals(Snapshot.type, 2)

        self.sim.compute_metafile_hashes_length = False
        self.sim.update_snapshot()
        self._run_refresh()

        self._assert_version_equals(Timestamp.type, 3)
        self._assert_version_equals(Snapshot.type, 3)

    def test_new_targets_fast_forward_recovery(self) -> None:
        """Test targets fast-forward recovery using key rotation.

        The targets recovery is made by issuing new Snapshot keys, by following
        steps:
            - Remove the snapshot key
            - Create and add a new key for snapshot
            - Bump and publish root
            - Rollback the target version
        """
        # attacker updates to a higher version
        self.sim.targets.version = 99999
        self.sim.update_snapshot()

        # client refreshes the metadata and see the new targets version
        self._run_refresh()
        self._assert_version_equals(Targets.type, 99999)

        # repository rotates snapshot keys, rolls back targets version
        self.sim.rotate_keys(Snapshot.type)
        self.sim.root.version += 1
        self.sim.publish_root()

        self.sim.targets.version = 1
        self.sim.update_snapshot()

        # client refreshes the metadata version and see initial targets version
        self._run_refresh()
        self._assert_version_equals(Targets.type, 1)

    @patch.object(builtins, "open", wraps=builtins.open)
    def test_not_loading_targets_twice(self, wrapped_open: MagicMock) -> None:
        # Do not load targets roles more than once when traversing
        # the delegations tree

        # Add new delegated targets, update the snapshot
        spec_version = ".".join(SPECIFICATION_VERSION)
        targets = Targets(1, spec_version, self.sim.safe_expiry, {}, None)
        role = DelegatedRole("role1", [], 1, False, ["*"], None)
        self.sim.add_delegation("targets", role, targets)
        self.sim.update_snapshot()

        # Run refresh, top-level roles are loaded
        updater = self._run_refresh()
        # Clean up calls to open during refresh()
        wrapped_open.reset_mock()

        # First time looking for "somepath", only 'role1' must be loaded
        updater.get_targetinfo("somepath")
        wrapped_open.assert_called_once_with(
            os.path.join(self.metadata_dir, "role1.json"), "rb"
        )
        wrapped_open.reset_mock()
        # Second call to get_targetinfo, all metadata is already loaded
        updater.get_targetinfo("somepath")
        wrapped_open.assert_not_called()

    def test_snapshot_rollback_with_local_snapshot_hash_mismatch(self) -> None:
        # Test triggering snapshot rollback check on a newly downloaded snapshot
        # when the local snapshot is loaded even when there is a hash mismatch
        # with timestamp.snapshot_meta.

        # By raising this flag on timestamp update the simulator would:
        # 1) compute the hash of the new modified version of snapshot
        # 2) assign the hash to timestamp.snapshot_meta
        # The purpose is to create a hash mismatch between timestamp.meta and
        # the local snapshot, but to have hash match between timestamp.meta and
        # the next snapshot version.
        self.sim.compute_metafile_hashes_length = True

        # Initialize all metadata and assign targets version higher than 1.
        self.sim.targets.version = 2
        self.sim.update_snapshot()
        self._run_refresh()

        # The new targets must have a lower version than the local trusted one.
        self.sim.targets.version = 1
        self.sim.update_snapshot()

        # During the snapshot update, the local snapshot will be loaded even if
        # there is a hash mismatch with timestamp.snapshot_meta, because it will
        # be considered as trusted.
        # Should fail as a new version of snapshot will be fetched which lowers
        # the snapshot.meta["targets.json"] version by 1 and throws an error.
        with self.assertRaises(BadVersionNumberError):
            self._run_refresh()

    @patch.object(builtins, "open", wraps=builtins.open)
    def test_load_metadata_from_cache(self, wrapped_open: MagicMock) -> None:
        # Add new delegated targets
        spec_version = ".".join(SPECIFICATION_VERSION)
        targets = Targets(1, spec_version, self.sim.safe_expiry, {}, None)
        role = DelegatedRole("role1", [], 1, False, ["*"], None)
        self.sim.add_delegation("targets", role, targets)
        self.sim.update_snapshot()

        # Make a successful update of valid metadata which stores it in cache
        updater = self._run_refresh()
        updater.get_targetinfo("non_existent_target")

        # Clear statistics for open() calls and metadata requests
        wrapped_open.reset_mock()
        self.sim.fetch_tracker.metadata.clear()

        # Create a new updater and perform a second update while
        # the metadata is already stored in cache (metadata dir)
        updater = self._init_updater()
        updater.get_targetinfo("non_existent_target")

        # Test that metadata is loaded from cache and not downloaded
        root_dir = os.path.join(self.metadata_dir, "root_history")
        wrapped_open.assert_has_calls(
            [
                call(os.path.join(root_dir, "2.root.json"), "rb"),
                call(os.path.join(self.metadata_dir, "timestamp.json"), "rb"),
                call(os.path.join(self.metadata_dir, "snapshot.json"), "rb"),
                call(os.path.join(self.metadata_dir, "targets.json"), "rb"),
                call(os.path.join(self.metadata_dir, "role1.json"), "rb"),
            ]
        )

        expected_calls = [("root", 2), ("timestamp", None)]
        self.assertListEqual(self.sim.fetch_tracker.metadata, expected_calls)

    @patch.object(builtins, "open", wraps=builtins.open)
    def test_intermediate_root_cache(self, wrapped_open: MagicMock) -> None:
        """Test that refresh uses the intermediate roots from cache"""
        # Add root versions 2, 3
        self.sim.root.version += 1
        self.sim.publish_root()
        self.sim.root.version += 1
        self.sim.publish_root()

        # Make a successful update of valid metadata which stores it in cache
        self._run_refresh()

        # assert that cache lookups happened but data was downloaded from remote
        root_dir = os.path.join(self.metadata_dir, "root_history")
        wrapped_open.assert_has_calls(
            [
                call(os.path.join(root_dir, "2.root.json"), "rb"),
                call(os.path.join(root_dir, "3.root.json"), "rb"),
                call(os.path.join(root_dir, "4.root.json"), "rb"),
                call(os.path.join(self.metadata_dir, "timestamp.json"), "rb"),
                call(os.path.join(self.metadata_dir, "snapshot.json"), "rb"),
                call(os.path.join(self.metadata_dir, "targets.json"), "rb"),
            ]
        )
        expected_calls = [
            ("root", 2),
            ("root", 3),
            ("root", 4),
            ("timestamp", None),
            ("snapshot", 1),
            ("targets", 1),
        ]
        self.assertListEqual(self.sim.fetch_tracker.metadata, expected_calls)

        # Clear statistics for open() calls and metadata requests
        wrapped_open.reset_mock()
        self.sim.fetch_tracker.metadata.clear()

        # Run update again, assert that metadata from cache was used (including intermediate roots)
        self._run_refresh()
        wrapped_open.assert_has_calls(
            [
                call(os.path.join(root_dir, "2.root.json"), "rb"),
                call(os.path.join(root_dir, "3.root.json"), "rb"),
                call(os.path.join(root_dir, "4.root.json"), "rb"),
                call(os.path.join(self.metadata_dir, "timestamp.json"), "rb"),
                call(os.path.join(self.metadata_dir, "snapshot.json"), "rb"),
                call(os.path.join(self.metadata_dir, "targets.json"), "rb"),
            ]
        )
        expected_calls = [("root", 4), ("timestamp", None)]
        self.assertListEqual(self.sim.fetch_tracker.metadata, expected_calls)

    def test_intermediate_root_cache_poisoning(self) -> None:
        """Test that refresh works as expected when intermediate roots in cache are poisoned"""
        # Add root versions 2, 3
        self.sim.root.version += 1
        self.sim.publish_root()
        self.sim.root.version += 1
        self.sim.publish_root()

        # Make a successful update of valid metadata which stores it in cache
        self._run_refresh()

        # Modify cached intermediate root v2 so that it's no longer signed correctly
        root_path = os.path.join(
            self.metadata_dir, "root_history", "2.root.json"
        )
        md = Metadata.from_file(root_path)
        md.signatures.clear()
        md.to_file(root_path)

        # Clear statistics for metadata requests
        self.sim.fetch_tracker.metadata.clear()

        # Update again, assert that intermediate root v2 was downloaded again
        self._run_refresh()

        expected_calls = [("root", 2), ("root", 4), ("timestamp", None)]
        self.assertListEqual(self.sim.fetch_tracker.metadata, expected_calls)

        # Clear statistics for metadata requests
        self.sim.fetch_tracker.metadata.clear()

        # Update again, this time assert that intermediate root v2 was used from cache
        self._run_refresh()

        expected_calls = [("root", 4), ("timestamp", None)]
        self.assertListEqual(self.sim.fetch_tracker.metadata, expected_calls)

    def test_expired_metadata(self) -> None:
        """Verifies that expired local timestamp/snapshot can be used for
        updating from remote.

        The updates and verifications are performed with the following timing:
         - Timestamp v1 expiry set to day 7
         - First updater refresh performed on day 0
         - Repository bumps snapshot and targets to v2 on day 0
         - Timestamp v2 expiry set to day 21
         - Second updater refresh performed on day 18,
           it is successful and timestamp/snapshot final versions are v2"""

        now = datetime.datetime.now(timezone.utc)
        self.sim.timestamp.expires = now + datetime.timedelta(days=7)

        # Make a successful update of valid metadata which stores it in cache
        self._run_refresh()

        self.sim.targets.version += 1
        self.sim.update_snapshot()
        self.sim.timestamp.expires = now + datetime.timedelta(days=21)

        # Mocking time so that local timestam has expired
        # but the new timestamp has not
        with freezegun.freeze_time(
            datetime.datetime.now(timezone.utc) + datetime.timedelta(days=18)
        ):
            self._run_refresh()

        # Assert that the final version of timestamp/snapshot is version 2
        # which means a successful refresh is performed
        # with expired local metadata
        for role in ["timestamp", "snapshot", "targets"]:
            md = Metadata.from_file(
                os.path.join(self.metadata_dir, f"{role}.json")
            )
            self.assertEqual(md.signed.version, 2)

    def test_max_metadata_lengths(self) -> None:
        """Test that clients configured max metadata lengths are respected"""

        # client has root v1 already: create a new one available for download
        self.sim.root.version += 1
        self.sim.publish_root()

        config_vars = [
            "root_max_length",
            "timestamp_max_length",
            "snapshot_max_length",
            "targets_max_length",
        ]
        # make sure going over any length limit raises DownloadLengthMismatchError
        for var_name in config_vars:
            updater = self._init_updater()
            setattr(updater.config, var_name, 100)
            with self.assertRaises(DownloadLengthMismatchError):
                updater.refresh()

        # All good with normal length limits
        updater = self._init_updater()
        updater.refresh()

    def test_timestamp_eq_versions_check(self) -> None:
        # Test that a modified timestamp with different content, but the same
        # version doesn't replace the valid locally stored one.

        # Make a successful update of valid metadata which stores it in cache
        self._run_refresh()
        initial_timestamp_meta_ver = self.sim.timestamp.snapshot_meta.version

        # Change timestamp without bumping its version in order to test if a new
        # timestamp with the same version will be persisted.
        self.sim.timestamp.snapshot_meta.version = 100
        self._run_refresh()

        # If the local timestamp md file has the same snapshot_meta.version as
        # the initial one, then the new modified timestamp has not been stored.
        timestamp_path = os.path.join(self.metadata_dir, "timestamp.json")
        timestamp: Metadata[Timestamp] = Metadata.from_file(timestamp_path)
        self.assertEqual(
            initial_timestamp_meta_ver, timestamp.signed.snapshot_meta.version
        )


if __name__ == "__main__":
    if "--dump" in sys.argv:
        TestRefresh.dump_dir = tempfile.mkdtemp()
        print(f"Repository Simulator dumps in {TestRefresh.dump_dir}")
        sys.argv.remove("--dump")

    utils.configure_test_logging(sys.argv)
    unittest.main()
