#!/usr/bin/env python

# Copyright 2021, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Test ngclient Updater using the repository simulator.
"""

import builtins
import os
import sys
import tempfile
import unittest
from typing import Optional, Tuple
from unittest.mock import MagicMock, patch

from tests import utils
from tests.repository_simulator import RepositorySimulator
from tuf.api.metadata import SPECIFICATION_VERSION, Targets
from tuf.exceptions import BadVersionNumberError, UnsignedMetadataError
from tuf.ngclient import Updater


class TestUpdater(unittest.TestCase):
    """Test ngclient Updater using the repository simulator."""

    # set dump_dir to trigger repository state dumps
    dump_dir: Optional[str] = None

    def setUp(self) -> None:
        # pylint: disable-next=consider-using-with
        self.temp_dir = tempfile.TemporaryDirectory()
        self.metadata_dir = os.path.join(self.temp_dir.name, "metadata")
        self.targets_dir = os.path.join(self.temp_dir.name, "targets")
        os.mkdir(self.metadata_dir)
        os.mkdir(self.targets_dir)

        # Setup the repository, bootstrap client root.json
        self.sim = RepositorySimulator()
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
        """Creates a new updater and runs refresh."""
        if self.sim.dump_dir is not None:
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

    def test_refresh(self) -> None:
        # Update top level metadata
        self._run_refresh()

        # New root (root needs to be explicitly signed)
        self.sim.root.version += 1
        self.sim.publish_root()

        self._run_refresh()

        # New timestamp
        self.sim.update_timestamp()

        self._run_refresh()

        # New targets, snapshot, timestamp version
        self.sim.targets.version += 1
        self.sim.update_snapshot()

        self._run_refresh()

    targets: utils.DataSet = {
        "standard case": ("targetpath", b"content", "targetpath"),
        "non-asci case": ("åäö", b"more content", "%C3%A5%C3%A4%C3%B6"),
        "subdirectory case": (
            "a/b/c/targetpath",
            b"dir target content",
            "a%2Fb%2Fc%2Ftargetpath",
        ),
    }

    @utils.run_sub_tests_with_dataset(targets)
    def test_targets(self, test_case_data: Tuple[str, bytes, str]) -> None:
        targetpath, content, encoded_path = test_case_data
        path = os.path.join(self.targets_dir, encoded_path)

        updater = self._run_refresh()
        # target does not exist yet, configuration is what we expect
        self.assertIsNone(updater.get_targetinfo(targetpath))
        self.assertTrue(self.sim.root.consistent_snapshot)
        self.assertTrue(updater.config.prefix_targets_with_hash)

        # Add targets to repository
        self.sim.targets.version += 1
        self.sim.add_target("targets", content, targetpath)
        self.sim.update_snapshot()

        updater = self._run_refresh()
        # target now exists, is not in cache yet
        info = updater.get_targetinfo(targetpath)
        assert info is not None
        # Test without and with explicit local filepath
        self.assertIsNone(updater.find_cached_target(info))
        self.assertIsNone(updater.find_cached_target(info, path))

        # download target, assert it is in cache and content is correct
        self.assertEqual(path, updater.download_target(info))
        self.assertEqual(path, updater.find_cached_target(info))
        self.assertEqual(path, updater.find_cached_target(info, path))

        with open(path, "rb") as f:
            self.assertEqual(f.read(), content)

        # download using explicit filepath as well
        os.remove(path)
        self.assertEqual(path, updater.download_target(info, path))
        self.assertEqual(path, updater.find_cached_target(info))
        self.assertEqual(path, updater.find_cached_target(info, path))

    def test_fishy_rolenames(self) -> None:
        roles_to_filenames = {
            "../a": "..%2Fa.json",
            ".": "..json",
            "/": "%2F.json",
            "ö": "%C3%B6.json",
        }

        # Add new delegated targets, update the snapshot
        spec_version = ".".join(SPECIFICATION_VERSION)
        targets = Targets(1, spec_version, self.sim.safe_expiry, {}, None)
        for role in roles_to_filenames:
            self.sim.add_delegation(
                "targets", role, targets, False, ["*"], None
            )
        self.sim.update_snapshot()

        updater = self._run_refresh()

        # trigger updater to fetch the delegated metadata, check filenames
        updater.get_targetinfo("anything")
        local_metadata = os.listdir(self.metadata_dir)
        for fname in roles_to_filenames.values():
            self.assertTrue(fname in local_metadata)

    def test_keys_and_signatures(self) -> None:
        """Example of the two trickiest test areas: keys and root updates"""

        # Update top level metadata
        self._run_refresh()

        # New targets: signed with only a new key that is not in roles keys
        old_signers = self.sim.signers.pop("targets")
        key, signer = self.sim.create_key()
        self.sim.add_signer("targets", signer)
        self.sim.targets.version += 1
        self.sim.update_snapshot()

        with self.assertRaises(UnsignedMetadataError):
            self._run_refresh()

        # New root: Add the new key as targets role key
        # (root changes require explicit publishing)
        self.sim.root.add_key("targets", key)
        self.sim.root.version += 1
        self.sim.publish_root()

        self._run_refresh()

        # New root: Raise targets threshold to 2
        self.sim.root.roles["targets"].threshold = 2
        self.sim.root.version += 1
        self.sim.publish_root()

        with self.assertRaises(UnsignedMetadataError):
            self._run_refresh()

        # New targets: sign with both new and any original keys
        for signer in old_signers.values():
            self.sim.add_signer("targets", signer)
        self.sim.targets.version += 1
        self.sim.update_snapshot()

        self._run_refresh()

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
    def test_not_loading_targets_twice(self, wrapped_open: MagicMock) -> None:
        # Do not load targets roles more than once when traversing
        # the delegations tree

        # Add new delegated targets, update the snapshot
        spec_version = ".".join(SPECIFICATION_VERSION)
        targets = Targets(1, spec_version, self.sim.safe_expiry, {}, None)
        self.sim.add_delegation("targets", "role1", targets, False, ["*"], None)
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


if __name__ == "__main__":
    if "--dump" in sys.argv:
        TestUpdater.dump_dir = tempfile.mkdtemp()
        print(f"Repository Simulator dumps in {TestUpdater.dump_dir}")
        sys.argv.remove("--dump")

    utils.configure_test_logging(sys.argv)
    unittest.main()
