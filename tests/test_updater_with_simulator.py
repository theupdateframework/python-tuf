#!/usr/bin/env python

# Copyright 2021, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Test ngclient Updater using the repository simulator
"""

import os
import sys
import tempfile
from tuf.api.metadata import SPECIFICATION_VERSION, Targets
from typing import Optional, Tuple
from tuf.exceptions import UnsignedMetadataError, BadVersionNumberError
import unittest

from tuf.ngclient import Updater

from tests import utils
from tests.repository_simulator import RepositorySimulator
from securesystemslib import hash as sslib_hash


class TestUpdater(unittest.TestCase):
    # set dump_dir to trigger repository state dumps
    dump_dir:Optional[str] = None

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.metadata_dir = os.path.join(self.temp_dir.name, "metadata")
        self.targets_dir = os.path.join(self.temp_dir.name, "targets")
        os.mkdir(self.metadata_dir)
        os.mkdir(self.targets_dir)

        # Setup the repository, bootstrap client root.json
        self.sim = RepositorySimulator()
        with open(os.path.join(self.metadata_dir, "root.json"), "bw") as f:
            root = self.sim.download_bytes("https://example.com/metadata/1.root.json", 100000)
            f.write(root)

        if self.dump_dir is not None:
            # create test specific dump directory
            name = self.id().split('.')[-1]
            self.sim.dump_dir = os.path.join(self.dump_dir, name)
            os.mkdir(self.sim.dump_dir)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _run_refresh(self) -> Updater:
        if self.sim.dump_dir is not None:
            self.sim.write()

        updater = Updater(
            self.metadata_dir,
            "https://example.com/metadata/",
            "https://example.com/targets/",
            self.sim
        )
        updater.refresh()
        return updater

    def test_refresh(self):
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
        "subdirectory case": ("a/b/c/targetpath", b"dir target content", "a%2Fb%2Fc%2Ftargetpath"),
    }

    @utils.run_sub_tests_with_dataset(targets)
    def test_targets(self, test_case_data: Tuple[str, bytes, str]):
        targetpath, content, encoded_path = test_case_data
        # target does not exist yet
        updater = self._run_refresh()
        self.assertIsNone(updater.get_one_valid_targetinfo(targetpath))

        # Add targets to repository
        self.sim.targets.version += 1
        self.sim.add_target("targets", content, targetpath)
        self.sim.update_snapshot()

        updater = self._run_refresh()
        # target now exists, is not in cache yet
        file_info = updater.get_one_valid_targetinfo(targetpath)
        self.assertIsNotNone(file_info)
        self.assertEqual(
            updater.updated_targets([file_info], self.targets_dir),
            [file_info]
        )

        # Assert consistent_snapshot is True and downloaded targets have prefix.
        self.assertTrue(self.sim.root.consistent_snapshot)
        self.assertTrue(updater.config.prefix_targets_with_hash)
        # download target, assert it is in cache and content is correct
        local_path = updater.download_target(file_info, self.targets_dir)
        self.assertEqual(
            updater.updated_targets([file_info], self.targets_dir), []
        )
        self.assertTrue(local_path.startswith(self.targets_dir))
        with open(local_path, "rb") as f:
            self.assertEqual(f.read(), content)

        # Assert that the targetpath was URL encoded as expected.
        encoded_absolute_path = os.path.join(self.targets_dir, encoded_path)
        self.assertEqual(local_path, encoded_absolute_path)



    def test_fishy_rolenames(self):
        roles_to_filenames = {
            "../a": "..%2Fa.json",
            "": ".json",
            ".": "..json",
            "/": "%2F.json",
            "ö": "%C3%B6.json"
        }

        # Add new delegated targets, update the snapshot
        spec_version = ".".join(SPECIFICATION_VERSION)
        targets = Targets(1, spec_version, self.sim.safe_expiry, {}, None)
        for role in roles_to_filenames.keys():
            self.sim.add_delegation("targets", role, targets, False, ["*"], None)
        self.sim.update_snapshot()

        updater = self._run_refresh()

        # trigger updater to fetch the delegated metadata, check filenames
        updater.get_one_valid_targetinfo("anything")
        local_metadata = os.listdir(self.metadata_dir)
        for fname in roles_to_filenames.values():
            self.assertTrue(fname in local_metadata)

    def test_keys_and_signatures(self):
        """Example of the two trickiest test areas: keys and root updates"""

        # Update top level metadata
        self._run_refresh()

        # New targets: signed with a new key that is not in roles keys
        old_signer = self.sim.signers["targets"].pop()
        key, signer = self.sim.create_key()
        self.sim.signers["targets"] = [signer]
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

        # New targets: sign with both new and old key
        self.sim.signers["targets"] = [signer, old_signer]
        self.sim.targets.version += 1
        self.sim.update_snapshot()

        self._run_refresh()

    def test_snapshot_rollback_with_local_snapshot_hash_mismatch(self):
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

        # The new targets should have a lower version than the local trusted one.
        self.sim.targets.version = 1
        self.sim.update_snapshot()

        # During the snapshot update, the local snapshot will be loaded even if
        # there is a hash mismatch with timestamp.snapshot_meta, because it will
        # be considered as trusted.
        # Should fail as a new version of snapshot will be fetched which lowers
        # the snapshot.meta["targets.json"] version by 1 and throws an error.
        with self.assertRaises(BadVersionNumberError):
            self._run_refresh()


if __name__ == "__main__":
    if "--dump" in sys.argv:
        TestUpdater.dump_dir = tempfile.mkdtemp()
        print(f"Repository Simulator dumps in {TestUpdater.dump_dir}")
        sys.argv.remove("--dump")

    utils.configure_test_logging(sys.argv)
    unittest.main()
