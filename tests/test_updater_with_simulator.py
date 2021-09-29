#!/usr/bin/env python

# Copyright 2021, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Test ngclient Updater using the repository simulator
"""

import logging
import os
import sys
import tempfile
from typing import Optional, Tuple
from tuf.exceptions import UnsignedMetadataError
import unittest

from tuf.ngclient import Updater

from tests import utils
from tests.repository_simulator import RepositorySimulator


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

if __name__ == "__main__":
    if "--dump" in sys.argv:
        TestUpdater.dump_dir = tempfile.mkdtemp()
        print(f"Repository Simulator dumps in {TestUpdater.dump_dir}")
        sys.argv.remove("--dump")

    utils.configure_test_logging(sys.argv)
    unittest.main()
