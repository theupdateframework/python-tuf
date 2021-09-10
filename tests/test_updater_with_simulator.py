#!/usr/bin/env python

# Copyright 2021, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Test ngclient Updater using the repository simulator
"""

import logging
import os
import sys
import tempfile
from typing import Optional
from tuf.exceptions import UnsignedMetadataError
import unittest

from tuf.ngclient import Updater

from tests import utils
from tests.repository_simulator import RepositorySimulator

class TestUpdater(unittest.TestCase):
    # set dump_dir to trigger repository state dumps
    dump_dir:Optional[str] = None

    def setUp(self):
        self.client_dir = tempfile.TemporaryDirectory()

        # Setup the repository, bootstrap client root.json
        self.sim = RepositorySimulator()
        with open(os.path.join(self.client_dir.name, "root.json"), "bw") as f:
            root = self.sim.download_bytes("https://example.com/metadata/1.root.json", 100000)
            f.write(root)

        if self.dump_dir is not None:
            # create test specific dump directory
            name = self.id().split('.')[-1]
            self.sim.dump_dir = os.path.join(self.dump_dir, name)
            os.mkdir(self.sim.dump_dir)

    def _run_refresh(self):
        if self.sim.dump_dir is not None:
            self.sim.write()

        updater = Updater(
            self.client_dir.name,
            "https://example.com/metadata/",
            "https://example.com/targets/",
            self.sim
        )
        updater.refresh()

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

    def tearDown(self):
        self.client_dir.cleanup()

if __name__ == "__main__":
    if "--dump" in sys.argv:
        TestUpdater.dump_dir = tempfile.mkdtemp()
        print(f"Repository Simulator dumps in {TestUpdater.dump_dir}")
        sys.argv.remove("--dump")

    utils.configure_test_logging(sys.argv)
    unittest.main()
