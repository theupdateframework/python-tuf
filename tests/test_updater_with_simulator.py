#!/usr/bin/env python

# Copyright 2021, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Test ngclient Updater using the repository simulator
"""

import logging
import os
import sys
import tempfile
from tuf.exceptions import UnsignedMetadataError
import unittest

from tuf.ngclient import Updater

from tests import utils
from tests.repository_simulator import RepositorySimulator

class TestUpdater(unittest.TestCase):
    def setUp(self):
        self.client_dir = tempfile.TemporaryDirectory()

        # Setup the repository, bootstrap client root.json
        self.sim = RepositorySimulator()
        with open(os.path.join(self.client_dir.name, "root.json"), "bw") as f:
            root = self.sim.download_bytes("https://example.com/metadata/1.root.json", 100000)
            f.write(root)

    def _new_updater(self):
        return Updater(
            self.client_dir.name,
            "https://example.com/metadata/",
            "https://example.com/targets/",
            self.sim
        )

    def test_refresh(self):
        # Update top level metadata
        self._new_updater().refresh()

        # New root (root needs to be explicitly published)
        self.sim.root.version += 1
        self.sim.publish_root()

        # TODO compare file contents?

        # New timestamp version
        self.sim.update_timestamp()

        self._new_updater().refresh()

        # TODO compare file contents?

        # New targets version
        self.sim.targets.version += 1
        self.sim.update_snapshot()

        self._new_updater().refresh()

        # TODO compare file contents?

    # this is just an example of testing different key/signature situations
    def test_targets_signatures(self):
        # Update top level metadata
        self._new_updater().refresh()

        # New targets: signed by a new key that is not in roles keys
        old_signer = self.sim.signers["targets"].pop()
        key, signer = self.sim.create_key()
        self.sim.signers["targets"] = [signer]
        self.sim.targets.version += 1
        self.sim.update_snapshot()

        with self.assertRaises(UnsignedMetadataError):
            self._new_updater().refresh()

        # New root: Add the new key as targets role key
        # (root changes require explicit publishing)
        self.sim.root.add_key("targets", key)
        self.sim.root.version += 1
        self.sim.publish_root()

        self._new_updater().refresh()

        # New root: Raise targets threshold to 2
        self.sim.root.roles["targets"].threshold = 2
        self.sim.root.version += 1
        self.sim.publish_root()

        with self.assertRaises(UnsignedMetadataError):
            self._new_updater().refresh()

        # New targets: sign with both new and old key
        self.sim.signers["targets"] = [signer, old_signer]
        self.sim.targets.version += 1
        self.sim.update_snapshot()

        self._new_updater().refresh()


    def tearDown(self):
        self.client_dir.cleanup()

if __name__ == "__main__":
  utils.configure_test_logging(sys.argv)
  unittest.main()
