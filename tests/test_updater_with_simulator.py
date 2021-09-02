#!/usr/bin/env python

# Copyright 2021, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Test ngclient Updater using the repository simulator
"""

import logging
import os
import sys
import tempfile
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
        updater = self._new_updater()
        updater.refresh()

        # TODO compare file contents?

        # New timestamp version
        self.sim.update_timestamp()

        updater = self._new_updater()
        updater.refresh()

        # TODO compare file contents?

        # New targets version
        self.sim.targets.version += 1
        self.sim.update_snapshot()

        updater = self._new_updater()
        updater.refresh()

        # TODO compare file contents?


    def tearDown(self):
        self.client_dir.cleanup()

if __name__ == "__main__":
  utils.configure_test_logging(sys.argv)
  unittest.main()
