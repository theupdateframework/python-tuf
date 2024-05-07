# Copyright 2022, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Test ngclient Updater validations."""

import os
import sys
import tempfile
import unittest

from tests import utils
from tests.repository_simulator import RepositorySimulator
from tuf.ngclient import Updater


class TestUpdater(unittest.TestCase):
    """Test ngclient Updater input validation."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.metadata_dir = os.path.join(self.temp_dir.name, "metadata")
        self.targets_dir = os.path.join(self.temp_dir.name, "targets")
        os.mkdir(self.metadata_dir)
        os.mkdir(self.targets_dir)

        # Setup the repository, bootstrap client root.json
        self.sim = RepositorySimulator()
        with open(os.path.join(self.metadata_dir, "root.json"), "bw") as f:
            f.write(self.sim.signed_roots[0])

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _new_updater(self) -> Updater:
        return Updater(
            self.metadata_dir,
            "https://example.com/metadata/",
            self.targets_dir,
            "https://example.com/targets/",
            fetcher=self.sim,
        )

    def test_local_target_storage_fail(self) -> None:
        self.sim.add_target("targets", b"content", "targetpath")
        self.sim.targets.version += 1
        self.sim.update_snapshot()

        updater = self._new_updater()
        target_info = updater.get_targetinfo("targetpath")
        assert target_info is not None
        with self.assertRaises(FileNotFoundError):
            updater.download_target(target_info, filepath="")

    def test_non_existing_metadata_dir(self) -> None:
        with self.assertRaises(FileNotFoundError):
            # Initialize Updater with non-existing metadata_dir
            Updater(
                "non_existing_metadata_dir",
                "https://example.com/metadata/",
                fetcher=self.sim,
            )


if __name__ == "__main__":
    utils.configure_test_logging(sys.argv)
    unittest.main()
