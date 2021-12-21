#!/usr/bin/env python

# Copyright 2021, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Test ngclient Updater using the repository simulator.
"""

import os
import sys
import tempfile
import unittest
from typing import Optional

from tests import utils
from tests.repository_simulator import RepositorySimulator
from tuf.exceptions import BadVersionNumberError
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


if __name__ == "__main__":
    if "--dump" in sys.argv:
        TestUpdater.dump_dir = tempfile.mkdtemp()
        print(f"Repository Simulator dumps in {TestUpdater.dump_dir}")
        sys.argv.remove("--dump")

    utils.configure_test_logging(sys.argv)
    unittest.main()
