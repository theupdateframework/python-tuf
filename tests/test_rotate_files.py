#!/usr/bin/env python

# Copyright 2023, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

""" Test ngclient handling of rotate files"""

import os
import sys
import tempfile
import unittest
from typing import ClassVar, List, Optional

from securesystemslib.signer import SSlibSigner

from tests import utils
from tests.repository_simulator import RepositorySimulator
from tuf.api import exceptions
from tuf.api.metadata import Key
from tuf.ngclient import Updater


class TestRotateFiles(unittest.TestCase):
    """Test ngclient handling of rotate files"""

    # set dump_dir to trigger repository state dumps
    dump_dir: Optional[str] = None
    temp_dir: ClassVar[tempfile.TemporaryDirectory]
    keys: ClassVar[List[Key]]
    signers: ClassVar[List[SSlibSigner]]

    @classmethod
    def setUpClass(cls) -> None:
        # pylint: disable-next=consider-using-with
        cls.temp_dir = tempfile.TemporaryDirectory()

        # pre-create keys and signers
        cls.keys = []
        cls.signers = []
        for _ in range(10):
            key, signer = RepositorySimulator.create_key()
            cls.keys.append(key)
            cls.signers.append(signer)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp_dir.cleanup()

    def setUp(self) -> None:
        self.metadata_dir = os.path.join(self.temp_dir.name, "metadata")
        self.targets_dir = os.path.join(self.temp_dir.name, "targets")
        os.mkdir(self.metadata_dir)
        os.mkdir(self.targets_dir)

        self.sim = RepositorySimulator()
        with open(os.path.join(self.metadata_dir, "root.json"), "bw") as f:
            f.write(self.sim.signed_roots[0])

        if self.dump_dir is not None:
            # create subtest dumpdir
            # pylint: disable=no-member
            name = f"{self.id().split('.')[-1]}-{self.case_name}"
            self.sim.dump_dir = os.path.join(self.dump_dir, name)
            os.mkdir(self.sim.dump_dir)

    def _init_updater(self) -> Updater:
        """Creates a new updater instance."""
        if self.sim.dump_dir is not None:
            self.sim.write()

        updater = Updater(
            self.metadata_dir,
            "https://example.com/metadata/",
            self.targets_dir,
            "https://example.com/targets/",
            self.sim,
        )
        return updater

    def test_read_rotate_file(self) -> None:
        root = self.sim.root
        new_keyids = root.roles["snapshot"].keyids
        new_keys = {k: v for (k, v) in root.keys.items() if k in new_keyids}
        self.sim.add_rotate_file(
            "timestamp", new_keys, 1, self.sim.signers["timestamp"]
        )
        self.sim.update_snapshot()

        updater = self._init_updater()
        with self.assertRaises(exceptions.UnsignedMetadataError):
            updater.refresh()

        old_keyids = root.roles["timestamp"].keyids
        old_keys = {k: v for (k, v) in root.keys.items() if k in old_keyids}
        self.sim.add_rotate_file(
            "timestamp", old_keys, 1, self.sim.signers["snapshot"]
        )
        updater.refresh()


if __name__ == "__main__":
    if "--dump" in sys.argv:
        TestRotateFiles.dump_dir = tempfile.mkdtemp()
        print(f"Repository dumps in {TestRotateFiles.dump_dir}")
        sys.argv.remove("--dump")

    utils.configure_test_logging(sys.argv)
    unittest.main()
