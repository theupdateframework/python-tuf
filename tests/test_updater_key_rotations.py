#!/usr/bin/env python

# Copyright 2021, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Test ngclient Updater key rotation handling"""

from dataclasses import dataclass
from typing import List, Optional, Type
import os
import sys
import tempfile
import unittest

from securesystemslib.signer import SSlibSigner

from tuf.api.metadata import Key
from tuf.exceptions import UnsignedMetadataError
from tuf.ngclient import Updater

from tests import utils
from tests.repository_simulator import RepositorySimulator
from tests.utils import run_sub_tests_with_dataset


@dataclass
class RootVersion:
    keys: List[int]
    threshold: int
    signatures: List[int]
    result: Optional[Type[Exception]] = None


class TestUpdaterKeyRotations(unittest.TestCase):
    """Test ngclient root rotation handling"""
    # set dump_dir to trigger repository state dumps
    dump_dir: Optional[str] = None

    def setUp(self) -> None:
        self.sim = None
        self.metadata_dir = None
        self.subtest_count = 0
        # pylint: disable-next=consider-using-with
        self.temp_dir = tempfile.TemporaryDirectory()

        # Pre-create a bunch of keys and signers
        self.keys: List[Key] = []
        self.signers: List[SSlibSigner] = []
        for _ in range(10):
            key, signer = RepositorySimulator.create_key()
            self.keys.append(key)
            self.signers.append(signer)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def setup_subtest(self) -> None:
        self.subtest_count += 1

        # Setup repository for subtest: make sure no roots have been published
        self.sim = RepositorySimulator()
        self.sim.signed_roots.clear()
        self.sim.root.version = 0

        if self.dump_dir is not None:
            # create subtest dumpdir
            name = f"{self.id().split('.')[-1]}-{self.subtest_count}"
            self.sim.dump_dir = os.path.join(self.dump_dir, name)
            os.mkdir(self.sim.dump_dir)

    def _run_refresh(self) -> None:
        """Create new updater, run refresh"""
        if self.sim.dump_dir is not None:
            self.sim.write()

        # bootstrap with initial root
        self.metadata_dir = tempfile.mkdtemp(dir=self.temp_dir.name)
        with open(os.path.join(self.metadata_dir, "root.json"), "bw") as f:
            f.write(self.sim.signed_roots[0])

        updater = Updater(
            self.metadata_dir,
            "https://example.com/metadata/",
            fetcher=self.sim,
        )
        updater.refresh()

    root_rotation_cases = {
        "1-of-1 key rotation": [
            RootVersion([1], 1, [1]),
            RootVersion([2], 1, [2, 1]),
            RootVersion([2], 1, [2]),
        ],
        "1-of-1 key rotation, unused signatures": [
            RootVersion([1], 1, [3, 1, 4]),
            RootVersion([2], 1, [3, 2, 1, 4]),
            RootVersion([2], 1, [3, 2, 4]),
        ],
        "1-of-1 key rotation fail: not signed with old key": [
            RootVersion([1], 1, [1]),
            RootVersion([2], 1, [2, 3, 4], UnsignedMetadataError),
        ],
        "1-of-1 key rotation fail: not signed with new key": [
            RootVersion([1], 1, [1]),
            RootVersion([2], 1, [1, 3, 4], UnsignedMetadataError),
        ],
        "3-of-5, sign with different keycombos": [
            RootVersion([0, 1, 2, 3, 4], 3, [0, 2, 4]),
            RootVersion([0, 1, 2, 3, 4], 3, [0, 4, 1]),
            RootVersion([0, 1, 2, 3, 4], 3, [0, 1, 3]),
            RootVersion([0, 1, 2, 3, 4], 3, [0, 1, 3]),
        ],
        "3-of-5, one key rotated": [
            RootVersion([0, 1, 2, 3, 4], 3, [0, 2, 4]),
            RootVersion([0, 1, 3, 4, 5], 3, [0, 4, 1]),
        ],
        "3-of-5, one key rotate fails: not signed with 3 new keys": [
            RootVersion([0, 1, 2, 3, 4], 3, [0, 2, 4]),
            RootVersion([0, 1, 3, 4, 5], 3, [0, 2, 4], UnsignedMetadataError),
        ],
        "3-of-5, one key rotate fails: not signed with 3 old keys": [
            RootVersion([0, 1, 2, 3, 4], 3, [0, 2, 4]),
            RootVersion([0, 1, 3, 4, 5], 3, [0, 4, 5], UnsignedMetadataError),
        ],
        "3-of-5, one key rotated, with intermediate step": [
            RootVersion([0, 1, 2, 3, 4], 3, [0, 2, 4]),
            RootVersion([0, 1, 3, 4, 5], 3, [0, 2, 4, 5]),
            RootVersion([0, 1, 3, 4, 5], 3, [0, 4, 5]),
        ],
        "3-of-5, all keys rotated, with intermediate step": [
            RootVersion([0, 1, 2, 3, 4], 3, [0, 2, 4]),
            RootVersion([5, 6, 7, 8, 9], 3, [0, 2, 4, 5, 6, 7]),
            RootVersion([5, 6, 7, 8, 9], 3, [5, 6, 7]),
        ],
        "1-of-3 threshold increase to 2-of-3": [
            RootVersion([1, 2, 3], 1, [1]),
            RootVersion([1, 2, 3], 2, [1, 2]),
        ],
        "1-of-3 threshold bump to 2-of-3 fails: new threshold not reached": [
            RootVersion([1, 2, 3], 1, [1]),
            RootVersion([1, 2, 3], 2, [2], UnsignedMetadataError),
        ],
        "2-of-3 threshold decrease to 1-of-3": [
            RootVersion([1, 2, 3], 2, [1, 2]),
            RootVersion([1, 2, 3], 1, [1, 2]),
            RootVersion([1, 2, 3], 1, [1]),
        ],
        "2-of-3 threshold decr. to 1-of-3 fails: old threshold not reached": [
            RootVersion([1, 2, 3], 2, [1, 2]),
            RootVersion([1, 2, 3], 1, [1], UnsignedMetadataError),
        ],
        "1-of-2 threshold increase to 2-of-2": [
            RootVersion([1], 1, [1]),
            RootVersion([1, 2], 2, [1, 2]),
        ],
    }

    @run_sub_tests_with_dataset(root_rotation_cases)
    def test_root_rotation(self, root_versions: List[RootVersion]) -> None:
        """Test Updater.refresh() with various sequences of root updates

        Each RootVersion in the list describes root keys and signatures of a
        remote root metadata version. As an example:
            RootVersion([1,2,3], 2, [1,2])
        defines a root that contains keys 1, 2 and 3 with threshold 2. The
        metadata is signed with keys 1 and 2.

        Assert that refresh() result is expected and that local root on disk is
        the expected one after all roots have been loaded from remote using the
        standard client update workflow.
        """
        self.setup_subtest()

        # Publish all remote root versions defined in root_versions
        for rootver in root_versions:
            # clear root keys, signers
            self.sim.root.roles["root"].keyids.clear()
            self.sim.signers["root"].clear()

            self.sim.root.roles["root"].threshold = rootver.threshold
            for i in rootver.keys:
                self.sim.root.add_key("root", self.keys[i])
            for i in rootver.signatures:
                self.sim.add_signer("root", self.signers[i])
            self.sim.root.version += 1
            self.sim.publish_root()

        # run client workflow, assert success/failure
        expected_result = root_versions[-1].result
        if expected_result is None:
            self._run_refresh()
            expected_local_root = self.sim.signed_roots[-1]
        else:
            # failure expected: local root should be the root before last
            with self.assertRaises(expected_result):
                self._run_refresh()
            expected_local_root = self.sim.signed_roots[-2]

        # assert local root on disk is expected
        with open(os.path.join(self.metadata_dir, "root.json"), "rb") as f:
            self.assertEqual(f.read(), expected_local_root)


if __name__ == "__main__":
    if "--dump" in sys.argv:
        TestUpdaterKeyRotations.dump_dir = tempfile.mkdtemp()
        print(f"Repository dumps in {TestUpdaterKeyRotations.dump_dir}")
        sys.argv.remove("--dump")

    utils.configure_test_logging(sys.argv)
    unittest.main()
