# Copyright 2021, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Test ngclient Updater key rotation handling"""

import os
import sys
import tempfile
import unittest
from dataclasses import dataclass
from typing import ClassVar, Dict, List, Optional, Type

from securesystemslib.signer import CryptoSigner, Signer

from tests import utils
from tests.repository_simulator import RepositorySimulator
from tests.utils import run_sub_tests_with_dataset
from tuf.api.exceptions import UnsignedMetadataError
from tuf.api.metadata import Key, Root
from tuf.ngclient import Updater


@dataclass
class MdVersion:
    keys: List[int]
    threshold: int
    sigs: List[int]
    res: Optional[Type[Exception]] = None


class TestUpdaterKeyRotations(unittest.TestCase):
    """Test ngclient root rotation handling"""

    # set dump_dir to trigger repository state dumps
    dump_dir: Optional[str] = None
    temp_dir: ClassVar[tempfile.TemporaryDirectory]
    keys: ClassVar[List[Key]]
    signers: ClassVar[List[Signer]]

    @classmethod
    def setUpClass(cls) -> None:
        cls.temp_dir = tempfile.TemporaryDirectory()

        # Pre-create a bunch of keys and signers
        cls.signers = []
        for _ in range(10):
            signer = CryptoSigner.generate_ed25519()
            cls.signers.append(signer)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp_dir.cleanup()

    def setup_subtest(self) -> None:
        # Setup repository for subtest: make sure no roots have been published
        self.sim = RepositorySimulator()
        self.sim.signed_roots.clear()
        self.sim.root.version = 0

        if self.dump_dir is not None:
            # create subtest dumpdir
            name = f"{self.id().split('.')[-1]}-{self.case_name}"
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

    # fmt: off
    root_rotation_cases = {
        "1-of-1 key rotation": [
            MdVersion(keys=[1], threshold=1, sigs=[1]),
            MdVersion(keys=[2], threshold=1, sigs=[2, 1]),
            MdVersion(keys=[2], threshold=1, sigs=[2]),
        ],
        "1-of-1 key rotation, unused signatures": [
            MdVersion(keys=[1], threshold=1, sigs=[3, 1, 4]),
            MdVersion(keys=[2], threshold=1, sigs=[3, 2, 1, 4]),
            MdVersion(keys=[2], threshold=1, sigs=[3, 2, 4]),
        ],
        "1-of-1 key rotation fail: not signed with old key": [
            MdVersion(keys=[1], threshold=1, sigs=[1]),
            MdVersion(keys=[2], threshold=1, sigs=[2, 3, 4], res=UnsignedMetadataError),
        ],
        "1-of-1 key rotation fail: not signed with new key": [
            MdVersion(keys=[1], threshold=1, sigs=[1]),
            MdVersion(keys=[2], threshold=1, sigs=[1, 3, 4], res=UnsignedMetadataError),
        ],
        "3-of-5, sign with different keycombos": [
            MdVersion(keys=[0, 1, 2, 3, 4], threshold=3, sigs=[0, 2, 4]),
            MdVersion(keys=[0, 1, 2, 3, 4], threshold=3, sigs=[0, 4, 1]),
            MdVersion(keys=[0, 1, 2, 3, 4], threshold=3, sigs=[0, 1, 3]),
            MdVersion(keys=[0, 1, 2, 3, 4], threshold=3, sigs=[0, 1, 3]),
        ],
        "3-of-5, one key rotated": [
            MdVersion(keys=[0, 1, 2, 3, 4], threshold=3, sigs=[0, 2, 4]),
            MdVersion(keys=[0, 1, 3, 4, 5], threshold=3, sigs=[0, 4, 1]),
        ],
        "3-of-5, one key rotate fails: not signed with 3 new keys": [
            MdVersion(keys=[0, 1, 2, 3, 4], threshold=3, sigs=[0, 2, 4]),
            MdVersion(keys=[0, 1, 3, 4, 5], threshold=3, sigs=[0, 2, 4], res=UnsignedMetadataError),
        ],
        "3-of-5, one key rotate fails: not signed with 3 old keys": [
            MdVersion(keys=[0, 1, 2, 3, 4], threshold=3, sigs=[0, 2, 4]),
            MdVersion(keys=[0, 1, 3, 4, 5], threshold=3, sigs=[0, 4, 5], res=UnsignedMetadataError),
        ],
        "3-of-5, one key rotated, with intermediate step": [
            MdVersion(keys=[0, 1, 2, 3, 4], threshold=3, sigs=[0, 2, 4]),
            MdVersion(keys=[0, 1, 3, 4, 5], threshold=3, sigs=[0, 2, 4, 5]),
            MdVersion(keys=[0, 1, 3, 4, 5], threshold=3, sigs=[0, 4, 5]),
        ],
        "3-of-5, all keys rotated, with intermediate step": [
            MdVersion(keys=[0, 1, 2, 3, 4], threshold=3, sigs=[0, 2, 4]),
            MdVersion(keys=[5, 6, 7, 8, 9], threshold=3, sigs=[0, 2, 4, 5, 6, 7]),
            MdVersion(keys=[5, 6, 7, 8, 9], threshold=3, sigs=[5, 6, 7]),
        ],
        "1-of-3 threshold increase to 2-of-3": [
            MdVersion(keys=[1, 2, 3], threshold=1, sigs=[1]),
            MdVersion(keys=[1, 2, 3], threshold=2, sigs=[1, 2]),
        ],
        "1-of-3 threshold bump to 2-of-3 fails: new threshold not reached": [
            MdVersion(keys=[1, 2, 3], threshold=1, sigs=[1]),
            MdVersion(keys=[1, 2, 3], threshold=2, sigs=[2], res=UnsignedMetadataError),
        ],
        "2-of-3 threshold decrease to 1-of-3": [
            MdVersion(keys=[1, 2, 3], threshold=2, sigs=[1, 2]),
            MdVersion(keys=[1, 2, 3], threshold=1, sigs=[1, 2]),
            MdVersion(keys=[1, 2, 3], threshold=1, sigs=[1]),
        ],
        "2-of-3 threshold decr. to 1-of-3 fails: old threshold not reached": [
            MdVersion(keys=[1, 2, 3], threshold=2, sigs=[1, 2]),
            MdVersion(keys=[1, 2, 3], threshold=1, sigs=[1], res=UnsignedMetadataError),
        ],
        "1-of-2 threshold increase to 2-of-2": [
            MdVersion(keys=[1], threshold=1, sigs=[1]),
            MdVersion(keys=[1, 2], threshold=2, sigs=[1, 2]),
        ],
    }
    # fmt: on

    @run_sub_tests_with_dataset(root_rotation_cases)
    def test_root_rotation(self, root_versions: List[MdVersion]) -> None:
        """Test Updater.refresh() with various sequences of root updates

        Each MdVersion in the list describes root keys and signatures of a
        remote root metadata version. As an example:
            MdVersion([1,2,3], 2, [1,2])
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
            self.sim.root.roles[Root.type].keyids.clear()
            self.sim.signers[Root.type].clear()

            self.sim.root.roles[Root.type].threshold = rootver.threshold
            for i in rootver.keys:
                self.sim.root.add_key(self.signers[i].public_key, Root.type)
            for i in rootver.sigs:
                self.sim.add_signer(Root.type, self.signers[i])
            self.sim.root.version += 1
            self.sim.publish_root()

        # run client workflow, assert success/failure
        expected_error = root_versions[-1].res
        if expected_error is None:
            self._run_refresh()
            expected_local_root = self.sim.signed_roots[-1]
        else:
            # failure expected: local root should be the root before last
            with self.assertRaises(expected_error):
                self._run_refresh()
            expected_local_root = self.sim.signed_roots[-2]

        # assert local root on disk is expected
        with open(os.path.join(self.metadata_dir, "root.json"), "rb") as f:
            self.assertEqual(f.read(), expected_local_root)

    # fmt: off
    non_root_rotation_cases: Dict[str, MdVersion] = {
        "1-of-1 key rotation":
            MdVersion(keys=[2], threshold=1, sigs=[2]),
        "1-of-1 key rotation, unused signatures":
            MdVersion(keys=[1], threshold=1, sigs=[3, 1, 4]),
        "1-of-1 key rotation fail: not signed with new key":
            MdVersion(keys=[2], threshold=1, sigs=[1, 3, 4], res=UnsignedMetadataError),
        "3-of-5, one key signature wrong: not signed with 3 expected keys":
            MdVersion(keys=[0, 1, 3, 4, 5], threshold=3, sigs=[0, 2, 4], res=UnsignedMetadataError),
        "2-of-5, one key signature mising: threshold not reached":
            MdVersion(keys=[0, 1, 3, 4, 5], threshold=3, sigs=[0, 4], res=UnsignedMetadataError),
        "3-of-5, sign first combo":
            MdVersion(keys=[0, 1, 2, 3, 4], threshold=3, sigs=[0, 2, 4]),
        "3-of-5, sign second combo":
            MdVersion(keys=[0, 1, 2, 3, 4], threshold=3, sigs=[0, 4, 1]),
        "3-of-5, sign third combo":
            MdVersion(keys=[0, 1, 2, 3, 4], threshold=3, sigs=[0, 1, 3]),
        "3-of-5, sign fourth combo":
            MdVersion(keys=[0, 1, 2, 3, 4], threshold=3, sigs=[1, 2, 3]),
        "3-of-5, sign fifth combo":
            MdVersion(keys=[0, 1, 2, 3, 4], threshold=3, sigs=[2, 3, 4]),
    }
    # fmt: on

    @run_sub_tests_with_dataset(non_root_rotation_cases)
    def test_non_root_rotations(self, md_version: MdVersion) -> None:
        """Test Updater.refresh() with various sequences of metadata updates

        Each MdVersion in the list describes metadata keys and signatures
        of a remote metadata version. As an example:
            MdVersion([1,2,3], 2, [1,2])
        defines a metadata that contains keys 1, 2 and 3 with threshold 2. The
        metadata is signed with keys 1 and 2.

        Assert that refresh() result is expected and that local metadata on disk
        is the expected one after all roots have been loaded from remote using
        the standard client update workflow.
        """
        self.setup_subtest()
        roles = ["timestamp", "snapshot", "targets"]
        for role in roles:
            # clear role keys, signers
            self.sim.root.roles[role].keyids.clear()
            self.sim.signers[role].clear()

            self.sim.root.roles[role].threshold = md_version.threshold
            for i in md_version.keys:
                self.sim.root.add_key(self.signers[i].public_key, role)

            for i in md_version.sigs:
                self.sim.add_signer(role, self.signers[i])

            self.sim.root.version += 1
            self.sim.publish_root()

            # run client workflow, assert success/failure
            expected_error = md_version.res
            if expected_error is None:
                self._run_refresh()

                # Call fetch_metadata to sign metadata with new keys
                expected_local_md: bytes = self.sim.fetch_metadata(role)
                # assert local metadata role is on disk as expected
                md_path = os.path.join(self.metadata_dir, f"{role}.json")
                with open(md_path, "rb") as f:
                    data = f.read()
                    self.assertEqual(data, expected_local_md)
            else:
                # failure expected
                with self.assertRaises(expected_error):
                    self._run_refresh()


if __name__ == "__main__":
    if "--dump" in sys.argv:
        TestUpdaterKeyRotations.dump_dir = tempfile.mkdtemp()
        print(f"Repository dumps in {TestUpdaterKeyRotations.dump_dir}")
        sys.argv.remove("--dump")

    utils.configure_test_logging(sys.argv)
    unittest.main()
