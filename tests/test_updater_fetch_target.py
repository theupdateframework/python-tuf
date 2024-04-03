# Copyright 2021, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Test 'Fetch target' from 'Detailed client workflow' as well as
target files storing/loading from cache.
"""

import os
import sys
import tempfile
import unittest
from dataclasses import dataclass
from typing import Optional

from tests import utils
from tests.repository_simulator import RepositorySimulator
from tuf.api.exceptions import RepositoryError
from tuf.api.metadata import DelegatedRole, Delegations
from tuf.ngclient import Updater


@dataclass
class TestTarget:
    path: str
    content: bytes
    encoded_path: str


class TestFetchTarget(unittest.TestCase):
    """Test ngclient downloading and caching target files."""

    # set dump_dir to trigger repository state dumps
    dump_dir: Optional[str] = None

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

        if self.dump_dir is not None:
            # create test specific dump directory
            name = self.id().split(".")[-1]
            self.sim.dump_dir = os.path.join(self.dump_dir, name)
            os.mkdir(self.sim.dump_dir)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _init_updater(self) -> Updater:
        """Creates a new updater instance."""
        if self.sim.dump_dir is not None:
            self.sim.write()

        return Updater(
            self.metadata_dir,
            "https://example.com/metadata/",
            self.targets_dir,
            "https://example.com/targets/",
            self.sim,
        )

    targets: utils.DataSet = {
        "standard case": TestTarget(
            path="targetpath",
            content=b"target content",
            encoded_path="targetpath",
        ),
        "non-asci case": TestTarget(
            path="åäö",
            content=b"more content",
            encoded_path="%C3%A5%C3%A4%C3%B6",
        ),
        "subdirectory case": TestTarget(
            path="a/b/c/targetpath",
            content=b"dir target content",
            encoded_path="a%2Fb%2Fc%2Ftargetpath",
        ),
    }

    @utils.run_sub_tests_with_dataset(targets)
    def test_fetch_target(self, target: TestTarget) -> None:
        path = os.path.join(self.targets_dir, target.encoded_path)

        updater = self._init_updater()
        # target does not exist yet
        self.assertIsNone(updater.get_targetinfo(target.path))

        # Add targets to repository
        self.sim.targets.version += 1
        self.sim.add_target("targets", target.content, target.path)
        self.sim.update_snapshot()

        updater = self._init_updater()
        # target now exists, is not in cache yet
        info = updater.get_targetinfo(target.path)
        assert info is not None
        # Test without and with explicit local filepath
        self.assertIsNone(updater.find_cached_target(info))
        self.assertIsNone(updater.find_cached_target(info, path))

        # download target, assert it is in cache and content is correct
        self.assertEqual(path, updater.download_target(info))
        self.assertEqual(path, updater.find_cached_target(info))
        self.assertEqual(path, updater.find_cached_target(info, path))

        with open(path, "rb") as f:
            self.assertEqual(f.read(), target.content)

        # download using explicit filepath as well
        os.remove(path)
        self.assertEqual(path, updater.download_target(info, path))
        self.assertEqual(path, updater.find_cached_target(info))
        self.assertEqual(path, updater.find_cached_target(info, path))

    def test_download_targets_with_succinct_roles(self) -> None:
        self.sim.add_succinct_roles("targets", 8, "bin")
        self.sim.update_snapshot()

        assert self.sim.targets.delegations is not None
        assert self.sim.targets.delegations.succinct_roles is not None
        succinct_roles = self.sim.targets.delegations.succinct_roles

        # Add lots of targets with unique data to imitate a real repository.
        for i in range(20):
            target_name = f"target-{i}"
            target_bin = succinct_roles.get_role_for_target(target_name)
            self.sim.add_target(
                target_bin, bytes(target_name, "utf-8"), target_name
            )

        # download each target
        updater = self._init_updater()
        for i in range(20):
            target_name = f"target-{i}"

            # Verify that the target info was successfully found.
            target_info = updater.get_targetinfo(target_name)
            assert target_info is not None
            target_full_path = updater.download_target(target_info)

            # Verify that the target content is the same as the target name.
            with open(target_full_path, encoding="utf-8") as target:
                self.assertEqual(target.read(), target_name)

    def test_invalid_target_download(self) -> None:
        target = TestTarget("targetpath", b"content", "targetpath")

        # Add target to repository
        self.sim.targets.version += 1
        self.sim.add_target("targets", target.content, target.path)
        self.sim.update_snapshot()

        updater = self._init_updater()
        info = updater.get_targetinfo(target.path)
        assert info is not None

        # Corrupt the file content to not match the hash
        self.sim.target_files[target.path].data = b"conten@"
        with self.assertRaises(RepositoryError):
            updater.download_target(info)

        # Corrupt the file content to not match the length
        self.sim.target_files[target.path].data = b"cont"
        with self.assertRaises(RepositoryError):
            updater.download_target(info)

        # Verify the file is not persisted in cache
        self.assertIsNone(updater.find_cached_target(info))

    def test_invalid_target_cache(self) -> None:
        target = TestTarget("targetpath", b"content", "targetpath")

        # Add target to repository
        self.sim.targets.version += 1
        self.sim.add_target("targets", target.content, target.path)
        self.sim.update_snapshot()

        # Download the target
        updater = self._init_updater()
        info = updater.get_targetinfo(target.path)
        assert info is not None
        path = updater.download_target(info)
        self.assertEqual(path, updater.find_cached_target(info))

        # Add newer content to the same targetpath
        target.content = b"contentv2"
        self.sim.targets.version += 1
        self.sim.add_target("targets", target.content, target.path)
        self.sim.update_snapshot()

        # Newer content is detected, old cached version is not used
        updater = self._init_updater()
        info = updater.get_targetinfo(target.path)
        assert info is not None
        self.assertIsNone(updater.find_cached_target(info))

        # Download target, assert it is in cache and content is the newer
        path = updater.download_target(info)
        self.assertEqual(path, updater.find_cached_target(info))
        with open(path, "rb") as f:
            self.assertEqual(f.read(), target.content)

    def test_meta_missing_delegated_role(self) -> None:
        """Test a delegation where the role is not part of the snapshot"""

        # Add new delegation, update snapshot. Do not add the actual role
        role = DelegatedRole("role1", [], 1, True, ["*"])
        self.sim.targets.delegations = Delegations({}, roles={role.name: role})
        self.sim.update_snapshot()

        # assert that RepositoryError is raised when role1 is needed
        updater = self._init_updater()
        with self.assertRaises(RepositoryError):
            updater.get_targetinfo("")


if __name__ == "__main__":
    if "--dump" in sys.argv:
        TestFetchTarget.dump_dir = tempfile.mkdtemp()
        print(f"Repository Simulator dumps in {TestFetchTarget.dump_dir}")
        sys.argv.remove("--dump")

    utils.configure_test_logging(sys.argv)
    unittest.main()
