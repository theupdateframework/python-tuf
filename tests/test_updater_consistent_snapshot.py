# Copyright 2021, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Test ngclient Updater toggling consistent snapshot"""

import os
import sys
import tempfile
import unittest
from typing import Any, Dict, Iterable, List, Optional

from tests import utils
from tests.repository_simulator import RepositorySimulator
from tuf.api.metadata import (
    SPECIFICATION_VERSION,
    TOP_LEVEL_ROLE_NAMES,
    DelegatedRole,
    TargetFile,
    Targets,
)
from tuf.ngclient import Updater


class TestConsistentSnapshot(unittest.TestCase):
    """Test different combinations of 'consistent_snapshot' and
    'prefix_targets_with_hash' and verify that the correct URLs
    are formed for each combination"""

    # set dump_dir to trigger repository state dumps
    dump_dir: Optional[str] = None

    def setUp(self) -> None:
        self.subtest_count = 0
        self.temp_dir = tempfile.TemporaryDirectory()
        self.metadata_dir = os.path.join(self.temp_dir.name, "metadata")
        self.targets_dir = os.path.join(self.temp_dir.name, "targets")
        os.mkdir(self.metadata_dir)
        os.mkdir(self.targets_dir)
        self.sim: RepositorySimulator

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def setup_subtest(
        self, consistent_snapshot: bool, prefix_targets: bool = True
    ) -> None:
        self.sim = self._init_repo(consistent_snapshot, prefix_targets)

        self.subtest_count += 1
        if self.dump_dir is not None:
            # create subtest dumpdir
            name = f"{self.id().split('.')[-1]}-{self.subtest_count}"
            self.sim.dump_dir = os.path.join(self.dump_dir, name)
            os.mkdir(self.sim.dump_dir)

    def teardown_subtest(self) -> None:
        if self.dump_dir is not None:
            self.sim.write()

        utils.cleanup_dir(self.metadata_dir)

    def _init_repo(
        self, consistent_snapshot: bool, prefix_targets: bool = True
    ) -> RepositorySimulator:
        """Create a new RepositorySimulator instance"""
        sim = RepositorySimulator()
        sim.root.consistent_snapshot = consistent_snapshot
        sim.root.version += 1
        sim.publish_root()
        sim.prefix_targets_with_hash = prefix_targets

        # Init trusted root with the latest consistent_snapshot
        with open(os.path.join(self.metadata_dir, "root.json"), "bw") as f:
            f.write(sim.signed_roots[-1])

        return sim

    def _init_updater(self) -> Updater:
        """Create a new Updater instance"""
        return Updater(
            self.metadata_dir,
            "https://example.com/metadata/",
            self.targets_dir,
            "https://example.com/targets/",
            self.sim,
        )

    def _assert_metadata_files_exist(self, roles: Iterable[str]) -> None:
        """Assert that local metadata files exist for 'roles'"""
        local_metadata_files = os.listdir(self.metadata_dir)
        for role in roles:
            self.assertIn(f"{role}.json", local_metadata_files)

    def _assert_targets_files_exist(self, filenames: Iterable[str]) -> None:
        """Assert that local files with 'filenames' exist"""
        local_target_files = os.listdir(self.targets_dir)
        for filename in filenames:
            self.assertIn(filename, local_target_files)

    top_level_roles_data: utils.DataSet = {
        "consistent_snaphot disabled": {
            "consistent_snapshot": False,
            "calls": [
                ("root", 3),
                ("timestamp", None),
                ("snapshot", None),
                ("targets", None),
            ],
        },
        "consistent_snaphot enabled": {
            "consistent_snapshot": True,
            "calls": [
                ("root", 3),
                ("timestamp", None),
                ("snapshot", 1),
                ("targets", 1),
            ],
        },
    }

    @utils.run_sub_tests_with_dataset(top_level_roles_data)
    def test_top_level_roles_update(
        self, test_case_data: Dict[str, Any]
    ) -> None:
        # Test if the client fetches and stores metadata files with the
        # correct version prefix, depending on 'consistent_snapshot' config
        try:
            consistent_snapshot: bool = test_case_data["consistent_snapshot"]
            exp_calls: List[Any] = test_case_data["calls"]

            self.setup_subtest(consistent_snapshot)
            updater = self._init_updater()

            # cleanup fetch tracker metadata
            self.sim.fetch_tracker.metadata.clear()
            updater.refresh()

            # metadata files are fetched with the expected version (or None)
            self.assertListEqual(self.sim.fetch_tracker.metadata, exp_calls)
            # metadata files are always persisted without a version prefix
            self._assert_metadata_files_exist(TOP_LEVEL_ROLE_NAMES)
        finally:
            self.teardown_subtest()

    delegated_roles_data: utils.DataSet = {
        "consistent_snaphot disabled": {
            "consistent_snapshot": False,
            "expected_version": None,
        },
        "consistent_snaphot enabled": {
            "consistent_snapshot": True,
            "expected_version": 1,
        },
    }

    @utils.run_sub_tests_with_dataset(delegated_roles_data)
    def test_delegated_roles_update(
        self, test_case_data: Dict[str, Any]
    ) -> None:
        # Test if the client fetches and stores delegated metadata files with
        # the correct version prefix, depending on 'consistent_snapshot' config
        try:
            consistent_snapshot: bool = test_case_data["consistent_snapshot"]
            exp_version: Optional[int] = test_case_data["expected_version"]
            rolenames = ["role1", "..", "."]
            exp_calls = [(role, exp_version) for role in rolenames]

            self.setup_subtest(consistent_snapshot)
            # Add new delegated targets
            spec_version = ".".join(SPECIFICATION_VERSION)
            for role in rolenames:
                delegated_role = DelegatedRole(role, [], 1, False, ["*"], None)
                targets = Targets(
                    1, spec_version, self.sim.safe_expiry, {}, None
                )
                self.sim.add_delegation("targets", delegated_role, targets)
            self.sim.update_snapshot()
            updater = self._init_updater()
            updater.refresh()

            # cleanup fetch tracker metadata
            self.sim.fetch_tracker.metadata.clear()
            # trigger updater to fetch the delegated metadata
            updater.get_targetinfo("anything")
            # metadata files are fetched with the expected version (or None)
            self.assertListEqual(self.sim.fetch_tracker.metadata, exp_calls)
            # metadata files are always persisted without a version prefix
            self._assert_metadata_files_exist(rolenames)
        finally:
            self.teardown_subtest()

    targets_download_data: utils.DataSet = {
        "consistent_snaphot disabled": {
            "consistent_snapshot": False,
            "prefix_targets": True,
            "hash_algo": None,
            "targetpaths": ["file", "file.txt", "..file.ext", "f.le"],
        },
        "consistent_snaphot enabled without prefixed targets": {
            "consistent_snapshot": True,
            "prefix_targets": False,
            "hash_algo": None,
            "targetpaths": ["file", "file.txt", "..file.ext", "f.le"],
        },
        "consistent_snaphot enabled with prefixed targets": {
            "consistent_snapshot": True,
            "prefix_targets": True,
            "hash_algo": "sha256",
            "targetpaths": ["file", "file.txt", "..file.ext", "f.le"],
        },
    }

    @utils.run_sub_tests_with_dataset(targets_download_data)
    def test_download_targets(self, test_case_data: Dict[str, Any]) -> None:
        # Test if the client fetches and stores target files with
        # the correct hash prefix, depending on 'consistent_snapshot'
        # and 'prefix_targets_with_hash' config
        try:
            consistent_snapshot: bool = test_case_data["consistent_snapshot"]
            prefix_targets_with_hash: bool = test_case_data["prefix_targets"]
            hash_algo: Optional[str] = test_case_data["hash_algo"]
            targetpaths: List[str] = test_case_data["targetpaths"]

            self.setup_subtest(consistent_snapshot, prefix_targets_with_hash)
            # Add targets to repository
            for targetpath in targetpaths:
                self.sim.targets.version += 1
                self.sim.add_target("targets", b"content", targetpath)
            self.sim.update_snapshot()

            updater = self._init_updater()
            updater.config.prefix_targets_with_hash = prefix_targets_with_hash
            updater.refresh()

            for path in targetpaths:
                info = updater.get_targetinfo(path)
                assert isinstance(info, TargetFile)
                updater.download_target(info)

                # target files are always persisted without hash prefix
                self._assert_targets_files_exist([info.path])

                # files are fetched with the expected hash prefix (or None)
                exp_calls = [
                    (path, None if not hash_algo else info.hashes[hash_algo])
                ]

                self.assertListEqual(self.sim.fetch_tracker.targets, exp_calls)
                self.sim.fetch_tracker.targets.clear()
        finally:
            self.teardown_subtest()


if __name__ == "__main__":
    if "--dump" in sys.argv:
        TestConsistentSnapshot.dump_dir = tempfile.mkdtemp()
        print(
            f"Repository Simulator dumps in {TestConsistentSnapshot.dump_dir}"
        )
        sys.argv.remove("--dump")

    utils.configure_test_logging(sys.argv)
    unittest.main()
