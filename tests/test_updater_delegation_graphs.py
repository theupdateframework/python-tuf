# Copyright 2021, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Test updating delegated targets roles and searching for
target files with various delegation graphs"""

import os
import sys
import tempfile
import unittest
from dataclasses import astuple, dataclass, field
from typing import Iterable, List, Optional

from tests import utils
from tests.repository_simulator import RepositorySimulator
from tuf.api.exceptions import UnsignedMetadataError
from tuf.api.metadata import (
    SPECIFICATION_VERSION,
    TOP_LEVEL_ROLE_NAMES,
    DelegatedRole,
    Targets,
)
from tuf.ngclient import Updater


@dataclass
class TestDelegation:
    delegator: str
    rolename: str
    keyids: List[str] = field(default_factory=list)
    threshold: int = 1
    terminating: bool = False
    paths: Optional[List[str]] = field(default_factory=lambda: ["*"])
    path_hash_prefixes: Optional[List[str]] = None


@dataclass
class TestTarget:
    rolename: str
    content: bytes
    targetpath: str


@dataclass
class DelegationsTestCase:
    """A delegations graph as lists of delegations and target files
    and the expected order of traversal as a list of role names."""

    delegations: List[TestDelegation]
    target_files: List[TestTarget] = field(default_factory=list)
    visited_order: List[str] = field(default_factory=list)


@dataclass
class TargetTestCase:
    targetpath: str
    found: bool
    visited_order: List[str] = field(default_factory=list)


class TestDelegations(unittest.TestCase):
    """Base class for delegation tests"""

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

    def setup_subtest(self) -> None:
        self.subtest_count += 1
        if self.dump_dir is not None:
            # create subtest dumpdir
            name = f"{self.id().split('.')[-1]}-{self.subtest_count}"
            self.sim.dump_dir = os.path.join(self.dump_dir, name)
            os.mkdir(self.sim.dump_dir)
            # dump the repo simulator metadata
            self.sim.write()

    def teardown_subtest(self) -> None:
        utils.cleanup_dir(self.metadata_dir)

    def _init_repo(self, test_case: DelegationsTestCase) -> None:
        """Create a new RepositorySimulator instance and
        populate it with delegations and target files"""

        self.sim = RepositorySimulator()
        spec_version = ".".join(SPECIFICATION_VERSION)
        for d in test_case.delegations:
            if d.rolename in self.sim.md_delegates:
                targets = self.sim.md_delegates[d.rolename].signed
            else:
                targets = Targets(
                    1, spec_version, self.sim.safe_expiry, {}, None
                )
            # unpack 'd' but skip "delegator"
            role = DelegatedRole(*astuple(d)[1:])
            self.sim.add_delegation(d.delegator, role, targets)

        for target in test_case.target_files:
            self.sim.add_target(*astuple(target))

        if test_case.target_files:
            self.sim.targets.version += 1
        self.sim.update_snapshot()

    def _init_updater(self) -> Updater:
        """Create a new Updater instance"""
        # Init trusted root for Updater
        with open(os.path.join(self.metadata_dir, "root.json"), "bw") as f:
            f.write(self.sim.signed_roots[0])

        return Updater(
            self.metadata_dir,
            "https://example.com/metadata/",
            self.targets_dir,
            "https://example.com/targets/",
            self.sim,
        )

    def _assert_files_exist(self, roles: Iterable[str]) -> None:
        """Assert that local metadata files exist for 'roles'"""
        expected_files = sorted([f"{role}.json" for role in roles])
        local_metadata_files = sorted(os.listdir(self.metadata_dir))
        self.assertListEqual(local_metadata_files, expected_files)


class TestDelegationsGraphs(TestDelegations):
    """Test creating delegations graphs with different complexity
    and successfully updating the delegated roles metadata"""

    graphs: utils.DataSet = {
        "basic delegation": DelegationsTestCase(
            delegations=[TestDelegation("targets", "A")],
            visited_order=["A"],
        ),
        "single level delegations": DelegationsTestCase(
            delegations=[
                TestDelegation("targets", "A"),
                TestDelegation("targets", "B"),
            ],
            visited_order=["A", "B"],
        ),
        "two-level delegations": DelegationsTestCase(
            delegations=[
                TestDelegation("targets", "A"),
                TestDelegation("targets", "B"),
                TestDelegation("B", "C"),
            ],
            visited_order=["A", "B", "C"],
        ),
        "two-level test DFS order of traversal": DelegationsTestCase(
            delegations=[
                TestDelegation("targets", "A"),
                TestDelegation("targets", "B"),
                TestDelegation("A", "C"),
                TestDelegation("A", "D"),
            ],
            visited_order=["A", "C", "D", "B"],
        ),
        "three-level delegation test DFS order of traversal": DelegationsTestCase(
            delegations=[
                TestDelegation("targets", "A"),
                TestDelegation("targets", "B"),
                TestDelegation("A", "C"),
                TestDelegation("C", "D"),
            ],
            visited_order=["A", "C", "D", "B"],
        ),
        "two-level terminating ignores all but role's descendants": DelegationsTestCase(
            delegations=[
                TestDelegation("targets", "A"),
                TestDelegation("targets", "B"),
                TestDelegation("A", "C", terminating=True),
                TestDelegation("A", "D"),
            ],
            visited_order=["A", "C"],
        ),
        "three-level terminating ignores all but role's descendants": DelegationsTestCase(
            delegations=[
                TestDelegation("targets", "A"),
                TestDelegation("targets", "B"),
                TestDelegation("A", "C", terminating=True),
                TestDelegation("C", "D"),
            ],
            visited_order=["A", "C", "D"],
        ),
        "two-level ignores all branches not matching 'paths'": DelegationsTestCase(
            delegations=[
                TestDelegation("targets", "A", paths=["*.py"]),
                TestDelegation("targets", "B"),
                TestDelegation("A", "C"),
            ],
            visited_order=["B"],
        ),
        "three-level ignores all branches not matching 'paths'": DelegationsTestCase(
            delegations=[
                TestDelegation("targets", "A"),
                TestDelegation("targets", "B"),
                TestDelegation("A", "C", paths=["*.py"]),
                TestDelegation("C", "D"),
            ],
            visited_order=["A", "B"],
        ),
        "cyclic graph": DelegationsTestCase(
            delegations=[
                TestDelegation("targets", "A"),
                TestDelegation("targets", "B"),
                TestDelegation("B", "C"),
                TestDelegation("C", "D"),
                TestDelegation("D", "B"),
            ],
            visited_order=["A", "B", "C", "D"],
        ),
        "two roles delegating to a third": DelegationsTestCase(
            delegations=[
                TestDelegation("targets", "A"),
                TestDelegation("targets", "B"),
                TestDelegation("B", "C"),
                TestDelegation("A", "C"),
            ],
            # Under all same conditions, 'C' is reached through 'A' first"
            visited_order=["A", "C", "B"],
        ),
        "two roles delegating to a third different 'paths'": DelegationsTestCase(
            delegations=[
                TestDelegation("targets", "A"),
                TestDelegation("targets", "B"),
                TestDelegation("B", "C"),
                TestDelegation("A", "C", paths=["*.py"]),
            ],
            # 'C' is reached through 'B' since 'A' does not delegate a matching pattern"
            visited_order=["A", "B", "C"],
        ),
        "max number of delegations": DelegationsTestCase(
            delegations=[
                TestDelegation("targets", "A"),
                TestDelegation("targets", "B"),
                TestDelegation("targets", "C"),
                TestDelegation("C", "D"),
                TestDelegation("C", "E"),
            ],
            # "E" is skipped, max_delegations is 4
            visited_order=["A", "B", "C", "D"],
        ),
    }

    @utils.run_sub_tests_with_dataset(graphs)
    def test_graph_traversal(self, test_data: DelegationsTestCase) -> None:
        """Test that delegated roles are traversed in the order of appearance
        in the delegator's metadata, using pre-order depth-first search"""

        try:
            exp_files = [*TOP_LEVEL_ROLE_NAMES, *test_data.visited_order]
            exp_calls = [(role, 1) for role in test_data.visited_order]

            self._init_repo(test_data)
            self.setup_subtest()

            updater = self._init_updater()
            # restrict the max number of delegations to simplify the test
            updater.config.max_delegations = 4
            # Call explicitly refresh to simplify the expected_calls list
            updater.refresh()
            self.sim.fetch_tracker.metadata.clear()
            # Check that metadata dir contains only top-level roles
            self._assert_files_exist(TOP_LEVEL_ROLE_NAMES)

            # Looking for a non-existing targetpath forces updater
            # to visit all possible delegated roles
            targetfile = updater.get_targetinfo("missingpath")
            self.assertIsNone(targetfile)
            # Check that the delegated roles were visited in the expected
            # order and the corresponding metadata files were persisted
            self.assertListEqual(self.sim.fetch_tracker.metadata, exp_calls)
            self._assert_files_exist(exp_files)
        finally:
            self.teardown_subtest()

    invalid_metadata: utils.DataSet = {
        "unsigned delegated role": DelegationsTestCase(
            delegations=[
                TestDelegation("targets", "invalid"),
                TestDelegation("targets", "B"),
                TestDelegation("invalid", "C"),
            ],
            # The traversal stops after visiting an invalid role
            visited_order=["invalid"],
        )
    }

    @utils.run_sub_tests_with_dataset(invalid_metadata)
    def test_invalid_metadata(self, test_data: DelegationsTestCase) -> None:
        try:
            self._init_repo(test_data)
            # The invalid role is the last visited
            invalid_role = test_data.visited_order[-1]
            self.sim.signers[invalid_role].clear()

            self.setup_subtest()
            # The invalid role metadata must not be persisted
            exp_files = [*TOP_LEVEL_ROLE_NAMES, *test_data.visited_order[:-1]]
            exp_calls = [(role, 1) for role in test_data.visited_order]

            updater = self._init_updater()
            # Call explicitly refresh to simplify the expected_calls list
            updater.refresh()
            self.sim.fetch_tracker.metadata.clear()

            with self.assertRaises(UnsignedMetadataError):
                updater.get_targetinfo("missingpath")
            # Check that there were no visited roles after the invalid one
            # and only the valid metadata files were persisted
            self.assertListEqual(self.sim.fetch_tracker.metadata, exp_calls)
            self._assert_files_exist(exp_files)
        finally:
            self.teardown_subtest()

    def test_safely_encoded_rolenames(self) -> None:
        """Test that delegated roles names are safely encoded in the filenames
        and URLs.
        """

        roles_to_filenames = {
            "../a": "..%2Fa.json",
            ".": "..json",
            "/": "%2F.json",
            "ö": "%C3%B6.json",
        }

        delegations = []
        for rolename in roles_to_filenames:
            delegations.append(TestDelegation("targets", rolename))

        delegated_rolenames = DelegationsTestCase(delegations)
        self._init_repo(delegated_rolenames)
        updater = self._init_updater()
        updater.refresh()

        # trigger updater to fetch the delegated metadata
        self.sim.fetch_tracker.metadata.clear()
        updater.get_targetinfo("anything")

        # assert that local delegated metadata filenames are expected
        local_metadata = os.listdir(self.metadata_dir)
        for fname in roles_to_filenames.values():
            self.assertTrue(fname in local_metadata)

        # assert that requested URLs are quoted without extension
        exp_calls = [(quoted[:-5], 1) for quoted in roles_to_filenames.values()]
        self.assertListEqual(self.sim.fetch_tracker.metadata, exp_calls)

    hash_bins_graph: utils.DataSet = {
        "delegations": DelegationsTestCase(
            delegations=[
                TestDelegation(
                    "targets",
                    "role1",
                    paths=None,
                    path_hash_prefixes=["8", "9", "a", "b"],
                ),
                TestDelegation(
                    "targets",
                    "role2",
                    paths=None,
                    path_hash_prefixes=["0", "1", "2", "3"],
                ),
                TestDelegation(
                    "targets",
                    "role3",
                    paths=None,
                    path_hash_prefixes=["c", "d", "e", "f"],
                ),
            ],
            visited_order=["role1", "role2", "role3"],
        ),
    }

    @utils.run_sub_tests_with_dataset(hash_bins_graph)
    def test_hash_bins_graph_traversal(
        self, test_data: DelegationsTestCase
    ) -> None:
        """Test that delegated roles are traversed in the order of appearance
        in the delegator's metadata, using pre-order depth-first search and that
        they correctly reffer to the corresponding hash bin prefixes"""

        try:
            exp_files = [*TOP_LEVEL_ROLE_NAMES, *test_data.visited_order]
            exp_calls = [(role, 1) for role in test_data.visited_order]

            self._init_repo(test_data)
            self.setup_subtest()

            updater = self._init_updater()
            # Call explicitly refresh to simplify the expected_calls list
            updater.refresh()
            self.sim.fetch_tracker.metadata.clear()
            # Check that metadata dir contains only top-level roles
            self._assert_files_exist(TOP_LEVEL_ROLE_NAMES)

            # Looking for a non-existing targetpath forces updater
            # to visit a correspondning delegated role
            targetfile = updater.get_targetinfo("missingpath")
            self.assertIsNone(targetfile)
            targetfile = updater.get_targetinfo("othermissingpath")
            self.assertIsNone(targetfile)
            targetfile = updater.get_targetinfo("thirdmissingpath")
            self.assertIsNone(targetfile)
            # Check that the delegated roles were visited in the expected
            # order and the corresponding metadata files were persisted
            self.assertListEqual(self.sim.fetch_tracker.metadata, exp_calls)
            self._assert_files_exist(exp_files)
        finally:
            self.teardown_subtest()

    @dataclass
    class SuccinctRolesTestCase:
        bit_length: int
        target_path: str
        expected_target_bin: str

    # By setting the bit_length the total number of bins is 2^bit_length.
    # In each test case target_path is a path to a random target we want to
    # fetch and expected_target_bin is the bin we are expecting to visit.
    succinct_bins_graph: utils.DataSet = {
        "bin amount = 2, taget bin index 0": SuccinctRolesTestCase(
            bit_length=1,
            target_path="boo",
            expected_target_bin="bin-0",
        ),
        "bin amount = 2, taget bin index 1": SuccinctRolesTestCase(
            bit_length=1,
            target_path="too",
            expected_target_bin="bin-1",
        ),
        "bin amount = 4, taget bin index 0": SuccinctRolesTestCase(
            bit_length=2,
            target_path="foo",
            expected_target_bin="bin-0",
        ),
        "bin amount = 4, taget bin index 1": SuccinctRolesTestCase(
            bit_length=2,
            target_path="doo",
            expected_target_bin="bin-1",
        ),
        "bin amount = 4, taget bin index 2": SuccinctRolesTestCase(
            bit_length=2,
            target_path="too",
            expected_target_bin="bin-2",
        ),
        "bin amount = 4, taget bin index 3": SuccinctRolesTestCase(
            bit_length=2,
            target_path="bar",
            expected_target_bin="bin-3",
        ),
        "bin amount = 256, taget bin index fc": SuccinctRolesTestCase(
            bit_length=8,
            target_path="bar",
            expected_target_bin="bin-fc",
        ),
    }

    @utils.run_sub_tests_with_dataset(succinct_bins_graph)
    def test_succinct_roles_graph_traversal(
        self, test_data: SuccinctRolesTestCase
    ) -> None:
        # Test traversing the delegation tree when succinct roles is used. For a
        # successful traversal all top level metadata files plus the expected
        # bin should exist locally and only one bin must be downloaded.

        try:
            exp_files = [*TOP_LEVEL_ROLE_NAMES, test_data.expected_target_bin]
            exp_calls = [(test_data.expected_target_bin, 1)]

            self.sim = RepositorySimulator()
            self.sim.add_succinct_roles("targets", test_data.bit_length, "bin")
            self.sim.update_snapshot()

            self.setup_subtest()

            updater = self._init_updater()
            # Call explicitly refresh to simplify the expected_calls list.
            updater.refresh()
            self.sim.fetch_tracker.metadata.clear()
            # Check that metadata dir contains only top-level roles
            self._assert_files_exist(TOP_LEVEL_ROLE_NAMES)

            # Looking for a non-existing targetpath forces updater
            # to visit a corresponding delegated role.
            targetfile = updater.get_targetinfo(test_data.target_path)
            self.assertIsNone(targetfile)

            # Check that the delegated roles were visited in the expected
            # order and the corresponding metadata files were persisted.
            self.assertListEqual(self.sim.fetch_tracker.metadata, exp_calls)
            self._assert_files_exist(exp_files)

        finally:
            self.teardown_subtest()


class TestTargetFileSearch(TestDelegations):
    r"""
    Create a single repository with the following delegations:

              targets
    *.doc, *md / \ release/*/*
              A   B
     release/x/* / \ release/y/*.zip
                C   D

    Test that Updater successfully finds the target files metadata,
    traversing the delegations as expected.
    """

    delegations_tree = DelegationsTestCase(
        delegations=[
            TestDelegation("targets", "A", paths=["*.doc", "*.md"]),
            TestDelegation("targets", "B", paths=["releases/*/*"]),
            TestDelegation("B", "C", paths=["releases/x/*"]),
            TestDelegation("B", "D", paths=["releases/y/*.zip"]),
        ],
        target_files=[
            TestTarget("targets", b"targetfile content", "targetfile"),
            TestTarget("A", b"README by A", "README.md"),
            TestTarget("C", b"x release by C", "releases/x/x_v1"),
            TestTarget("D", b"y release by D", "releases/y/y_v1.zip"),
            TestTarget("D", b"z release by D", "releases/z/z_v1.zip"),
        ],
    )

    def setUp(self) -> None:
        super().setUp()
        self._init_repo(self.delegations_tree)

    # fmt: off
    targets: utils.DataSet = {
        "no delegations":
            TargetTestCase("targetfile", True, []),
        "targetpath matches wildcard":
            TargetTestCase("README.md", True, ["A"]),
        "targetpath with separators x":
            TargetTestCase("releases/x/x_v1", True, ["B", "C"]),
        "targetpath with separators y":
            TargetTestCase("releases/y/y_v1.zip", True, ["B", "D"]),
        "targetpath is not delegated by all roles in the chain":
            TargetTestCase("releases/z/z_v1.zip", False, ["B"]),
    }
    # fmt: on

    @utils.run_sub_tests_with_dataset(targets)
    def test_targetfile_search(self, test_data: TargetTestCase) -> None:
        try:
            self.setup_subtest()
            exp_files = [*TOP_LEVEL_ROLE_NAMES, *test_data.visited_order]
            exp_calls = [(role, 1) for role in test_data.visited_order]
            exp_target = self.sim.target_files[test_data.targetpath].target_file

            updater = self._init_updater()
            # Call explicitly refresh to simplify the expected_calls list
            updater.refresh()
            self.sim.fetch_tracker.metadata.clear()
            target = updater.get_targetinfo(test_data.targetpath)
            if target is not None:
                # Confirm that the expected TargetFile is found
                self.assertTrue(test_data.found)
                self.assertDictEqual(target.to_dict(), exp_target.to_dict())
            else:
                self.assertFalse(test_data.found)
            # Check that the delegated roles were visited in the expected
            # order and the corresponding metadata files were persisted
            self.assertListEqual(self.sim.fetch_tracker.metadata, exp_calls)
            self._assert_files_exist(exp_files)
        finally:
            self.teardown_subtest()


if __name__ == "__main__":
    if "--dump" in sys.argv:
        TestDelegations.dump_dir = tempfile.mkdtemp()
        print(f"Repository Simulator dumps in {TestDelegations.dump_dir}")
        sys.argv.remove("--dump")

    utils.configure_test_logging(sys.argv)
    unittest.main()
