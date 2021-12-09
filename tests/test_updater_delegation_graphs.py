#!/usr/bin/env python

# Copyright 2021, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Test updating delegated targets roles with various
delegation hierarchies"""

import os
import sys
import tempfile
import unittest
from dataclasses import astuple, dataclass, field
from typing import Iterable, List, Optional

from tests import utils
from tests.repository_simulator import RepositorySimulator
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
    paths: List[str] = field(default_factory=lambda: ["*"])
    path_hash_prefixes: Optional[List[str]] = None


@dataclass
class DelegationsTestCase:
    """Describes a delegations graph as a list of delegations
    and the expected order of traversal as 'visited_order'."""

    delegations: List[TestDelegation]
    visited_order: List[str]


class TestDelegationsGraphs(unittest.TestCase):
    """Test creating delegations graphs with different complexity
    and successfully updating the delegated roles metadata"""

    # set dump_dir to trigger repository state dumps
    dump_dir: Optional[str] = None

    def setUp(self) -> None:
        self.subtest_count = 0
        self.temp_dir = tempfile.TemporaryDirectory()
        self.metadata_dir = os.path.join(self.temp_dir.name, "metadata")
        self.targets_dir = os.path.join(self.temp_dir.name, "targets")
        os.mkdir(self.metadata_dir)
        os.mkdir(self.targets_dir)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def setup_subtest(
        self, delegations: List[TestDelegation]
    ) -> RepositorySimulator:
        sim = self._init_repo(delegations)

        self.subtest_count += 1
        if self.dump_dir is not None:
            # create subtest dumpdir
            name = f"{self.id().split('.')[-1]}-{self.subtest_count}"
            sim.dump_dir = os.path.join(self.dump_dir, name)
            os.mkdir(sim.dump_dir)
            # dump the repo simulator metadata
            sim.write()

        return sim

    def teardown_subtest(self) -> None:
        # clean up after each subtest
        utils.cleanup_dir(self.metadata_dir)

    def _init_updater(self, sim: RepositorySimulator) -> Updater:
        """Create a new Updater instance"""
        return Updater(
            self.metadata_dir,
            "https://example.com/metadata/",
            self.targets_dir,
            "https://example.com/targets/",
            sim,
        )

    def _init_repo(
        self, delegations: List[TestDelegation]
    ) -> RepositorySimulator:
        """Create a new RepositorySimulator instance with 'delegations'"""
        sim = RepositorySimulator()
        spec_version = ".".join(SPECIFICATION_VERSION)

        for d in delegations:
            if d.rolename in sim.md_delegates:
                targets = sim.md_delegates[d.rolename].signed
            else:
                targets = Targets(1, spec_version, sim.safe_expiry, {}, None)

            # unpack 'd' but skip "delegator"
            role = DelegatedRole(*astuple(d)[1:])
            sim.add_delegation(d.delegator, role, targets)
        sim.update_snapshot()

        # Init trusted root for Updater
        with open(os.path.join(self.metadata_dir, "root.json"), "bw") as f:
            f.write(sim.signed_roots[0])

        return sim

    def _assert_files_exist(self, roles: Iterable[str]) -> None:
        """Assert that local metadata files exist for 'roles'"""
        expected_files = sorted([f"{role}.json" for role in roles])
        local_metadata_files = sorted(os.listdir(self.metadata_dir))
        self.assertListEqual(local_metadata_files, expected_files)

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
    }

    @utils.run_sub_tests_with_dataset(graphs)
    def test_graph_traversal(self, test_data: DelegationsTestCase) -> None:
        """Test that delegated roles are traversed in the order of appearance
        in the delegator's metadata, using pre-order depth-first search"""

        try:
            exp_files = [*TOP_LEVEL_ROLE_NAMES, *test_data.visited_order]
            exp_calls = [(role, 1) for role in test_data.visited_order]

            sim = self.setup_subtest(test_data.delegations)
            updater = self._init_updater(sim)
            # Call explicitly refresh to simplify the expected_calls list
            updater.refresh()
            sim.fetch_tracker.metadata.clear()
            # Check that metadata dir contains only top-level roles
            self._assert_files_exist(TOP_LEVEL_ROLE_NAMES)

            # Looking for a non-existing targetpath forces updater
            # to visit all possible delegated roles
            targetfile = updater.get_targetinfo("missingpath")
            self.assertIsNone(targetfile)
            # Check that the delegated roles were visited in the expected
            # order and the corresponding metadata files were persisted
            self.assertListEqual(sim.fetch_tracker.metadata, exp_calls)
            self._assert_files_exist(exp_files)
        finally:
            self.teardown_subtest()


if __name__ == "__main__":
    if "--dump" in sys.argv:
        TestDelegationsGraphs.dump_dir = tempfile.mkdtemp()
        print(f"Repository Simulator dumps in {TestDelegationsGraphs.dump_dir}")
        sys.argv.remove("--dump")

    utils.configure_test_logging(sys.argv)
    unittest.main()
