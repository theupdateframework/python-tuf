# Copyright 2020, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Unit tests for 'examples' scripts."""

import glob
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from typing import ClassVar, List

from tests import utils


class TestRepoExamples(unittest.TestCase):
    """Unit test class for 'manual_repo' scripts.

    Provides a '_run_example_script' method to run (exec) a script located in
    the 'manual_repo' directory.

    """

    repo_examples_dir: ClassVar[Path]

    @classmethod
    def setUpClass(cls) -> None:
        """Locate the example dir."""
        base = Path(__file__).resolve().parents[1]
        cls.repo_examples_dir = base / "examples" / "manual_repo"

    def setUp(self) -> None:
        """Create and change into test dir.
        NOTE: Test scripts are expected to create dirs/files in new CWD."""
        self.original_cwd = os.getcwd()
        self.base_test_dir = os.path.realpath(tempfile.mkdtemp())
        os.chdir(self.base_test_dir)

    def tearDown(self) -> None:
        """Change back to original dir and remove test dir, which may contain
        dirs/files the test created at test-time CWD."""
        os.chdir(self.original_cwd)
        shutil.rmtree(self.base_test_dir)

    def _run_script_and_assert_files(
        self, script_name: str, filenames_created: List[str]
    ) -> None:
        """Run script in exmple dir and assert that it created the
        files corresponding to the passed filenames inside a 'tmp*' test dir at
        CWD."""
        script_path = str(self.repo_examples_dir / script_name)
        with open(script_path, "rb") as f:
            exec(
                compile(f.read(), script_path, "exec"),
                {"__file__": script_path},
            )

        test_dirs = glob.glob("tmp*")
        self.assertTrue(
            len(test_dirs) == 1, f"expected 1 'tmp*' test dir, got {test_dirs}"
        )

        test_dir = test_dirs.pop()
        for name in filenames_created:
            metadata_path = Path(test_dir) / f"{name}"
            self.assertTrue(
                metadata_path.exists(), f"missing '{metadata_path}' file"
            )

    def test_basic_repo(self) -> None:
        """Run 'basic_repo.py' and assert creation of metadata files."""
        self._run_script_and_assert_files(
            "basic_repo.py",
            [
                "1.python-scripts.json",
                "1.root.json",
                "1.snapshot.json",
                "1.targets.json",
                "2.root.json",
                "2.snapshot.json",
                "2.targets.json",
                "timestamp.json",
            ],
        )

    def test_hashed_bin_delegation(self) -> None:
        """Run 'hashed_bin_delegation.py' and assert creation of metadata files."""
        self._run_script_and_assert_files(
            "hashed_bin_delegation.py",
            [
                "1.bins.json",
                "1.00-07.json",
                "1.08-0f.json",
                "1.10-17.json",
                "1.18-1f.json",
                "1.20-27.json",
                "1.28-2f.json",
                "1.30-37.json",
                "1.38-3f.json",
                "1.40-47.json",
                "1.48-4f.json",
                "1.50-57.json",
                "1.58-5f.json",
                "1.60-67.json",
                "1.68-6f.json",
                "1.70-77.json",
                "1.78-7f.json",
                "1.80-87.json",
                "1.88-8f.json",
                "1.90-97.json",
                "1.98-9f.json",
                "1.a0-a7.json",
                "1.a8-af.json",
                "1.b0-b7.json",
                "1.b8-bf.json",
                "1.c0-c7.json",
                "1.c8-cf.json",
                "1.d0-d7.json",
                "1.d8-df.json",
                "1.e0-e7.json",
                "1.e8-ef.json",
                "1.f0-f7.json",
                "1.f8-ff.json",
            ],
        )

    def test_succinct_hash_bin_delegation(self) -> None:
        self._run_script_and_assert_files(
            "succinct_hash_bin_delegations.py",
            [
                "1.targets.json",
                "1.delegated_bin-00.json",
                "1.delegated_bin-01.json",
                "1.delegated_bin-02.json",
                "1.delegated_bin-03.json",
                "1.delegated_bin-04.json",
                "1.delegated_bin-05.json",
                "1.delegated_bin-06.json",
                "1.delegated_bin-07.json",
                "1.delegated_bin-08.json",
                "1.delegated_bin-09.json",
                "1.delegated_bin-0a.json",
                "1.delegated_bin-0b.json",
                "1.delegated_bin-0c.json",
                "1.delegated_bin-0d.json",
                "1.delegated_bin-0e.json",
                "1.delegated_bin-0f.json",
                "1.delegated_bin-10.json",
                "1.delegated_bin-11.json",
                "1.delegated_bin-12.json",
                "1.delegated_bin-13.json",
                "1.delegated_bin-14.json",
                "1.delegated_bin-15.json",
                "1.delegated_bin-16.json",
                "1.delegated_bin-17.json",
                "1.delegated_bin-18.json",
                "1.delegated_bin-19.json",
                "1.delegated_bin-1a.json",
                "1.delegated_bin-1b.json",
                "1.delegated_bin-1c.json",
                "1.delegated_bin-1d.json",
                "1.delegated_bin-1e.json",
                "1.delegated_bin-1f.json",
            ],
        )


if __name__ == "__main__":
    utils.configure_test_logging(sys.argv)
    unittest.main()
