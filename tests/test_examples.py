#!/usr/bin/env python
# Copyright 2020, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
""" Unit tests for 'examples' scripts.

"""
import glob
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import ClassVar, List


class TestRepoExamples(unittest.TestCase):
    """Unit test class for 'repo_example' scripts.

    Provides a '_run_example_script' method to run (exec) a script located in
    the 'repo_example' directory.

    """

    repo_examples_dir: ClassVar[Path]

    @classmethod
    def setUpClass(cls) -> None:
        """Locate and cache 'repo_example' dir."""
        base = Path(__file__).resolve().parents[1]
        cls.repo_examples_dir = base / "examples" / "repo_example"

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
        """Run script in 'repo_example' dir and assert that it created the
        files corresponding to the passed filenames inside a 'tmp*' test dir at
        CWD."""
        script_path = str(self.repo_examples_dir / script_name)
        with open(script_path, "rb") as f:
            # pylint: disable=exec-used
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


if __name__ == "__main__":
    unittest.main()
