# Copyright 2026, the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""End-to-end test that runs the repository, uploader and client examples.

Unlike test_examples.py (which execs the self-contained 'manual_repo'
scripts), this test wires the three interacting examples together the way
a user would run them from the command line:

* 'examples/repository/repo' is started as a live HTTP server,
* 'examples/uploader/uploader' performs Trust-On-First-Use, claims a
  delegation and uploads target files to that server,
* 'examples/client/client' performs Trust-On-First-Use and downloads the
  uploaded targets, which verifies them against the repository metadata.

The test also uploads a second target after the client has already been
initialized, then downloads it: this exercises the case from issue #2228
where a client with metadata version N must update to version N+M.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import ClassVar
from urllib.parse import quote

import urllib3

from tests import utils

# The repository example serves metadata under this URL prefix.
_METADATA_URL = "metadata"


def _get_free_port() -> int:
    """Return a currently-free localhost TCP port.

    The port is handed to the example repository server via '-p'. There is a
    small race between closing this socket and the server binding the port,
    but the readiness poll in setUp() tolerates it.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((utils.TEST_HOST_ADDRESS, 0))
        return int(sock.getsockname()[1])


class TestExamplesEnd2End(unittest.TestCase):
    """Run the repository, uploader and client examples against each other."""

    examples_dir: ClassVar[Path]

    @classmethod
    def setUpClass(cls) -> None:
        cls.examples_dir = Path(__file__).resolve().parents[1] / "examples"

    def setUp(self) -> None:
        # The examples import their private helper modules by name (e.g.
        # "from _simplerepo import SimpleRepository"), so each example dir
        # must be importable. The client and uploader also write trusted
        # metadata and keys under Path.home(): point HOME at a throwaway dir
        # so the test does not touch the real home directory and starts from
        # a clean slate every run.
        self.test_dir = tempfile.mkdtemp()
        self.addCleanup(self._rmtree, self.test_dir)

        self.env = os.environ.copy()
        self.env["HOME"] = self.test_dir
        self.env["PYTHONPATH"] = os.pathsep.join(
            str(self.examples_dir / name)
            for name in ("repository", "uploader", "client")
        )

        self.port = _get_free_port()
        self.base_url = f"http://{utils.TEST_HOST_ADDRESS}:{self.port}"

        # Start the repository example as a live server subprocess.
        repo_script = self.examples_dir / "repository" / "repo"
        self.server = subprocess.Popen(
            [sys.executable, "-u", str(repo_script), "-p", str(self.port)],
            env=self.env,
            cwd=self.test_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        self.addCleanup(self._stop_server)

        utils.wait_for_server(
            utils.TEST_HOST_ADDRESS, "repository example", self.port
        )
        # wait_for_server only confirms the port is open; also wait until the
        # repository has published its initial root metadata.
        self._wait_for_root()

    def _rmtree(self, path: str) -> None:
        # shutil.rmtree wrapper registered with addCleanup.
        shutil.rmtree(path, ignore_errors=True)

    def _stop_server(self) -> None:
        self.server.terminate()
        try:
            self.server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.server.kill()
            self.server.wait()
        if self.server.stdout is not None:
            self.server.stdout.close()

    def _wait_for_root(self, timeout: int = 10) -> None:
        """Poll until the server serves 1.root.json (or time out)."""
        deadline = time.monotonic() + timeout
        url = f"{self.base_url}/{_METADATA_URL}/1.root.json"
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            if self.server.poll() is not None:
                self.fail(
                    "repository example exited early with code "
                    f"{self.server.returncode}:\n{self._server_output()}"
                )
            try:
                response = urllib3.request("GET", url)
                if response.status == 200:
                    return
            except urllib3.exceptions.HTTPError as e:
                last_error = e
            time.sleep(0.05)
        self.fail(
            f"repository example never served root metadata: {last_error}"
        )

    def _server_output(self) -> str:
        if self.server.stdout is None:
            return ""
        return self.server.stdout.read().decode("utf-8", errors="replace")

    def _run_example(self, script: str, *args: str) -> None:
        """Run an example script as a subprocess and assert it succeeds."""
        script_path = self.examples_dir / script
        result = subprocess.run(
            [sys.executable, str(script_path), "-u", self.base_url, *args],
            env=self.env,
            cwd=self.test_dir,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        self.assertEqual(
            result.returncode,
            0,
            f"{script} {' '.join(args)} failed (rc={result.returncode}):\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}",
        )

    def _snapshot_version(self) -> int:
        """Return the version of the repository's current snapshot metadata."""
        url = f"{self.base_url}/{_METADATA_URL}/snapshot.json"
        response = urllib3.request("GET", url)
        self.assertEqual(response.status, 200)
        return int(json.loads(response.data)["signed"]["version"])

    def _downloaded_target(self, targetpath: str) -> bytes:
        """Read a target the client downloaded into its downloads dir.

        The client writes targets into a 'downloads' dir at its CWD, using the
        URL-quoted targetpath as filename (see Updater file path generation).
        """
        path = Path(self.test_dir) / "downloads" / quote(targetpath, "")
        self.assertTrue(path.exists(), f"missing downloaded target {path}")
        return path.read_bytes()

    def test_repository_uploader_client(self) -> None:
        """Upload targets via the uploader and download them via the client.

        Covers the end-to-end "examples" slice of issue #2228: a client can
        download a target and can update across metadata versions (N -> N+M).
        """
        uploader = "uploader/uploader"
        client = "client/client"
        role = "myrole"
        first_target = f"{role}/first"
        second_target = f"{role}/second"

        # Maintainer side: trust the repo, claim a delegation, add a target.
        self._run_example(uploader, "tofu")
        self._run_example(uploader, "add-delegation", role)
        self._run_example(uploader, "add-target", role, first_target)

        version_after_first = self._snapshot_version()

        # Client side: trust the repo and download the first target. The
        # Updater verifies the target against the (signed) repository metadata
        # before download_target() returns, so a successful download means the
        # metadata chain and the target hash both verified.
        self._run_example(client, "tofu")
        self._run_example(client, "download", first_target)

        # The example generates target content equal to the targetpath.
        self.assertEqual(
            self._downloaded_target(first_target),
            first_target.encode(),
        )

        # Maintainer adds a second target. This publishes new targets,
        # snapshot and timestamp metadata, so the repository advances past the
        # version the client currently trusts.
        self._run_example(uploader, "add-target", role, second_target)
        version_after_second = self._snapshot_version()
        self.assertGreater(version_after_second, version_after_first)

        # Client downloads the second target. download() refreshes metadata
        # first, so the already-initialized client must update from the
        # version it trusts (N) to the newer version (N+M) to find and verify
        # the new target.
        self._run_example(client, "download", second_target)
        self.assertEqual(
            self._downloaded_target(second_target),
            second_target.encode(),
        )


if __name__ == "__main__":
    utils.configure_test_logging(sys.argv)
    unittest.main()
