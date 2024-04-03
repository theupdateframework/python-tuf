# Copyright 2020, TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
<Program Name>
  test_utils.py

<Author>
  Martin Vrachev.

<Started>
  October 21, 2020.

<Copyright>
  See LICENSE-MIT OR LICENSE for licensing information.

<Purpose>
  Provide tests for some of the functions in utils.py module.
"""

import logging
import socket
import sys
import unittest

from tests import utils

logger = logging.getLogger(__name__)


def can_connect(port: int) -> bool:
    """Check if a socket can connect on the given port"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("localhost", port))
        return True
    except Exception:  # noqa: BLE001
        return False
    finally:
        # The process will always enter in finally even after return.
        if sock:
            sock.close()


class TestServerProcess(unittest.TestCase):
    """Test functionality provided in TestServerProcess from tests/utils.py."""

    def test_simple_server_startup(self) -> None:
        # Test normal case
        server_process_handler = utils.TestServerProcess(log=logger)

        # Make sure we can connect to the server
        self.assertTrue(can_connect(server_process_handler.port))
        server_process_handler.clean()

    def test_cleanup(self) -> None:
        # Test normal case
        server_process_handler = utils.TestServerProcess(
            log=logger, server="simple_server.py"
        )

        server_process_handler.clean()

        # Check if the process has successfully been killed.
        self.assertFalse(server_process_handler.is_process_running())

    def test_server_exit_before_timeout(self) -> None:
        with self.assertRaises(utils.TestServerProcessError):
            utils.TestServerProcess(logger, server="non_existing_server.py")

        # Test starting a server which immediately exits."
        with self.assertRaises(utils.TestServerProcessError):
            utils.TestServerProcess(logger, server="fast_server_exit.py")


if __name__ == "__main__":
    utils.configure_test_logging(sys.argv)
    unittest.main()
