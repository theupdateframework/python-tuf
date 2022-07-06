#!/usr/bin/env python

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

import io
import json
import logging
import socket
import sys
import unittest
from unittest import mock

from tests import utils

logger = logging.getLogger(__name__)


def can_connect(port: int) -> bool:
    """Check if a socket can connect on the given port"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("localhost", port))
        return True
    # pylint: disable=broad-except
    except Exception:
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


class CustomHTTPRequestHandlerTests(unittest.TestCase):
    def setUp(self) -> None:
        # Based on cpython tests SocketlessRequestHandler:
        # https://github.com/python/cpython/blob/main/Lib/test/test_httpservers.py#L921
        request = mock.Mock()
        request.makefile.return_value = io.BytesIO()
        self.handler = utils.CustomHTTPRequestHandler(
            request, None, None, directory=None
        )
        self.handler.get_called = False
        self.handler.protocol_version = "HTTP/1.1"
        self.handler.client_address = ('localhost', 0)

    def send_request(self, message):
        # Based on cpython tests BaseHTTPRequestHandlerTestCase:
        # https://github.com/python/cpython/blob/main/Lib/test/test_httpservers.py#L973
        self.handler.rfile = io.BytesIO(message)
        self.handler.wfile = io.BytesIO()
        self.handler.handle_one_request()
        self.handler.wfile.seek(0)
        return self.handler.wfile.readlines()

    def test_custom_response_headers(self):
        header_name = 'Some-Header'
        header_value = 'some value'
        req_header = utils.REQUEST_RESPONSE_HEADERS
        resp_headers = json.dumps({header_name: header_value})
        raw_header = f'{req_header}: {resp_headers}\r\n'.encode('utf-8')
        raw_request = b'GET / HTTP/1.1\r\n'
        raw_request += raw_header
        raw_request += b'\r\n'
        raw_response = b''.join(self.send_request(message=raw_request))
        print(raw_response)
        self.assertIn(header_name.encode('utf-8'), raw_response)
        self.assertIn(header_value.encode('utf-8'), raw_response)


if __name__ == "__main__":
    utils.configure_test_logging(sys.argv)
    unittest.main()
