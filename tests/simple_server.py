#!/usr/bin/env python

# Copyright 2012 - 2017, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
<Program>
  simple_server.py

<Author>
  Konstantin Andrianov.

<Started>
  February 15, 2012.

<Copyright>
  See LICENSE-MIT or LICENSE for licensing information.

<Purpose>
  This is a basic server that was designed to be used in conjunction with
  test_download.py to test download.py module.

<Reference>
  SimpleHTTPServer:
    http://docs.python.org/library/simplehttpserver.html#module-SimpleHTTPServer
"""

import socketserver
import sys
from http.server import SimpleHTTPRequestHandler
from typing import Type, Union


class QuietHTTPRequestHandler(SimpleHTTPRequestHandler):
    """A SimpleHTTPRequestHandler that does not write incoming requests to
    stderr."""

    def log_request(
        self, code: Union[int, str] = "-", size: Union[int, str] = "-"
    ) -> None:
        pass


# NOTE: On Windows/Python2 tests that use this simple_server.py in a
# subprocesses hang after a certain amount of requests (~68), if a PIPE is
# passed as Popen's stderr argument. This problem doesn't emerge if
# we silence the HTTP messages.
# If you decide to receive the HTTP messages, then this bug
# could reappear.

# pylint: disable=invalid-name
handler: Type[Union[SimpleHTTPRequestHandler, QuietHTTPRequestHandler]]

if len(sys.argv) > 2 and sys.argv[2]:
    handler = QuietHTTPRequestHandler
else:
    handler = SimpleHTTPRequestHandler

# Allow re-use so you can re-run tests as often as you want even if the
# tests re-use ports. Otherwise TCP TIME-WAIT prevents reuse for ~1 minute
socketserver.TCPServer.allow_reuse_address = True

httpd = socketserver.TCPServer(("localhost", 0), handler)
port_message = "bind succeeded, server port is: " + str(httpd.server_address[1])
print(port_message)
httpd.serve_forever()
