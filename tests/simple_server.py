#!/usr/bin/env python

# Copyright 2012 - 2017, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Simple HTTP server for python-tuf tests"""

import socketserver
from http.server import SimpleHTTPRequestHandler

# Allow re-use so you can re-run tests as often as you want even if the
# tests re-use ports. Otherwise TCP TIME-WAIT prevents reuse for ~1 minute
socketserver.TCPServer.allow_reuse_address = True

httpd = socketserver.TCPServer(("localhost", 0), SimpleHTTPRequestHandler)
port_message = "bind succeeded, server port is: " + str(httpd.server_address[1])
print(port_message)
httpd.serve_forever()
