#!/usr/bin/env python

# Copyright 2014 - 2017, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
<Program>
  simple_https_server.py

<Author>
  Vladimir Diaz.

<Started>
  June 17, 2014

<Copyright>
  See LICENSE-MIT OR LICENSE for licensing information.

<Purpose>
  Provide a simple https server that can be used by the unit tests.  For
  example, 'download.py' can connect to the https server started by this module
  to verify that https downloads are permitted.

<Reference>
  ssl.wrap_socket:
    https://docs.python.org/2/library/ssl.html#functions-constants-and-exceptions

  SimpleHTTPServer:
    http://docs.python.org/library/simplehttpserver.html#module-SimpleHTTPServer
"""

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import sys
import ssl
import os
import six

keyfile = os.path.join('ssl_certs', 'ssl_cert.key')
certfile = os.path.join('ssl_certs', 'ssl_cert.crt')


if len(sys.argv) > 1 and os.path.exists(sys.argv[1]):
    certfile = sys.argv[1]

httpd = six.moves.BaseHTTPServer.HTTPServer(('localhost', 0),
    six.moves.SimpleHTTPServer.SimpleHTTPRequestHandler)

httpd.socket = ssl.wrap_socket(
    httpd.socket, keyfile=keyfile, certfile=certfile, server_side=True)

port_message = 'bind succeeded, server port is: ' \
    + str(httpd.server_address[1])
print(port_message)

if len(sys.argv) > 1 and certfile != sys.argv[1]:
  print('simple_https_server: cert file was not found: ' + sys.argv[1] +
      '; using default: ' + certfile + " certfile")

httpd.serve_forever()
