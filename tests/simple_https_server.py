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
import random
import ssl
import os
import six

PORT = 0

keyfile = os.path.join('ssl_certs', 'ssl_cert.key')
certfile = os.path.join('ssl_certs', 'ssl_cert.crt')

def _generate_random_port():
  return random.randint(30000, 45000)

if len(sys.argv) > 1:
  try:
    PORT = int(sys.argv[1])
    if PORT < 30000 or PORT > 45000:
      raise ValueError

  except ValueError:
    PORT = _generate_random_port()

else:
  PORT = _generate_random_port()

if len(sys.argv) > 2:

  if os.path.exists(sys.argv[2]):
    certfile = sys.argv[2]
  else:
    print('simple_https_server: cert file not found: ' + sys.argv[2] +
        '; using default: ' + certfile)

httpd = six.moves.BaseHTTPServer.HTTPServer(('localhost', PORT),
                            six.moves.SimpleHTTPServer.SimpleHTTPRequestHandler)

httpd.socket = ssl.wrap_socket(
    httpd.socket, keyfile=keyfile, certfile=certfile, server_side=True)

#print('Starting https server on port: ' + str(PORT))
httpd.serve_forever()
