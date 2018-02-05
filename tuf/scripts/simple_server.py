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
  See LICENSE-MIT OR LICENSE for licensing information.

<Purpose>
  This is a basic server that was designed to be used in conjunction with
  test_download.py to test download.py module.

<Reference>
  SimpleHTTPServer:
    https://docs.python.org/2/library/simplehttpserver.html
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

import six

PORT = 0

def _port_gen():
  return random.SystemRandom().randint(30000, 45000)

if len(sys.argv) > 1:
  try:
    PORT = int(sys.argv[1])

    # Enforce arbitrarily chosen port range.
    if PORT < 30000 or PORT > 45000:
      raise ValueError

  except ValueError:
    PORT = _port_gen()

else:
  PORT = _port_gen()


if __name__ == '__main__':

  Handler = six.moves.SimpleHTTPServer.SimpleHTTPRequestHandler
  httpd = six.moves.socketserver.TCPServer(('', PORT), Handler)

  httpd.serve_forever()
