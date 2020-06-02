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

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import sys
import random
import platform
import os
import re

import six
from six.moves.SimpleHTTPServer import SimpleHTTPRequestHandler

# We won't use the HTTPStatus codes from the http module
# for backward compability with python 2.7
FILE_NOT_FOUND = 404
PORT = 0

def _port_gen():
  return random.randint(30000, 45000)

if len(sys.argv) > 1:
  try:
    PORT = int(sys.argv[1])
    if PORT < 30000 or PORT > 45000:
      raise ValueError

  except ValueError:
    PORT = _port_gen()

else:
  PORT = _port_gen()


class QuietHTTPRequestHandler(SimpleHTTPRequestHandler):
  """A SimpleHTTPRequestHandler that does not write incoming requests to
  stderr. """

  # Override the log_request function
  def log_request(self, code='-', size='-'):
    pass

  # Override the log_error function
  def log_error(self, format, *args):

    file_not_found_name = os.path.basename(self.path)

    # There are errors in the format "code 404, message File not found"
    # when downloading \d*.root.json (match digits preffix before ".root.json":
    # 1.root.json, 10.root.json, etc.) files.
    # We don't want to show them because they are expected.
    if len(args) > 0 and args[0] == FILE_NOT_FOUND and \
        re.match("\d*.root.json", file_not_found_name):
      pass
    else:
      SimpleHTTPRequestHandler.log_error(self, format, *args)



# NOTE: On Windows/Python2 tests that use this simple_server.py in a
# subprocesses hang after a certain amount of requests (~68), if a PIPE is
# passed as Popen's stderr argument. This problem doesn't emerge if
# we silence the HTTP messages.
# If you decide to receive the HTTP messages, then this bug
# could reappear.
use_quiet_http_request_handler = True

if len(sys.argv) > 2:
  use_quiet_http_request_handler = sys.argv[2]

if use_quiet_http_request_handler:
  handler = QuietHTTPRequestHandler
else:
  handler = SimpleHTTPRequestHandler

httpd = six.moves.socketserver.TCPServer(('', PORT), handler)

httpd.serve_forever()
