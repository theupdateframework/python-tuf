#!/usr/bin/env python

# Copyright 2012 - 2017, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
<Program Name>
  slow_retrieval_server.py

<Author>
  Konstantin Andrianov.

<Started>
  March 13, 2012.

<Copyright>
  See LICENSE-MIT OR LICENSE for licensing information.

<Purpose>
  Server that throttles data by sending one byte at a time (specified time
  interval 'DELAY').  The server is used in 'test_slow_retrieval_attack.py'.
"""

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import os
import sys
import time
import random

import six


# Modify the HTTPServer class to pass the 'test_mode' argument to
# do_GET() function.
class HTTPServer_Test(six.moves.BaseHTTPServer.HTTPServer):
  def __init__(self, server_address, Handler, test_mode):
    six.moves.BaseHTTPServer.HTTPServer.__init__(self, server_address, Handler)
    self.test_mode = test_mode



# HTTP request handler.
class Handler(six.moves.BaseHTTPServer.BaseHTTPRequestHandler):

  # Overwrite do_GET.
  def do_GET(self):
    current_dir = os.getcwd()
    try:
      filepath = os.path.join(current_dir, self.path.lstrip('/'))
      data = None
      with open(filepath, 'r') as fileobj:
        data = fileobj.read()

      self.send_response(200)
      self.send_header('Content-length', str(len(data)))
      self.end_headers()

      if self.server.test_mode == 'mode_1':
        # Before sending any data, the server does nothing for a long time.
        DELAY = 40
        time.sleep(DELAY)
        self.wfile.write(data)

        return

      # 'mode_2'
      else:
        DELAY = 1
        # Throttle the file by sending a character every DELAY seconds.
        for i in range(len(data)):
          self.wfile.write(data[i].encode('utf-8'))
          time.sleep(DELAY)

        return

    except IOError as e:
      self.send_error(404, 'File Not Found!')



def get_random_port():
  port = random.randint(30000, 45000)
  return port



def run(port, test_mode):
  server_address = ('localhost', port)
  httpd = HTTPServer_Test(server_address, Handler, test_mode)
  httpd.handle_request()



if __name__ == '__main__':
  port = int(sys.argv[1])
  test_mode = sys.argv[2]
  assert test_mode in ('mode_1', 'mode_2')
  run(port, test_mode)
