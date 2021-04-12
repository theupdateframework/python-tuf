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

import os
import sys
import time
import http.server



# HTTP request handler.
class Handler(http.server.BaseHTTPRequestHandler):

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

      # Before sending any data, the server does nothing for a long time.
      DELAY = 40
      time.sleep(DELAY)
      self.wfile.write((data.encode('utf-8')))

    except IOError as e:
      self.send_error(404, 'File Not Found!')



if __name__ == '__main__':
  server_address = ('localhost', 0)

  httpd = http.server.HTTPServer(server_address, Handler)
  port_message = 'bind succeeded, server port is: ' \
      + str(httpd.server_address[1])
  print(port_message)
  httpd.serve_forever()
