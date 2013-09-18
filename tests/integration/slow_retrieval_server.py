#!/usr/bin/env python

"""
<Program Name>
  slow_retrieval_server.py

<Author>
  Konstantin Andrianov

<Started>
  March 13, 2012

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Server that throttles data by sending one byte at a time 
  (specified time interval 'DELAY').  The server is used in
  test_slow_retrieval_attack.py.

"""

import os
import sys
import time
import random
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer





# Modify the HTTPServer class to pass the test_mode argument to do_GET function.
class HTTPServer_Test(HTTPServer):
  def __init__(self, server_address, Handler, test_mode):
    HTTPServer.__init__(self, server_address, Handler)
    self.test_mode = test_mode





# HTTP request handler.
class Handler(BaseHTTPRequestHandler):

  # Overwrite do_GET.
  def do_GET(self):
    current_dir = os.getcwd()
    try:
      filepath = os.path.join(current_dir, self.path.lstrip('/'))
      fileobj = open(filepath, 'rb')
      data = fileobj.read()
      fileobj.close()
      self.send_response(200)
      self.send_header('Content-length', str(len(data)))
      self.end_headers()
      
      if self.server.test_mode == "mode_1":
      # before sends any data, the server does nothing during a long time.
        DELAY = 1000
        time.sleep(DELAY)
        self.wfile.write(data)

        return

      else: # "mode_2"
        DELAY = 1
        # Throttle the file by sending a character every few seconds.
        for i in range(len(data)):
          self.wfile.write(data[i])
          time.sleep(DELAY)
        return

    except IOError, e:
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
  assert test_mode in ("mode_1", "mode_2")
  run(port, test_mode)
