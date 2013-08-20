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

      else:
        DELAY = 1
        send_bytes_per_time = len(data) / 10
        count = 0
        # Throttle the file by sending several characters every few seconds.
        while count <= len(data) / send_bytes_per_time:
          time.sleep(DELAY)
          self.wfile.write(data[count * send_bytes_per_time:(count + 1) * send_bytes_per_time])
          count += 1

        return
    except IOError, e:
      self.send_error(404, 'File Not Found!')



def get_random_port():
  port = random.randint(30000, 45000)
  return port



def run(port, test_mode):
  server_address = ('localhost', port)
  httpd = HTTPServer_Test(server_address, Handler, test_mode)
  print('Slow server is active on port: '+str(port)+' ...')
  httpd.handle_request()



if __name__ == '__main__':
  if len(sys.argv) > 2:
    port = int(sys.argv[1])
    test_mode = sys.argv[2]
  else:
    port = get_random_port()
    test_mode = None
  run(port, test_mode)