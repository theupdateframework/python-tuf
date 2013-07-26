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


DELAY = 1



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

      # Throttle the file by sending a character every few seconds.
      for i in range(len(data)):
        time.sleep(DELAY)
        self.wfile.write(data[i])

      return

    except IOError, e:
      self.send_error(404, 'File Not Found!')



def get_random_port():
  port = random.randint(30000, 45000)
  return port



def run(port):
  server_address = ('localhost', port)
  httpd = HTTPServer(server_address, Handler)
  print('Slow server is active on port: '+str(port)+' ...')
  httpd.handle_request()



if __name__ == '__main__':
  if len(sys.argv) > 1:
    port = int(sys.argv[1])
  else:
    port = get_random_port()

  run(port)