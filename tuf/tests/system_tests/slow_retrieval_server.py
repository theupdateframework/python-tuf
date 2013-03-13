import os
import time
import random
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer


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
        print i
        time.sleep(1)
        self.wfile.write(data[i])

      return

    except IOError, e:
      self.send_error(404, 'File Not Found!')



def get_random_port():
  port = random.randint(30000, 45000)
  return port



def run(port):
  server_address = ('localhost', port)
  print server_address
  httpd = HTTPServer(server_address, Handler)
  print('Server is active...')
  httpd.handle_request()
  


if __name__ == '__main__':
    port = get_random_port()
    print 'Port: '+str(port)
    run(port)
