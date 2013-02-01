import sys
import random
import SimpleHTTPServer
import SocketServer

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

Handler = SimpleHTTPServer.SimpleHTTPRequestHandler
httpd = SocketServer.TCPServer(("", PORT), Handler)

print "serving at port", PORT
httpd.serve_forever()


"""
class PortGen(object):
  def __init__(self, port=None):
    if port is None:
      self.port = random.randint(30000, 40000)

PORT = PortGen()

Handler = SimpleHTTPServer.SimpleHTTPRequestHandler
httpd = SocketServer.TCPServer(("", PORT.port), Handler)

print "serving at port", PORT.port
httpd.serve_forever()
"""
