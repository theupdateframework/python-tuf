"""
<Program>
  test_download_server.py
 
<Author>
  Konstantin Andrianov

<Started>
  February 15, 2012
  
<Copyright>
  See LICENSE for licensing information.

<Purpose>
  This is a basic server that was designed to be used in conjunction with 
  test_download.py to test download.py module. 

"""

# Server serves files in the current directory.

import SimpleHTTPServer
import SocketServer

PORT = 8080

Handler = SimpleHTTPServer.SimpleHTTPRequestHandler
httpd = SocketServer.TCPServer(("", PORT), Handler)

print "serving at port", PORT
httpd.serve_forever(poll_interval=0.5)


# Instead you can run the following command:
# $python -m SimpleHTTPServer 8080
# http://docs.python.org/library/simplehttpserver.html#module-SimpleHTTPServer

