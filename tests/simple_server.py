#!/usr/bin/env python

"""
<Program>
  simple_server.py
 
<Author>
  Konstantin Andrianov.

<Started>
  February 15, 2012.
  
<Copyright>
  See LICENSE for licensing information.

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

import six

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

Handler = six.moves.SimpleHTTPServer.SimpleHTTPRequestHandler
httpd = six.moves.socketserver.TCPServer(('', PORT), Handler)

httpd.serve_forever()
