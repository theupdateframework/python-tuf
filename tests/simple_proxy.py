#!/usr/bin/env python

# Copyright 2018, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
<Program>
  simple_proxy.py

<Copyright>
  See LICENSE-MIT OR LICENSE for licensing information.

<Purpose>
  Provide a simple http proxy server that can be used by TUF tests.
  See test_proxy_use.py to see how it's used in the tests.

	Arguments are optional, but:
		If provided, the first argument is assumed to choose HTTP vs HTTPS proxy.
		If the first argument is 'https' (case insensitive), an HTTPS proxy will be
		run, else an HTTP proxy will be run.
		If provided, the second argument is assumed to indicate the port on which
		the proxy should run. It must be 1023<port<65536. If it is not provided or
		not in that range, a random port will be chosen.

	Example use:
		python simple_proxy.py https 8989


"""
# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import sys
import random

import twisted.web.proxy
import twisted.web.http
import twisted.internet
import twisted.python.log

def _generate_random_port():
  return random.randint(8090, 30000)





def main():
	port = 0
	proxy_type = 'http_dumb'

	if len(sys.argv) > 1:
		if sys.argv[1].lower() in ['https', 'http_smart', 'http_dumb']:
			proxy_type = sys.argv[1].lower()
		else:
			print('\n\nUNEXPECTED PROTOCOL FOR PROXY SERVER. Using ' + proxy_type +
				  ' instead.\n\n')

	if len(sys.argv) > 2:
	  try:
	  	port = int(sys.argv[2])
	  except:
	  	print('Ignoring argument. Second argument expected to be port, an int '
	  	  'i > 1023 and i < 65536. Generating randomly between 8090 and 30000.')
	  pass

	if port < 1024 or port > 65536:
	  port = _generate_random_port()

	if proxy_type == 'https':
		run_https_proxy(port)
	elif proxy_type == 'http_dumb':
		run_http_dumb_proxy(port)
	elif proxy_type == 'http_smart':
		run_http_smart_proxy(port)
	else:
		raise Exception('Unexpected proxy type requested....')





def run_http_dumb_proxy(port):
	"""
	This proxy doesn't know what to do with HTTP CONNECT requests, so it can't
	pass on HTTPS requests.
	"""

	twisted.python.log.startLogging(sys.stdout)

	class ProxyFactory(twisted.web.http.HTTPFactory):
	  protocol = twisted.web.proxy.Proxy

	twisted.internet.reactor.listenTCP(port, ProxyFactory())
	twisted.internet.reactor.run()





def run_http_smart_proxy(port):
	"""
	This proxy needs to support HTTP CONNECT requests so that it can create a
	TCP tunnel for HTTPS requests to the target server to go through.
	"""
	raise NotImplementedError()





def run_https_proxy(port):
	"""
	Run a proxy that connects using HTTPS (has its own validated certificate
	that the client accepts, etc.) before passing the request on to the target
	server.
	"""
	raise NotImplementedError()





if __name__ == '__main__':
	main()
