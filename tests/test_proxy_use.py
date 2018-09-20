#!/usr/bin/env python

# Copyright 2018, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
<Program>
  test_proxy_use.py

<Copyright>
  See LICENSE-MIT OR LICENSE for licensing information.

<Purpose>
  Integration/regression test of TUF downloads through proxies.

  NOTE: Make sure test_proxy_use.py is run in 'tuf/tests/' directory.
  Otherwise, test data or scripts may not be found.

  THIS module requires Python3.6+, as it uses mitmproxy, which only supports
  Python3.6+.

  So long as the tests succeed in Python 3.6+, it is unlikely that TUF
  behaves differently with respect to proxies when it runs in other Python
  versions.

  As a result of this dependency on a modern Python version, this test does
  not run with the other unit tests, being specifically excluded from
  aggregate_tests.py.
"""

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import hashlib
import logging
import os
import random
import subprocess
import time
import unittest

import tuf
import tuf.download as download
import tuf.log
import tuf.unittest_toolbox as unittest_toolbox
import tuf.exceptions

import requests.exceptions

import securesystemslib
import six

logger = logging.getLogger('tuf.test_download')

class TestWithProxies(unittest_toolbox.Modified_TestCase):

  @classmethod
  def setUpClass(cls):
    """
    Setup performed before the first test function (TestWithProxies class
    method) runs.
    Launch http, https, and proxy servers in the current working directory.
    """

    unittest_toolbox.Modified_TestCase.setUpClass()

    # Launch a simple HTTP server (serves files in the current dir).
    cls.http_port = random.randint(30000, 45000)
    cls.http_server_proc = subprocess.Popen(
        ['python', 'simple_server.py', str(cls.http_port)],
        stderr=subprocess.PIPE)
    # logger.info('\n\tHTTP server process started.')
    # logger.info('\tHTTP server process id: ' + str(cls.http_server_proc.pid))
    # logger.info('\tServing HTTP on port: ' + str(cls.http_port))

    # Launch an HTTPS server (serves files in the current dir).
    cls.https_port = cls.http_port + 1
    cls.https_server_proc = subprocess.Popen(
        ['python', 'simple_https_server.py', str(cls.https_port)],
        stderr=subprocess.PIPE)
    # logger.info('\n\tHTTPS server process started.')
    # logger.info('\tHTTPS server process id: ' + str(cls.https_server_proc.pid))
    # logger.info('\tServing HTTPS on port: ' + str(cls.https_port))

    # Launch a very basic HTTP proxy server. I think this one won't even handle
    # HTTP CONNECT (and so can't pass HTTPS requests on)
    cls.http_proxy_port = cls.http_port + 2
    cls.http_proxy_proc = subprocess.Popen(
        ['python', 'simple_proxy.py', 'http_dumb', str(cls.http_proxy_port)],
        stderr=subprocess.PIPE)
    # logger.info('\n\tProxy server process started.')
    # logger.info('\tHTTP Proxy process id: ' + str(cls.http_proxy_proc.pid))
    # logger.info('\tHTTP Proxy listening on port: ' + str(cls.http_proxy_proc))

    # Launch a less basic HTTP proxy server. This one should be able to handle
    # HTTP CONNECT requests, and so should be able to pass HTTPS requests on to
    # the target server.

    cls.http_proxy_port2 = cls.http_port + 4

    # Try proxy.py:
    #   Nope, proxy.py doesn't support HTTP CONNECT.
    # cls.http_proxy_proc2 = subprocess.Popen(
    #     ['proxy.py', '--port', str(cls.http_proxy_port2)],
    #     stderr=subprocess.PIPE)

    # Once a working proxy is chosen, it should probably be run this way instead:
    # cls.http_proxy_proc2 = subprocess.Popen(
    #     ['python', 'simple_proxy.py', 'http_smart', str(cls.http_proxy_port2)],
    #     stderr=subprocess.PIPE)

    # So, mitm_proxy doesn't support HTTP CONNECT, either, because it expects to
    # tinker with things and isn't interested in being blind to the data.
    # mitm_proxy can't be started this way; it expects a console.
    # NOTE: Start it manually outside of this tester for now, using:
    #   >>> mitmproxy --listen-host 127.0.0.1 --listen-port 8899
    # cls.http_proxy_proc2 = subprocess.Popen(
    #     ['mitmproxy', '--listen-host', '127.0.0.1',
    #     '--listen-port', str(cls.http_proxy_port2)],
    #     stderr=subprocess.PIPE)
    # logger.info('\n\tProxy server process started.')
    # logger.info('\tHTTP Proxy process id: ' + str(cls.http_proxy_proc2.pid))
    # logger.info('\tHTTP Proxy listening on port: ' + str(cls.http_proxy_proc2))

    # Let's try inaz2/proxy2....
    #   This seems to work, once modified to use IPv4.
    cls.http_proxy_proc2 = subprocess.Popen(
        ['python', 'proxy2.py', str(cls.http_proxy_port2)],
        stderr=subprocess.PIPE)



    # TODO: Launch a basic HTTPS proxy server.
    # # Launch a basic HTTPS proxy server.
    # cls.https_proxy_port = cls.http_port + 11
    # cls.https_proxy_proc = subprocess.Popen(
    #     ['python', 'simple_proxy.py', 'https', str(cls.https_proxy_port)],
    #     stderr=subprocess.PIPE)
    # logger.info('\n\tProxy server process started.')
    # logger.info('\tHTTPS Proxy process id: '+str(cls.http_proxy_proc.pid))
    # logger.info('\tHTTPS Proxy listening on port: '+str(cls.http_proxy_proc))


    # The first here is for an http proxy that cannot support HTTP CONNECT, and
    # so cannot pass on HTTPS connections.
    cls.http_proxy_addr = 'http://127.0.0.1:' + str(cls.http_proxy_port)

    # The second is for an http proxy that can support HTTP CONNECT, and so can
    # pass on HTTPS connections. Because it is an http proxy, the address will
    # begin with http:// whether the connection to the final target server is
    # HTTP or HTTPS.
    cls.http_proxy_addr2 = 'http://127.0.0.1:' + str(cls.http_proxy_port2)

    # # This is to the HTTPS proxy server.
    # cls.https_proxy_addr = 'https://localhost:' + str(cls.https_proxy_port)

    # Give the HTTP server and proxy server processes a little bit of time to
    # start listening before allowing tests to begin, lest we get "Connection
    # refused" errors.
    time.sleep(1.5)





  @classmethod
  def tearDownClass(cls):
    """
    Cleanup performed after the last of the tests (TestWithProxies methods)
    has been run.
    Stop server process and perform clean up.
    """
    unittest_toolbox.Modified_TestCase.tearDownClass()

    for proc in [
        cls.http_server_proc,
        cls.https_server_proc,
        cls.http_proxy_proc,
        cls.http_proxy_proc2,
        #cls.https_proxy_proc,
      ]:
      if proc.returncode is None:
        logger.info('\tTerminating process ' + str(proc.pid) + ' in cleanup.')
        proc.kill()



  def setUp(self):
    """
    Setup performed before EACH test function (TestWithProxies class method)
    runs.
    """
    unittest_toolbox.Modified_TestCase.setUp(self)

    # Dictionary for saving environment values to restore.
    self.old_env_values = {}

    # Make a temporary file to serve on the server, and determine its length,
    # and its url on the server.
    current_dir = os.getcwd()
    target_filepath = self.make_temp_data_file(directory=current_dir)
    rel_target_filepath = os.path.basename(target_filepath)

    with open(target_filepath, 'r') as target_file_object:
      self.target_data_length = len(target_file_object.read())

    self.url = \
        'http://localhost:' + str(self.http_port) + '/' + rel_target_filepath

    self.url_https = \
        'https://localhost:' + str(self.https_port) + '/' + rel_target_filepath





  def tearDown(self):
    """
    Cleanup performed after each test (each TestWithProxies method).
    Reset environment variables (for next test, etc.).
    """
    unittest_toolbox.Modified_TestCase.tearDown(self)

    self.restore_all_modified_env_values()





  def test_baseline_no_proxy(self):
    """
    Test a length-validating TUF download of a file through a proxy. Use an
    HTTP proxy, and perform an HTTP connection with the final server.
    """

    logger.info('Trying http download with no proxy: ' + self.url)
    download.safe_download(self.url, self.target_data_length)
    download.unsafe_download(self.url, self.target_data_length)





  def test_http_dl_via_dumb_http_proxy(self):
    """
    Test a length-validating TUF download of a file through a proxy. Use an
    HTTP proxy, and make an HTTP connection with the final server.
    """

    self.set_env_value('HTTP_PROXY', self.http_proxy_addr)

    logger.info('Trying http download via http proxy: ' + self.url)
    download.safe_download(self.url, self.target_data_length)
    download.unsafe_download(self.url, self.target_data_length)





  @unittest.expectedFailure
  def test_httpS_dl_via_dumb_http_proxy(self):
    """
    Test a length-validating TUF download of a file through a proxy. Use an
    HTTP proxy, and try to use HTTP CONNECT, even though this HTTP proxy does
    not happen to support HTTP CONNECT. (Consequently, this test fails.)

    Note that the proxy address is still http://... even though the connection
    with the target server is an HTTPS connection.
    """
    self.set_env_value('HTTPS_PROXY', self.http_proxy_addr) # http as intended

    logger.info('Trying httpS download via http proxy: ' + self.url_https)
    download.safe_download(self.url_https, self.target_data_length)
    download.unsafe_download(self.url_https, self.target_data_length)





  def test_http_dl_via_smart_http_proxy(self):
    """
    Test a length-validating TUF download of a file through a proxy. Use an
    HTTP proxy normally, and make an HTTP connection with the final server.
    """

    self.set_env_value('HTTP_PROXY', self.http_proxy_addr2)

    logger.info('Trying http download via http proxy: ' + self.url)
    download.safe_download(self.url, self.target_data_length)
    download.unsafe_download(self.url, self.target_data_length)





  def test_httpS_dl_via_smart_http_proxy(self):
    """
    Test a length-validating TUF download of a file through a proxy. Use an
    HTTP proxy that supports HTTP CONNECT (which essentially causes it to act
    as a TCP proxy), and perform an HTTPS connection through with the final
    server.

    Note that the proxy address is still http://... even though the connection
    with the target server is an HTTPS connection. The proxy itself will act as
    a TCP proxy via HTTP CONNECT.

    TEMPORARY NOTE: It turns out that mitmproxy doesn't support HTTP CONNECT,
    so I need a new proxy option for this....

    """
    self.set_env_value('HTTP_PROXY', self.http_proxy_addr2) # http as intended
    self.set_env_value('HTTPS_PROXY', self.http_proxy_addr2) # http as intended

    self.set_env_value('REQUESTS_CA_BUNDLE', 'ssl_cert.crt')

    logger.info('Trying httpS download via http proxy: ' + self.url_https)
    download.safe_download(self.url_https, self.target_data_length)
    download.unsafe_download(self.url_https, self.target_data_length)





  # def test_http_dl_via_httpS_proxy(self):
  #   """
  #   Test a length-validating TUF download of a file through a proxy. Use an
  #   HTTP proxy, and perform an HTTPS connection with the final server.

  #   Note that the proxy address is still http://... even though the connection
  #   with the target server is an HTTPS connection. The proxy itself is reached
  #   in an HTTP connection.
  #   """
  #   pass





  # def test_httpS_dl_via_httpS_proxy(self):
  #   pass





  # def test_transparent_https_proxy(self):
  #   pass






  def set_env_value(self, key, value):
    """
    Set an environment variable after noting what the original value was, if it
    was set, and add it to the queue for restoring to its original value / lack
    of a value after the test finishes.

    Safe for multiple uses in one test: does not overwrite original saved value
    with new saved values.
    """

    if key in self.old_env_values:
      # Do not save the current value. We already saved an older value, and
      # the original one is the one we'll restore to, not whatever we most
      # recently overwrote it with.
      pass

    elif key in os.environ:
      self.old_env_values[key] = os.environ[key]

    else:
      self.old_env_values[key] = None # Note that it was previously unset.

    # Actually set the new value.
    os.environ[key] = value





  def restore_env_value(self, key):
    # Save old values for environment variables for restoration after the test.
    # Save the pre-existing value of the environment variables HTTP_PROXY and
    # HTTPS_PROXY so that we can restore them in tearDown() after the test.
    # If the value was not originally set at all, we'll try to unset it again,
    # too.
    assert key in self.old_env_values, 'Test coding mistake: something is ' \
        'trying to restore environment variable ' + key + ', but that ' \
        'variable does not appear in the list of values to restore. ' \
        'Please make sure to use _set_env_value().'

    if self.old_env_values[key] is None:
      # If it was not previously set, try to unset it.
      # If the platform provides a way to unset environment variables,
      # del os.environ[key] should unset the variable. Otherwise, we'll just
      # have to settle for setting it to an empty string.
      # See os.environ in:
      #    https://docs.python.org/2/library/os.html#process-parameters)
      os.environ[key] = ''
      del os.environ[key]

    else:
      # If it was previously set, restore the original value from when the
      # test was being set up.
      os.environ[key] = self.old_env_values[key]





  def restore_all_modified_env_values(self):
    for key in self.old_env_values:
      self.restore_env_value(key)





# Run unit test.
if __name__ == '__main__':
  unittest.main()
