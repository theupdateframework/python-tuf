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

  THIS module requires Python2.7 (not 2.8.x, not 3.x, just 2.7.x) as the test
  proxy it uses only supports Python2.7.

  So long as the tests succeed in Python 2.7, it is unlikely that TUF
  behaves differently with respect to proxies when it runs in other Python
  versions.

  As a result of this dependency, this test is only run by aggregate_tests.py
  when the Python version is 2.7.x.
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
import sys
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

logger = logging.getLogger(__name__)

class TestWithProxies(unittest_toolbox.Modified_TestCase):

  @classmethod
  def setUpClass(cls):
    """
    Setup performed before the first test function (TestWithProxies class
    method) runs.
    Launch HTTP, HTTPS, and proxy servers in the current working directory.
    We'll set up four servers:
     - HTTP server (simple_server.py)
     - HTTPS server (simple_https_server.py)
     - HTTP proxy server (proxy_server.py)
         (that supports HTTP CONNECT to funnel HTTPS connections)
     - HTTPS proxy server (proxy_server.py)
         (trusted by the client to intercept and resign connections)
    """

    unittest_toolbox.Modified_TestCase.setUpClass()

    # Launch a simple HTTP server (serves files in the current dir).
    cls.http_port = random.randint(30000, 45000)
    cls.http_server_proc = popen_python(
        ['simple_server.py', str(cls.http_port)])

    # Launch an HTTPS server (serves files in the current dir).
    cls.https_port = cls.http_port + 1
    cls.https_server_proc = popen_python(
        ['simple_https_server.py', str(cls.https_port)])


    # Launch an HTTP proxy server derived from inaz2/proxy2.
    # This one is able to handle HTTP CONNECT requests, and so can pass HTTPS
    # requests on to the target server.
    cls.http_proxy_port = cls.http_port + 2
    cls.http_proxy_proc = popen_python(
        ['proxy_server.py', str(cls.http_proxy_port)])
    # Note that the HTTP proxy server's address uses http://, regardless of the
    # type of connection used with the target server.
    cls.http_proxy_addr = 'http://127.0.0.1:' + str(cls.http_proxy_port)


    # Launch an HTTPS proxy server, also derived from inaz2/proxy2.
    # (An HTTPS proxy performs its own TLS connection with the client and must
    # be trusted by it, and is capable of tampering.)
    # We instruct the proxy server to expect certain certificates from the
    # target server.
    # 1st arg: port
    # 2nd arg: whether to intercept (HTTPS proxy) or relay (TCP tunnel using
    #   HTTP CONNECT verb, to facilitate an HTTPS connection between the client
    #   and server which the proxy cannot inspect)
    # 3rd arg: (optional) certificate file for telling the proxy what target
    #   server certs to accept in its HTTPS connection to the target server.
    #   This is only relevant if the proxy is in intercept mode.
    cls.https_proxy_port = cls.http_port + 3
    cls.https_proxy_proc = popen_python(
        ['proxy_server.py', str(cls.https_proxy_port), 'intercept',
        os.path.join('ssl_certs', 'ssl_cert.crt')])
    # Note that the HTTPS proxy server's address uses https://, regardless of
    # the type of connection used with the target server.
    cls.https_proxy_addr = 'https://127.0.0.1:' + str(cls.https_proxy_port)

    # Give the HTTP server and proxy server processes a little bit of time to
    # start listening before allowing tests to begin, lest we get "Connection
    # refused" errors. On the first test system. 0.1s was too short and 0.15s
    # was long enough. Use 0.5s to be safe, and if issues arise, increase it.
    # Observed occasional failures at 0.1s, 0.15s, 0.5s, and 2s, primarily on
    # AppVeyor.  Increasing to 4s.  This setup runs once for the module.
    time.sleep(4)





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
        cls.https_proxy_proc,
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

    logger.info('Trying HTTP download with no proxy: ' + self.url)
    download.safe_download(self.url, self.target_data_length)
    download.unsafe_download(self.url, self.target_data_length)





  def test_http_dl_via_smart_http_proxy(self):
    """
    Test a length-validating TUF download of a file through a proxy. Use an
    HTTP proxy normally, and make an HTTP connection with the final server.
    """

    self.set_env_value('HTTP_PROXY', self.http_proxy_addr)

    logger.info('Trying HTTP download via HTTP proxy: ' + self.url)
    download.safe_download(self.url, self.target_data_length)
    download.unsafe_download(self.url, self.target_data_length)





  def test_https_dl_via_smart_http_proxy(self):
    """
    Test a length-validating TUF download of a file through a proxy. Use an
    HTTP proxy that supports HTTP CONNECT (which essentially causes it to act
    as a TCP proxy), and perform an HTTPS connection through with the final
    server.

    Note that the proxy address is still http://... even though the connection
    with the target server is an HTTPS connection. The proxy itself will act as
    a TCP proxy via HTTP CONNECT.
    """
    self.set_env_value('HTTP_PROXY', self.http_proxy_addr) # http as intended
    self.set_env_value('HTTPS_PROXY', self.http_proxy_addr) # http as intended

    self.set_env_value('REQUESTS_CA_BUNDLE',
        os.path.join('ssl_certs', 'ssl_cert.crt'))
    # Clear sessions to ensure that the certificate we just specified is used.
    # TODO: Confirm necessity of this session clearing and lay out mechanics.
    tuf.download._sessions = {}

    logger.info('Trying HTTPS download via HTTP proxy: ' + self.url_https)
    download.safe_download(self.url_https, self.target_data_length)
    download.unsafe_download(self.url_https, self.target_data_length)





  def test_http_dl_via_https_proxy(self):
    """
    Test a length-validating TUF download of a file through a proxy. Use an
    HTTPS proxy, and perform an HTTP connection with the final server.
    """
    self.set_env_value('HTTP_PROXY', self.https_proxy_addr)
    self.set_env_value('HTTPS_PROXY', self.https_proxy_addr) # unnecessary

    # We're making an HTTPS connection with the proxy. The proxy will make a
    # plain HTTP connection to the target server.
    self.set_env_value('REQUESTS_CA_BUNDLE',
        os.path.join('ssl_certs', 'proxy_ca.crt'))
    # Clear sessions to ensure that the certificate we just specified is used.
    # TODO: Confirm necessity of this session clearing and lay out mechanics.
    tuf.download._sessions = {}

    logger.info('Trying HTTP download via HTTPS proxy: ' + self.url_https)
    download.safe_download(self.url, self.target_data_length)
    download.unsafe_download(self.url, self.target_data_length)





  def test_https_dl_via_https_proxy(self):
    """
    Test a length-validating TUF download of a file through a proxy. Use an
    HTTPS proxy, and perform an HTTPS connection with the final server.
    """
    self.set_env_value('HTTP_PROXY', self.https_proxy_addr) # unnecessary
    self.set_env_value('HTTPS_PROXY', self.https_proxy_addr)

    # We're making an HTTPS connection with the proxy. The proxy will make its
    # own HTTPS connection with the target server, and will have to know what
    # certificate to trust. It was told what certs to trust when it was
    # started in setUpClass().
    self.set_env_value('REQUESTS_CA_BUNDLE',
        os.path.join('ssl_certs', 'proxy_ca.crt'))
    # Clear sessions to ensure that the certificate we just specified is used.
    # TODO: Confirm necessity of this session clearing and lay out mechanics.
    tuf.download._sessions = {}

    logger.info('Trying HTTPS download via HTTPS proxy: ' + self.url_https)
    download.safe_download(self.url_https, self.target_data_length)
    download.unsafe_download(self.url_https, self.target_data_length)





  def set_env_value(self, key, value):
    """
    Set an environment variable after noting what the original value was, if it
    was set, and add it to the queue for restoring to its original value / lack
    of a value after the test finishes.

    Safe for multiple uses in one test: does not overwrite original saved value
    with new saved values.
    """

    # Only save the current value if we have not previously saved an older
    # value. The original one is the one we'll restore to, not whatever we
    # most recently overwrote.
    if key not in self.old_env_values:
      # If the value was previously unset in os.environ, save the old value
      # as None so that we know to unset it.
      self.old_env_values[key] = os.environ.get(key, None)

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
        'Please make sure to use set_env_value().'

    if self.old_env_values[key] is None:
      # If it was not previously set, try to unset it.
      # If the platform provides a way to unset environment variables,
      # del os.environ[key] should unset the variable. Otherwise, we'll just
      # have to settle for setting it to an empty string.
      # See os.environ in:
      #    https://docs.python.org/2/library/os.html#process-parameters
      os.environ[key] = ''
      del os.environ[key]

    else:
      # If it was previously set, restore the original value from when the
      # test was being set up.
      os.environ[key] = self.old_env_values[key]





  def restore_all_modified_env_values(self):
    for key in self.old_env_values:
      self.restore_env_value(key)





# TODO: Move this to a common test module (tests/common.py?)
#       and strip it test_proxy_use.py and test_download.py.
def popen_python(command_arg_list):
  """
  Run subprocess.Popen() to produce a process running a Python interpreter.
  Uses the same Python interpreter that the current process is using, via
  sys.executable.
  """
  assert sys.executable, 'Test cannot function: unable to determine ' \
      'current Python interpreter via sys.executable.'

  return subprocess.Popen(
      [sys.executable] + command_arg_list, stderr=subprocess.PIPE)



# Run unit test.
if __name__ == '__main__':
  unittest.main()
