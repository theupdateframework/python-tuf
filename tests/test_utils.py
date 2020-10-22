#!/usr/bin/env python

# Copyright 2020, TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
<Program Name>
  test_utils.py

<Author>
  Martin Vrachev.

<Started>
  October 21, 2020.

<Copyright>
  See LICENSE-MIT OR LICENSE for licensing information.

<Purpose>
  Provide tests for some of the functions in utils.py module.
"""

import os
import logging
import unittest
import sys

import tuf.unittest_toolbox as unittest_toolbox

import utils

logger = logging.getLogger(__name__)

class TestServerProcess(unittest_toolbox.Modified_TestCase):

  def tearDown(self):
    # Make sure we are calling clean on existing attribute.
    if hasattr(self, 'server_process_handler'):
      self.server_process_handler.clean()


  def test_simple_server_startup(self):
    # Test normal case
    self.server_process_handler = utils.TestServerProcess(log=logger)

    utils.wait_for_server(host='localhost', server='simple_server.py',
        port=self.server_process_handler.port)


  def test_simple_https_server_startup(self):
    # Test normal case
    good_cert_fname = os.path.join('ssl_certs', 'ssl_cert.crt')
    self.server_process_handler = utils.TestServerProcess(log=logger,
        server='simple_https_server.py', extra_cmd_args=[good_cert_fname])

    utils.wait_for_server(host='localhost', server='simple_https_server.py',
        port=self.server_process_handler.port)


  @unittest.skipIf(sys.version_info.major != 2, "Test for Python 2.X")
  def test_proxy_server_startup(self):
    # Test normal case
    self.server_process_handler = utils.TestServerProcess(log=logger,
        server='proxy_server.py')

    utils.wait_for_server(host='localhost', server='proxy_server.py',
        port=self.server_process_handler.port)


  def test_slow_retrieval_server_startup(self):
    # Test normal case
    self.server_process_handler = utils.TestServerProcess(log=logger,
        server='slow_retrieval_server.py')

    utils.wait_for_server(host='localhost', server='slow_retrieval_server.py',
        port=self.server_process_handler.port)


  def test_cleanup(self):
    # Test normal case
    self.server_process_handler = utils.TestServerProcess(log=logger,
        server='simple_server.py')

    self.server_process_handler.clean()

    # Check if the process has successfully been killed.
    self.assertFalse(self.server_process_handler.is_process_running())


  def test_broken_startup(self):
    # Test broken cases

    # TimeoutError is defined in Python 3 but it's not in Python 2.
    timeout_error = None
    if sys.version_info.major == 2:
      timeout_error = utils.TimeoutError
    else:
      timeout_error = TimeoutError

    # Test where the server returns imediatly and doesn't
    # print "bind succeeded"
    self.assertRaises(timeout_error, utils.TestServerProcess, logger,
        extra_cmd_args=["stop"])

    # Test where the server stales forever and never print "bind succeeded"
    self.assertRaises(timeout_error, utils.TestServerProcess, logger,
        extra_cmd_args=["endless"])


if __name__ == '__main__':
  utils.configure_test_logging(sys.argv)
  unittest.main()
