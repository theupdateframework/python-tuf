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
import socket
import sys

import tuf.unittest_toolbox as unittest_toolbox

from tests import utils

logger = logging.getLogger(__name__)

class TestServerProcess(unittest_toolbox.Modified_TestCase):

  def tearDown(self):
    # Make sure we are calling clean on existing attribute.
    if hasattr(self, 'server_process_handler'):
      self.server_process_handler.clean()


  def can_connect(self):
    try:
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.connect(('localhost', self.server_process_handler.port))
      return True
    except:
      return False
    finally:
      # The process will always enter in finally even we return.
      if sock:
        sock.close()


  def test_simple_server_startup(self):
    # Test normal case
    self.server_process_handler = utils.TestServerProcess(log=logger)

    # Make sure we can connect to the server
    self.assertTrue(self.can_connect())


  def test_simple_https_server_startup(self):
    # Test normal case
    good_cert_path = os.path.join('ssl_certs', 'ssl_cert.crt')
    self.server_process_handler = utils.TestServerProcess(log=logger,
        server='simple_https_server.py', extra_cmd_args=[good_cert_path])

    # Make sure we can connect to the server
    self.assertTrue(self.can_connect())
    self.server_process_handler.clean()

    # Test when no cert file is provided
    self.server_process_handler = utils.TestServerProcess(log=logger,
        server='simple_https_server.py')

    # Make sure we can connect to the server
    self.assertTrue(self.can_connect())
    self.server_process_handler.clean()

    # Test with a non existing cert file.
    non_existing_cert_path = os.path.join('ssl_certs', 'non_existing.crt')
    self.server_process_handler = utils.TestServerProcess(log=logger,
        server='simple_https_server.py',
        extra_cmd_args=[non_existing_cert_path])

    # Make sure we can connect to the server
    self.assertTrue(self.can_connect())


  @unittest.skipIf(sys.version_info.major != 2, "Test for Python 2.X")
  def test_proxy_server_startup(self):
    # Test normal case
    self.server_process_handler = utils.TestServerProcess(log=logger,
        server='proxy_server.py')

    # Make sure we can connect to the server.
    self.assertTrue(self.can_connect())

    self.server_process_handler.clean()

    # Test start proxy_server using certificate files.
    good_cert_fpath = os.path.join('ssl_certs', 'ssl_cert.crt')
    self.server_process_handler = utils.TestServerProcess(log=logger,
        server='proxy_server.py', extra_cmd_args=['intercept',
        good_cert_fpath])

    # Make sure we can connect to the server.
    self.assertTrue(self.can_connect())
    self.server_process_handler.clean()

    # Test with a non existing cert file.
    non_existing_cert_path = os.path.join('ssl_certs', 'non_existing.crt')
    self.server_process_handler = utils.TestServerProcess(log=logger,
        server='proxy_server.py', extra_cmd_args=[non_existing_cert_path])

    # Make sure we can connect to the server.
    self.assertTrue(self.can_connect())


  def test_slow_retrieval_server_startup(self):
    # Test normal case
    self.server_process_handler = utils.TestServerProcess(log=logger,
        server='slow_retrieval_server.py')

    # Make sure we can connect to the server
    self.assertTrue(self.can_connect())


  def test_cleanup(self):
    # Test normal case
    self.server_process_handler = utils.TestServerProcess(log=logger,
        server='simple_server.py')

    self.server_process_handler.clean()

    # Check if the process has successfully been killed.
    self.assertFalse(self.server_process_handler.is_process_running())


  def test_server_exit_before_timeout(self):
    self.assertRaises(utils.TestServerProcessError, utils.TestServerProcess,
        logger, server='non_existing_server.py')

    # Test starting a server which immediately exits."
    self.assertRaises(utils.TestServerProcessError, utils.TestServerProcess,
        logger, server='fast_server_exit.py')


if __name__ == '__main__':
  utils.configure_test_logging(sys.argv)
  unittest.main()
