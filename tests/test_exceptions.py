#!/usr/bin/env python

# Copyright 2014 - 2017, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
<Program Name>
  test_exceptions.py

<Author>
  Vladimir Diaz

<Started>
  July 13, 2017.

<Copyright>
  See LICENSE-MIT OR LICENSE for licensing information.

<Purpose>
  Test cases for exceptions.py (mainly the exceptions defined there).
"""

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import unittest
import logging

import tuf.exceptions

logger = logging.getLogger(__name__)

class TestExceptions(unittest.TestCase):
  def setUp(self):
    pass


  def tearDown(self):
    pass


  def test_bad_signature_error(self):
    bad_signature_error = tuf.exceptions.BadSignatureError('bad sig')
    logger.error(bad_signature_error)


  def test_bad_hash_error(self):
    bad_hash_error = tuf.exceptions.BadHashError('1234', '5678')
    logger.error(bad_hash_error)


# Run the unit tests.
if __name__ == '__main__':
  unittest.main()
