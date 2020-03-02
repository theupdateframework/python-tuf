#!/usr/bin/env python

# Copyright 2015 - 2017, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
<Program Name>
  test_init.py

<Author>
  Vladimir Diaz

<Started>
  March 30, 2015.

<Copyright>
  See LICENSE-MIT OR LICENSE for licensing information.

<Purpose>
  Test cases for __init__.py (mainly the exceptions defined there).
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

import tuf
import tuf.exceptions
import tuf.log

import securesystemslib

logger = logging.getLogger(__name__)

class TestInit(unittest.TestCase):
  def setUp(self):
    pass


  def tearDown(self):
    pass


  def test_bad_signature_error(self):
    bad_signature_error = securesystemslib.exceptions.BadSignatureError('bad_role')
    logger.error(bad_signature_error)


  def test_slow_retrieval_error(self):
    slow_signature_error = tuf.exceptions.SlowRetrievalError('bad_role')
    logger.error(slow_signature_error)


  def test_bad_hash_error(self):
    bad_hash_error = securesystemslib.exceptions.BadHashError('01234', '56789')
    logger.error(bad_hash_error)


  def test_invalid_metadata_json_error(self):
    format_error = securesystemslib.exceptions.FormatError('Improperly formatted JSON')
    invalid_metadata_json_error = tuf.exceptions.InvalidMetadataJSONError(format_error)
    logger.error(invalid_metadata_json_error)



# Run the unit tests.
if __name__ == '__main__':
  unittest.main()
