#!/usr/bin/env python

# Copyright 2017, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
<Program Name>
  test_unittest_toolbox.py

<Author>
  Vladimir Diaz

<Started>
  July 14, 2017.

<Copyright>
  See LICENSE-MIT OR LICENSE for licensing information.

<Purpose>
  Test cases for unittest_toolbox.py.
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
import shutil

import tuf.unittest_toolbox as unittest_toolbox

logger = logging.getLogger(__name__)


class TestUnittestToolbox(unittest_toolbox.Modified_TestCase):
  def setUp(self):
    unittest_toolbox.Modified_TestCase.setUp(self)

  def tearDown(self):
    unittest_toolbox.Modified_TestCase.tearDown(self)


  def test_tear_down_already_deleted_dir(self):
    temp_directory = self.make_temp_directory()

    # Delete the temp directory to make sure unittest_toolbox doesn't
    # complain about the missing temp_directory.
    shutil.rmtree(temp_directory)


# Run the unit tests.
if __name__ == '__main__':
  unittest.main()
