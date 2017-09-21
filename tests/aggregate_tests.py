#!/usr/bin/env python

"""
<Program Name>
  aggregate_tests.py

<Author>
  Konstantin Andrianov.
  Zane Fisher.

<Started>
  January 26, 2013.

  August 2013.
  Modified previous behavior that explicitly imported individual
  unit tests. -Zane Fisher

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Run all the unit tests from every .py file beginning with "test_" in
  'tuf/tests'.  Use --random to run the tests in random order.
"""

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import sys
import unittest
import glob
import random

# Generate a list of pathnames that match a pattern (i.e., that begin with
# 'test_' and end with '.py'.  A shell-style wildcard is used with glob() to
# match desired filenames.  All the tests matching the pattern will be loaded
# and run in a test suite.
tests_list = glob.glob('test_*.py')

# Remove '.py' from each filename to allow loadTestsFromNames() (called below)
# to properly load the file as a module.
tests_without_extension = []
for test in tests_list:
  test = test[:-3]
  tests_without_extension.append(test)

# Randomize the order in which the tests run.  Randomization might catch errors
# with unit tests that do not properly clean up or restore monkey-patched
# modules.
random.shuffle(tests_without_extension)

if __name__ == '__main__':
  suite = unittest.TestLoader().loadTestsFromNames(tests_without_extension)
  all_tests_passed = unittest.TextTestRunner(verbosity=1).run(suite).wasSuccessful()
  if not all_tests_passed:
    sys.exit(1)
