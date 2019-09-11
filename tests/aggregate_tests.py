#!/usr/bin/env python

# Copyright 2013 - 2017, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

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
  See LICENSE-MIT OR LICENSE for licensing information.

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
available_tests = glob.glob('test_*.py')

# A dictionary of test modules that should only run in certain python versions.
# Carefully consider the impact of only testing these in a given version.
# test_proxy_use.py: uses a proxy that only runs in Python2.7. TUF's
# compatibility with proxies is not likely to vary based on the Python version
# in use, so this is OK for now. See comments in that module.
# The semantics here are: only add to this list the particular tests that are
# to be run in a single major version or a single minor version. An entry must
# include major version, and may include minor version.
# Skip the test if any  such listed constraints don't match the python version
# currently running.
# Note that aggregate_tests.py is run for each version of Python that tox is
# configured to use. Note also that this TUF implementation does not support
# any Python versions <2.7 or any Python3 versions <3.4.
VERSION_SPECIFIC_TESTS = {
    'test_proxy_use': {'major': 2, 'minor': 7}} # Run test only if Python2.7
# Further example:
#   'test_abc': {'major': 2} # Run test only if Python2

# Determine which tests should be run.
test_modules_to_run = []
for test in available_tests:
  # Remove '.py' from each filename to allow loadTestsFromNames() (called below)
  # to properly load the file as a module.
  assert test[-3:] == '.py', 'aggregate_tests.py is inconsistent; fix.'
  test = test[:-3]

  if test in VERSION_SPECIFIC_TESTS:
    # Consistency checks.
    assert 'major' in VERSION_SPECIFIC_TESTS[test], 'Empty/illogical constraint'
    for keyword in VERSION_SPECIFIC_TESTS[test]:
      assert keyword in ['major', 'minor'], 'Unrecognized test constraint'

    if sys.version_info.major != VERSION_SPECIFIC_TESTS[test]['major']:
      continue
    if 'minor' in VERSION_SPECIFIC_TESTS[test] \
        and sys.version_info.minor != VERSION_SPECIFIC_TESTS[test]['minor']:
      continue
  test_modules_to_run.append(test)

# Randomize the order in which the tests run.  Randomization might catch errors
# with unit tests that do not properly clean up or restore monkey-patched
# modules.
random.shuffle(test_modules_to_run)

if __name__ == '__main__':
  suite = unittest.TestLoader().loadTestsFromNames(test_modules_to_run)
  all_tests_passed = unittest.TextTestRunner(
      verbosity=1, buffer=True).run(suite).wasSuccessful()

  if not all_tests_passed:
    sys.exit(1)

  else:
    sys.exit(0)
