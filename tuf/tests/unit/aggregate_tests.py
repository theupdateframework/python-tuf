#!/usr/bin/env python

"""
<Program Name>
  aggregate_tests.py

<Author>
  Konstantin Andrianov
  Zane Fisher

<Started>
  January 26, 2013

  August 2013.
  Modified previous behavior that explicitly imported individual
  unit tests. -Zane Fisher
 
<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Run all the unit tests from every .py file beginning with "test_" in
  'tuf/tests'.  Use --random to run the tests in random order.

"""


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

# Provide command-line option to randomize the order in which the tests run.
# Randomization might catch errors with unit tests that do not properly clean
# up or restore monkey-patched modules.
if '--random' in sys.argv:
  random.shuffle(tests_without_extension)


suite = unittest.TestLoader().loadTestsFromNames(tests_without_extension)
unittest.TextTestRunner(verbosity=2).run(suite)
