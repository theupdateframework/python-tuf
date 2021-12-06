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

import sys
import unittest

if __name__ == "__main__":
    suite = unittest.TestLoader().discover(".")
    all_tests_passed = (
        unittest.TextTestRunner(verbosity=1, buffer=True)
        .run(suite)
        .wasSuccessful()
    )

    if not all_tests_passed:
        sys.exit(1)

    else:
        sys.exit(0)
