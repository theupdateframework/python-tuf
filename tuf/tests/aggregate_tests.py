"""
<Program Name>
  aggregate_tests.py

<Author>
  Konstantin Andrianov
  Zane Fisher

<Started>
  January 26, 2013

  August 2013. Modified previous behavior that explicitly imported individual
  unit tests. -Zane Fisher
 
<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Run all the unit tests from every .py file beginning with "test_" in 'tuf/tests'.

"""

import unittest
import glob
import tuf.keydb as keydb
import tuf.repo.keystore as keystore
import tuf.roledb as roledb

tests_list = glob.glob('test_*.py')

# Remove '.py' from each filename.
tests_list = [test[:-3] for test in tests_list]

suite = unittest.TestLoader().loadTestsFromNames(tests_list)

unittest.TextTestRunner(verbosity=2).run(suite)
