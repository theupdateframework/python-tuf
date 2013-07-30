"""
<Program Name>
  aggregate_tests.py

<Author>
  Konstantin Andrianov

<Started>
  January 26, 2013
 
<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Run all the unit tests in 'tuf/tests'.

"""

import glob

tests_list = glob.glob('test_*.py')
for test in tests_list:
  __import__(test[:-3])

import system_tests.test_util_test_tools
import system_tests.test_replay_attack
