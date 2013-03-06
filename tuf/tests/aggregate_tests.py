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

# The unit tests listed below should provide their respective test suites
# and run on import.
import tuf.tests.test_download
import tuf.tests.test_formats
import tuf.tests.test_hash
import tuf.tests.test_keydb
import tuf.tests.test_keystore
import tuf.tests.test_mirrors
import tuf.tests.test_quickstart
import tuf.tests.test_roledb
import tuf.tests.test_rsa_key
import tuf.tests.test_schema
import tuf.tests.test_signercli
import tuf.tests.test_signerlib
import tuf.tests.test_sig
import tuf.tests.test_util
import tuf.tests.test_updater
import tuf.tests.system_tests.test_util_test_tools
import tuf.tests.system_tests.test_replay_attack
