"""
<Program Name>
  test_replay_attack.py

<Author>
  Konstantin Andrianov

<Started>
  February 22, 2012

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Simulate a replay attack.  A simple client update vs. client update 
  implementing TUF.

  Note: It's assumed that attacker does NOT have access to metadata signing
  keys.  Keep them safe!

"""

import test_system_setup
import replay_attack_setup


test_system_setup.init_repo(tuf=False)

try:
  replay_attack_setup.replay_attack()
except AssertionError, e:
  print 'Expected Failure: '+repr(e)
else:
  print 'Unexpected Failure!'

test_system_setup.cleanup()


test_system_setup.init_repo(tuf=True)

try:
  replay_attack_setup.replay_attack()
except AssertionError, e:
  print 'Unexpected Failure: '+repr(e)
else:
  print 'Expected Success!'

test_system_setup.cleanup()