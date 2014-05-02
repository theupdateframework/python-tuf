
"""
<Program Name>
  test_log.py

<Authors>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  May 1, 2014.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Unit test for 'log.py'.
"""

import logging
import unittest

import tuf
import tuf.log

logger = logging.getLogger('tuf.test_log')

log_levels = [logging.CRITICAL, logging.ERROR, logging.WARNING,
              logging.INFO, logging.DEBUG]


class TestLog(unittest.TestCase):
  
   


  def test_set_log_level(self):
    # Test normal case.
    global log_levels

    tuf.log.set_log_level()
    self.assertTrue(logger.isEnabledFor(logging.DEBUG))
    
    for level in log_levels:
      tuf.log.set_log_level(level)
      self.assertTrue(logger.isEnabledFor(level))

    # Test for improperly formatted argument.
    self.assertRaises(tuf.FormatError, tuf.log.set_log_level, '123')

    # Test for invalid argument.
    self.assertRaises(tuf.FormatError, tuf.log.set_log_level, 51)



  def test_set_filehandler_log_level(self):
    pass


  def test_set_console_log_level(self):
    pass



  def test_add_console_handler(self):
    pass



  def test_remove_console_handler(self):
    pass



# Run unit test.
if __name__ == '__main__':
  unittest.main()
