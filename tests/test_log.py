#!/usr/bin/env python

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
import imp

import tuf
import tuf.log
import tuf.settings

import securesystemslib

logger = logging.getLogger('tuf.test_log')

log_levels = [logging.CRITICAL, logging.ERROR, logging.WARNING,
  logging.INFO, logging.DEBUG]


class TestLog(unittest.TestCase):


  def tearDown(self):
    tuf.log.remove_console_handler()



  def test_set_log_level(self):
    # Test normal case.
    global log_levels
    global logger

    tuf.log.set_log_level()
    self.assertTrue(logger.isEnabledFor(logging.DEBUG))

    for level in log_levels:
      tuf.log.set_log_level(level)
      self.assertTrue(logger.isEnabledFor(level))

    # Test for improperly formatted argument.
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.log.set_log_level, '123')

    # Test for invalid argument.
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.log.set_log_level, 51)



  def test_set_filehandler_log_level(self):
    # Normal case.  Default log level.
    tuf.log.set_filehandler_log_level()

    # Expected log levels.
    for level in log_levels:
      tuf.log.set_log_level(level)

    # Test that the log level of the file handler cannot be set because
    # file logging is disabled (via tuf.settings.ENABLE_FILE_LOGGING).
    tuf.settings.ENABLE_FILE_LOGGING = False
    imp.reload(tuf.log)
    #self.assertRaises(securesystemslib.exceptions.Error, tuf.log.set_filehandler_log_level, logging.INFO)

    # Test for improperly formatted argument.
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.log.set_filehandler_log_level, '123')

    # Test for invalid argument.
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.log.set_filehandler_log_level, 51)


  def test_set_console_log_level(self):
    # Test setting a console log level without first adding one.
    self.assertRaises(securesystemslib.exceptions.Error, tuf.log.set_console_log_level)

    # Normal case.  Default log level.  Setting the console log level first
    # requires adding a console logger.
    tuf.log.add_console_handler()
    tuf.log.set_console_log_level()

    # Expected log levels.
    for level in log_levels:
      tuf.log.set_console_log_level(level)

    # Test for improperly formatted argument.
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.log.set_console_log_level, '123')

    # Test for invalid argument.
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.log.set_console_log_level, 51)





  def test_add_console_handler(self):
    # Normal case.  Default log level.
    tuf.log.add_console_handler()

    # Adding a console handler when one has already been added.
    tuf.log.add_console_handler()

    # Expected log levels.
    for level in log_levels:
      tuf.log.set_console_log_level(level)

    # Test for improperly formatted argument.
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.log.add_console_handler, '123')

    # Test for invalid argument.
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.log.add_console_handler, 51)

    # Test that an exception is printed to the console.  Note: A stack trace
    # is not included in the exception output because 'log.py' applies a filter
    # to minimize the amount of output to the console.
    try:
      raise TypeError('Test exception output in the console.')

    except TypeError as e:
      logger.exception(e)


  def test_remove_console_handler(self):
    # Normal case.
    tuf.log.remove_console_handler()

    # Removing a console handler that has not been added.  Logs a warning.
    tuf.log.remove_console_handler()



# Run unit test.
if __name__ == '__main__':
  unittest.main()
