#!/usr/bin/env python

# Copyright 2014 - 2017, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
<Program Name>
  test_log.py

<Authors>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  May 1, 2014.

<Copyright>
  See LICENSE-MIT OR LICENSE for licensing information.

<Purpose>
  Unit test for 'log.py'.
"""

import logging
import unittest
import os
import shutil

import tuf
import tuf.log
import tuf.settings

import securesystemslib
import securesystemslib.util

from six.moves import reload_module

# We explicitly create a logger which is a child of the tuf hierarchy,
# instead of using the standard getLogger(__name__) pattern, because the
# tests are not part of the tuf hierarchy and we are testing functionality
# of the tuf package explicitly enabled on the tuf hierarchy
logger = logging.getLogger('tuf.test_log')

log_levels = [logging.CRITICAL, logging.ERROR, logging.WARNING,
  logging.INFO, logging.DEBUG]


class TestLog(unittest.TestCase):


  def tearDown(self):
    tuf.log.remove_console_handler()
    tuf.log.disable_file_logging()



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
    # A file handler is not set by default.  Add one now before attempting to
    # set the log level.
    self.assertRaises(tuf.exceptions.Error, tuf.log.set_filehandler_log_level)
    tuf.log.enable_file_logging()
    tuf.log.set_filehandler_log_level()

    # Expected log levels.
    for level in log_levels:
      tuf.log.set_log_level(level)

    # Test that the log level of the file handler cannot be set because
    # file logging is disabled (via tuf.settings.ENABLE_FILE_LOGGING).
    tuf.settings.ENABLE_FILE_LOGGING = False
    reload_module(tuf.log)

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


  def test_enable_file_logging(self):
    # Normal case.
    if os.path.exists(tuf.settings.LOG_FILENAME):
      shutil.move(
          tuf.settings.LOG_FILENAME, tuf.settings.LOG_FILENAME + '.backup')

    tuf.log.enable_file_logging()
    self.assertTrue(os.path.exists(tuf.settings.LOG_FILENAME))
    if os.path.exists(tuf.settings.LOG_FILENAME + '.backup'):
      shutil.move(
          tuf.settings.LOG_FILENAME + '.backup', tuf.settings.LOG_FILENAME)

    # The file logger must first be unset before attempting to re-add it.
    self.assertRaises(tuf.exceptions.Error, tuf.log.enable_file_logging)

    tuf.log.disable_file_logging()
    tuf.log.enable_file_logging('my_log_file.log')
    logger.debug('testing file logging')
    self.assertTrue(os.path.exists('my_log_file.log'))

    # Test for an improperly formatted argument.
    tuf.log.disable_file_logging()
    self.assertRaises(securesystemslib.exceptions.FormatError,
        tuf.log.enable_file_logging, 1)


  def test_disable_file_logging(self):
    # Normal case.
    tuf.log.enable_file_logging('my.log')
    logger.debug('debug message')
    junk, hashes = securesystemslib.util.get_file_details('my.log')
    tuf.log.disable_file_logging()
    logger.debug('new debug message')
    junk, hashes2 = securesystemslib.util.get_file_details('my.log')
    self.assertEqual(hashes, hashes2)

    # An exception should not be raised if an attempt is made to disable
    # the file logger if it has already been disabled.
    tuf.log.disable_file_logging()


# Run unit test.
if __name__ == '__main__':
  unittest.main()
