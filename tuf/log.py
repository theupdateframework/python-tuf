"""
<Program Name>
  log.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  April 4, 2012.  Based on a previous version of this module by Geremy Condra.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  A central location for all logging-related configuration.  This module should
  be imported once by the main program.  If other modules wish to incorporate
  'tuf' logging, they should do the following:

  import logging
  logger = logging.getLogger('tuf')

  'logging' refers to the module name.  logging.getLogger() is a function of
  the module 'logging'.  logging.getLogger(name) returns a Logger instance
  associated with 'name'.  Calling getLogger(name) will always return the same
  instance.  In this 'log.py' module, we perform the initial setup for the name
  'tuf'.  The 'log.py' module should only be imported once by the main program.
  When any other module does a logging.getLogger('tuf'), it is referring to the
  same 'tuf' instance, and its associated settings, set here in 'log.py'.
  See http://docs.python.org/library/logging.html#logger-objects for more
  information.

  We use multiple handlers to process log messages in various ways and to
  configure each one independently.  Instead of using one single manner of
  processing log messages, we can use two built-in handlers that have already
  been configured for us.  For example, the built-in FileHandler will catch
  log messages and dump them to a file.  If we wanted, we could set this file
  handler to only catch CRITICAL (and greater) messages and save them to a
  file.  Other handlers (e.g., StreamHandler) could handle INFO-level
  (and greater) messages.

  Logging Levels:

    --Level--         --Value--
  logging.CRITICAL        50
  logging.ERROR           40
  logging.WARNING         30
  logging.INFO            20
  logging.DEBUG           10
  logging.NOTSET           0

"""


import logging
import time

import tuf
import tuf.formats

# Setting a handler's log level filters only logging messages of that level
# (and above).  For example, setting the built-in StreamHandler's log level to
# 'logging.WARNING' will cause the stream handler to only process messages
# of levels: WARNING, ERROR, and CRITICAL. 
_DEFAULT_LOG_FILENAME = 'tuf.log'
_DEFAULT_LOG_LEVEL = logging.DEBUG
_DEFAULT_CONSOLE_LOG_LEVEL = logging.INFO
_DEFAULT_FILE_LOG_LEVEL = logging.DEBUG

# Set the format for logging messages.
# Example format for '_FORMAT_STRING': 
# [2013-08-13 15:21:18,068 UTC] [tuf] [INFO][_update_metadata:851@updater.py]
_FORMAT_STRING = '[%(asctime)s UTC] [%(name)s] [%(levelname)s]'+\
  '[%(funcName)s:%(lineno)s@%(filename)s] %(message)s'


logging.Formatter.converter = time.gmtime
formatter = logging.Formatter(_FORMAT_STRING)

# Set the handlers for the logger.  The console handler is unset by default.  A
# module importing 'log.py' should explicitly set the console handler if
# outputting log messages to the screen is needed.  Adding a console handler
# can be done with tuf.log.add_console_handler().  Logging messages to a file
# *is* set by default. 
console_handler = None

# Set the built-in file handler.  Messages will be logged to
# '_DEFAULT_LOG_FILENAME', and only those messages with a log level of
# '_DEFAULT_LOG_LEVEL'.  The log level of messages handled by 'file_handler'
# may be modified with 'set_filehandler_log_level()'.  '_DEFAULT_LOG_FILENAME'
# will be opened in append mode.
file_handler = logging.FileHandler(_DEFAULT_LOG_FILENAME)
file_handler.setLevel(_DEFAULT_FILE_LOG_LEVEL)
file_handler.setFormatter(formatter)

# Set the logger and its settings.
logger = logging.getLogger('tuf')
logger.setLevel(_DEFAULT_LOG_LEVEL)
logger.addHandler(file_handler)

# Silently ignore logger exceptions.
logging.raiseExceptions = False





def set_log_level(log_level=_DEFAULT_LOG_LEVEL):
  """
  <Purpose>
    Allow the default log level to be overridden.

  <Arguments>
    log_level:
      The log level to set for the 'log.py' file handler.
      'log_level' examples: logging.INFO; logging.CRITICAL.
      
  <Exceptions>
    None.

  <Side Effects>
    Overrides the logging level for the 'log.py' file handler.

  <Returns>
    None.

  """
  
  # Does 'log_level' have the correct format?
  # Raise 'tuf.FormatError' if there is a mismatch.
  tuf.formats.LENGTH_SCHEMA.check_match(log_level)
  
  logger.setLevel(log_level)





def set_filehandler_log_level(log_level=_DEFAULT_FILE_LOG_LEVEL):
  """
  <Purpose>
    Allow the default file handler log level to be overridden.

  <Arguments>
    log_level:
      The log level to set for the 'log.py' file handler.
      'log_level' examples: logging.INFO; logging.CRITICAL.
      
  <Exceptions>
    None.

  <Side Effects>
    Overrides the logging level for the 'log.py' file handler.

  <Returns>
    None.

  """
  
  # Does 'log_level' have the correct format?
  # Raise 'tuf.FormatError' if there is a mismatch.
  tuf.formats.LENGTH_SCHEMA.check_match(log_level)
  
  file_handler.setLevel(log_level)





def set_console_log_level(log_level=_DEFAULT_CONSOLE_LOG_LEVEL):
  """
  <Purpose>
    Allow the default log level for console messages to be overridden.

  <Arguments>
    log_level:
      The log level to set for the console handler.
      'log_level' examples: logging.INFO; logging.CRITICAL.
      
  <Exceptions>
    tuf.Error, if the 'log.py' console handler has not been set yet with
    add_console_handler().

  <Side Effects>
    Overrides the logging level for the console handler.

  <Returns>
    None.

  """
  
  # Does 'log_level' have the correct format?
  # Raise 'tuf.FormatError' if there is a mismatch.
  tuf.formats.LENGTH_SCHEMA.check_match(log_level)
  
  if console_handler is not None:
    console_handler.setLevel(log_level)
  else:
    message = 'The console handler has not been set with add_console_handler().'
    raise tuf.Error(message)




def add_console_handler(log_level=_DEFAULT_CONSOLE_LOG_LEVEL):
  """
  <Purpose>
    Add a console handler and set its log level to 'log_level'.

  <Arguments>
    log_level:
      The log level to set for the console handler.
      'log_level' examples: logging.INFO; logging.CRITICAL.
      
  <Exceptions>
    None.

  <Side Effects>
    Adds a console handler to the 'log.py' logger and sets its logging level to
    'log_level'.

  <Returns>
    None.

  """
  
  # Does 'log_level' have the correct format?
  # Raise 'tuf.FormatError' if there is a mismatch.
  tuf.formats.LENGTH_SCHEMA.check_match(log_level)

  # Set the console handler for the logger.  The built-in console handler will
  # log messages to 'sys.stderr' and capture 'log_level' messages.
  global console_handler
  console_handler = logging.StreamHandler()
  console_handler.setLevel(log_level)
  console_handler.setFormatter(formatter)
  logger.addHandler(console_handler)
