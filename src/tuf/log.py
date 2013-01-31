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
  A central location for all logging-related configuration.
  This module should be imported once by the main program.
  If other modules wish to incorporate 'tuf' logging, they
  should do the following:

  import logging
  logger = logging.getLogger('tuf')

  'logging' refers to the module name.  logging.getLogger() is a function of
  the module 'logging'.  logging.getLogger(name) returns a Logger instance
  associated with 'name'.  Calling getLogger(name) will always return the same
  instance.  In this 'log.py' module, we perform the initial setup for the name
  'tuf'.  The 'log.py' module should only be imported once by the main program.
  When any other module does a logging.getLogger('tuf'), it is referring to the
  same 'tuf' instance and its associated settings we set up here in 'log.py'.
  See http://docs.python.org/library/logging.html#logger-objects
  for more information.

  We use multiple handlers to process log messages in various ways and to
  configure each one independently.  Instead of using one single manner of
  processing log messages, we can use two built-in handlers that have already
  been configured for us.  For example, the built-in FileHandler will catch
  log message and dump them to a file.  If we wanted, we could set this file
  handler to only catch CRITICAL (and greater)  messages and save them to a
  file.  The other stream handler would still handle DEBUG-level (and greater)
  messages.

"""


import logging


_DEFAULT_LOG_LEVEL = logging.INFO
_DEFAULT_LOG_FILENAME = 'tuf.log'

# Set the format for logging messages.
_FORMAT_STRING = "[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s"
formatter = logging.Formatter(_FORMAT_STRING)

# Set the handlers for the logger.
# The built-in stream handler will log
# messages to 'sys.stderr' and capture
# '_DEFAULT_LOG_LEVEL' messages.
stream_handler = logging.StreamHandler()
stream_handler.setLevel(_DEFAULT_LOG_LEVEL)
stream_handler.setFormatter(formatter)

# Set the built-in file handler.  Messages
# will be logged to '_DEFAULT_LOG_FILENAME'
# and use the logger's default log level.
# The file will be opened in append mode.
file_handler = logging.FileHandler(_DEFAULT_LOG_FILENAME)
file_handler.setFormatter(formatter)

# Set the logger and its settings.
logger = logging.getLogger('tuf')
logger.setLevel(_DEFAULT_LOG_LEVEL)
logger.addHandler(stream_handler)
logger.addHandler(file_handler)

# Silently ignore logger exceptions.
logging.raiseExceptions = False





def set_log_level(log_level):
  """
  <Purpose>
    Allow the default log level to be overridden.

  <Arguments>
    log_level:
      The log level to set for the logger and handler(s).
      E.g., logging.INFO; logging.CRITICAL.
      
  <Exceptions>
    None.

  <Side Effects>
    Overrides the logging level for the internal 
    'logger' and 'handler'.

  <Returns>
    None.

  """

  logger.setLevel(log_level)
  stream_handler.setLevel(log_level)
