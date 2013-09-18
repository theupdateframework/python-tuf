import logging


# Import our standard logger for its side effects.
import tuf.log





class InterpositionException(Exception):
  """Base exception class."""
  pass





class Logger(object):
  """A static logging object for tuf.interposition."""


  __logger = logging.getLogger("tuf.interposition")


  @staticmethod
  def debug(message):
    Logger.__logger.debug(message)


  @staticmethod
  def exception(message):
    Logger.__logger.exception(message)


  @staticmethod
  def info(message):
    Logger.__logger.info(message)


  @staticmethod
  def warn(message):
    Logger.__logger.warn(message)
