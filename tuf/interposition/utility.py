import logging





class InterpositionException(Exception):
  """Base exception class."""
  pass





class Logger(object):
  """A static logging object for tuf.interposition."""


  __logger = logging.getLogger("tuf.interposition")


  @staticmethod
  def error(message):
    Logger.__logger.error(message)
    Logger.exception(message)


  @staticmethod
  def exception(message):
    Logger.__logger.exception(message)


  @staticmethod
  def warn(message):
    Logger.__logger.warn(message)
    Logger.exception(message)
