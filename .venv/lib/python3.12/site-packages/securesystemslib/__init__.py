import logging

__version__ = "1.5.0"

# Configure a basic 'securesystemslib' top-level logger with a StreamHandler
# (print to console) and the WARNING log level (print messages of type
# warning, error or critical). This is similar to what 'logging.basicConfig'
# would do with the root logger. All 'securesystemslib.*' loggers default to
# this top-level logger and thus may be configured (e.g. formatted, silenced,
# etc.) with it. It can be accessed via logging.getLogger('securesystemslib').
logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)
logger.addHandler(logging.StreamHandler())
