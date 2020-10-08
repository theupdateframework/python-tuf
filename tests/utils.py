#!/usr/bin/env python

# Copyright 2020, TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
<Program Name>
  utils.py

<Started>
  August 3, 2020.

<Author>
  Jussi Kukkonen

<Copyright>
  See LICENSE-MIT OR LICENSE for licensing information.

<Purpose>
  Provide common utilities for TUF tests
"""

import argparse
from contextlib import contextmanager
import errno
import logging
import socket
import time
import subprocess
import tempfile
import random
import warnings

import tuf.log

logger = logging.getLogger(__name__)

try:
  # is defined in Python 3
  TimeoutError
except NameError:
  # Define for Python 2
  class TimeoutError(Exception):

    def __init__(self, value="Timeout"):
      self.value = value

    def __str__(self):
      return repr(self.value)


@contextmanager
def ignore_deprecation_warnings(module):
  with warnings.catch_warnings():
    warnings.filterwarnings('ignore',
        category=DeprecationWarning,
        module=module)
    yield


# Wait until host:port accepts connections.
# Raises TimeoutError if this does not happen within timeout seconds
# There are major differences between operating systems on how this works
# but the current blocking connect() seems to work fast on Linux and seems
# to at least work on Windows (ECONNREFUSED unfortunately has a 2 second
# timeout on Windows)
def wait_for_server(host, server, port, timeout=10):
  start = time.time()
  remaining_timeout = timeout
  succeeded = False
  while not succeeded and remaining_timeout > 0:
    try:
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.settimeout(remaining_timeout)
      sock.connect((host, port))
      succeeded = True
    except socket.timeout as e:
      pass
    except IOError as e:
      # ECONNREFUSED is expected while the server is not started
      if e.errno not in [errno.ECONNREFUSED]:
        logger.warning("Unexpected error while waiting for server: " + str(e))
      # Avoid pegging a core just for this
      time.sleep(0.01)
    finally:
      if sock:
        sock.close()
        sock = None
      remaining_timeout = timeout - (time.time() - start)

  if not succeeded:
    raise TimeoutError("Could not connect to the " + server \
        + " on port " + str(port) + " !")


def configure_test_logging(argv):
  # parse arguments but only handle '-v': argv may contain 
  # other things meant for unittest argument parser
  parser = argparse.ArgumentParser(add_help=False)
  parser.add_argument('-v', '--verbose', action='count', default=0)
  args, _ = parser.parse_known_args(argv)
  
  if args.verbose <= 1:
    # 0 and 1 both mean ERROR: this way '-v' makes unittest print test
    # names without increasing log level
    loglevel = logging.ERROR
  elif args.verbose == 2:
    loglevel = logging.WARNING
  elif args.verbose == 3:
    loglevel = logging.INFO
  else:
    loglevel = logging.DEBUG

  logging.basicConfig(level=loglevel)
  tuf.log.set_log_level(loglevel)


class TestServerProcess():
  """
  <Purpose>
    Creates a child process with the subprocess.Popen object and
    TempFile object used for logging.

   <Arguments>
      log:
        Logger which will be used for logging.

      server:
        Path to the server to run in the subprocess.
        Default is "simpler_server.py".

      port:
        The port used to access the server. If none is provided,
        then one will be generated.
        Default is None.

      timeout:
        Time in seconds in which the server should start or otherwise
        TimeoutError error will be raised.
        If 0 is given, no check if the server has started will be done.
        Default is 10.

      popen_cwd:
        Current working directory used when instancing a
        subprocess.Popen object.
        Default is "."

      extra_cmd_args:
        List of additional arguments for the command
        which will start the subprocess.
        More precisely "python -u <path_to_server> <port> <extra_cmd_args>".
        Default is empty list.
  """


  def __init__(self, log, server='simple_server.py',
      port=None, timeout=10, popen_cwd=".",
      extra_cmd_args=[]):

    # Create temporary log file used for logging stdout and stderr
    # of the subprocess. In the mode "r+"" stands for reading and writing
    # and "t" stands for text mode.
    self.__temp_log_file = tempfile.TemporaryFile(mode='r+t')

    self.server = server
    self.port = port or random.randint(30000, 45000)
    self.__logger = log

    # The "-u" option forces stdin, stdout and stderr to be unbuffered.
    command = ['python', '-u', server, str(self.port)] + extra_cmd_args

    # We are reusing one server subprocess in multiple unit tests, but we are
    # collecting the logs per test.
    self.__server_process = subprocess.Popen(command,
        stdout=self.__temp_log_file, stderr=subprocess.STDOUT, cwd=popen_cwd)

    self.__logger.info('Server process with process id ' \
        + str(self.__server_process.pid) + " serving on port " \
        + str(self.port) + ' started.')

    if timeout > 0:
      try:
        wait_for_server('localhost', self.server, self.port, timeout)
      except Exception as e:
        # Make sure that errors from the server side will be logged.
        self.flush_log()
        raise e



  def flush_log(self):
    """Logs contents from TempFile, truncates buffer"""

    # Seek is needed to move the pointer to the beginning of the file, because
    # the subprocess could have read and/or write and thus moved the pointer.
    self.__temp_log_file.seek(0)
    log_message = self.__temp_log_file.read()

    if len(log_message) > 0:
      title = "Test server (" + self.server + ") output:"
      message = [title] + log_message.splitlines()
      self.__logger.info('\n| '.join(message))

      # Make sure the file is empty before the next test logs new information.
      self.__temp_log_file.truncate(0)



  def clean(self):
    """Kills the subprocess and closes the TempFile.
    Calls flush_log to check for logged information, but not yet flushed."""

    # If there is anything logged, flush it before closing the resourses.
    self.flush_log()

    self.__temp_log_file.close()

    if self.__server_process.returncode is None:
      self.__logger.info('Server process ' + str(self.__server_process.pid) +
          ' terminated.')
      self.__server_process.kill()
      self.__server_process.wait()
