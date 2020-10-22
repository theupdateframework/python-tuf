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
        + " on port " + str(port) + "!")


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
    # of the subprocess. In the mode "r+" stands for reading and writing
    # and "t" stands for text mode.
    self.__temp_log_file = tempfile.TemporaryFile(mode='r+t')

    self.server = server
    self.__logger = log

    try:
      self._start_server(port, timeout, extra_cmd_args, popen_cwd)

      wait_for_server('localhost', self.server, self.port, timeout)
    except Exception as e:
      # Clean the resources and log the server errors if any exists.
      self.clean()
      raise e



  def _start_server(self, port, timeout, extra_cmd_args, popen_cwd):
    """Start the server subprocess. Uses a retry mechanism and
    generates a new port if the bind fails."""

    started = False
    ports_generated = 0
    start = time.time()
    while not started and timeout > 0:
      self.port = port or random.randint(30000, 45000)
      ports_generated += 1
      # The "-u" option forces stdin, stdout and stderr to be unbuffered.
      command = ['python', '-u', self.server, str(self.port)] + extra_cmd_args

      # We are reusing one server subprocess in multiple unit tests, but we are
      # collecting the logs per test.
      self.__server_process = subprocess.Popen(command,
          stdout=self.__temp_log_file, stderr=subprocess.STDOUT, cwd=popen_cwd)

      started = self._has_server_started(timeout)

      if not started:
        # If the server has not started for whatever reason
        self.__logger.info("Failed to start " + self.server + " on port " \
            + str(self.port) + "! Generating a new port and retrying.")

        if self.is_process_running():
          self.__server_process.kill()
          self.__server_process.wait()

        timeout = timeout - (time.time() - start)

    if not started:
      raise TimeoutError("Failure during server startup after " \
        + str(ports_generated) + " retries with random ports!")

    # Make sure the file is empty so we don't print log messages related
    # to the has_server_started checks.
    self.__temp_log_file.truncate(0)

    self.__logger.info('Server process with process id ' \
        + str(self.__server_process.pid) + " serving on port " \
        + str(self.port) + ' started.')



  def _has_server_started(self, remaining_timeout):
    """Waits until server has successfully started or
    'remaining_timeout' seconds have elapsed."""

    start = time.time()
    while remaining_timeout > 0:
      # Seek is needed to move the pointer to the beginning of the file, because
      # the subprocess could have read and/or write and thus moved the pointer.
      self.__temp_log_file.seek(0)
      log_message = self.__temp_log_file.read()

      if len(log_message) > 0:
        lines = log_message.splitlines()

        if "bind succeeded" in lines:
          return True
        elif "bind failed" in lines:
          return False

      time.sleep(0.1)
      remaining_timeout = remaining_timeout - (time.time() - start)

    # If the server process has exited we consider this as a
    # failed attempt to start the server.
    if not self.is_process_running():
        return False



  def flush_log(self):
    """Logs contents from TempFile, truncates buffer"""

    # Make sure we are only reading from opened files.
    if self.__temp_log_file.closed:
      return

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

    if self.is_process_running():
      self.__logger.info('Server process ' + str(self.__server_process.pid) +
          ' terminated.')
      self.__server_process.kill()
      self.__server_process.wait()



  def is_process_running(self):
    """Returns a boolean value if the server process is currently running."""

    return True if self.__server_process.returncode is None else False
