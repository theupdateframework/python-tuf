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
import errno
import logging
import socket
import time

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

# Wait until host:port accepts connections.
# Raises TimeoutError if this does not happen within timeout seconds
# There are major differences between operating systems on how this works
# but the current blocking connect() seems to work fast on Linux and seems
# to at least work on Windows (ECONNREFUSED unfortunately has a 2 second
# timeout on Windows)
def wait_for_server(host, port, timeout=10):
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
    raise TimeoutError


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

  logging.basicConfig()
  tuf.log.set_log_level(loglevel)
