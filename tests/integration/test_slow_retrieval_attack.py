#!/usr/bin/env python

"""
<Program Name>
  test_slow_retrieval_attack.py

<Author>
  Konstantin Andrianov

<Started>
  March 13, 2012

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Simulate slow retrieval attack.  A simple client update vs. client
  update implementing TUF.

  During the slow retrieval attack, attacker is able to prevent clients from
  being aware of interference with receiving updates by responding to client
  requests so slowly that automated updates never complete.

  NOTE: The interposition provided by 'tuf.interposition' is used to intercept
  all calls made by urllib/urillib2 to certain network locations specified in 
  the interposition configuration file.  Look up interposition.py for more
  information and illustration of a sample contents of the interposition 
  configuration file.  Interposition was meant to make TUF integration with an
  existing software updater an easy process.  This allows for more flexibility
  to the existing software updater.  However, if you are planning to solely use
  TUF there should be no need for interposition, all necessary calls will be
  generated from within TUF.

  There is no difference between 'updates' and 'target' files.

"""

# Help with Python 3 compatability, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division

from multiprocessing import Process
import os
import random
import subprocess
import sys
import time
import tuf
import urllib

import tuf.interposition
import tuf.tests.util_test_tools as util_test_tools


class SlowRetrievalAttackAlert(Exception):
  pass


def _download(url, filename, using_tuf=False):
  if using_tuf:
    try:
      tuf.interposition.urllib_tuf.urlretrieve(url, filename)
    except tuf.NoWorkingMirrorError, exception:
      slow_retrieval = False
      for mirror_url, mirror_error in exception.mirror_errors.iteritems():
        if isinstance(mirror_error, tuf.SlowRetrievalError):
          slow_retrieval = True
          break

      # We must fail due to a slow retrieval error; otherwise we will exit with
      # a "successful termination" exit status to indicate that slow retrieval
      # detection failed.
      if slow_retrieval:
        print('TUF stopped the update because it detected slow retrieval.')
        sys.exit(-1)
      else:
        print('TUF stopped the update due to something other than slow retrieval.')
        sys.exit(0)
  else:
    urllib.urlretrieve(url, filename)



def test_slow_retrieval_attack(using_tuf=False, mode=None):

  WAIT_TIME = 60  # Number of seconds to wait until download completes.
  ERROR_MSG = 'Slow retrieval attack succeeded (using_tuf: '+str(using_tuf)+', mode: '+\
              str(mode)+').'

  # Launch the server.
  port = random.randint(30000, 45000)
  command = ['python', 'slow_retrieval_server.py', str(port), mode]
  server_process = subprocess.Popen(command, stderr=subprocess.PIPE)
  time.sleep(1)

  try:
    # Setup.
    root_repo, url, server_proc, keyids = \
      util_test_tools.init_repo(using_tuf, port=port)
    reg_repo = os.path.join(root_repo, 'reg_repo')
    downloads = os.path.join(root_repo, 'downloads')
    
    # Add file to 'repo' directory: {root_repo}
    filepath = util_test_tools.add_file_to_repository(reg_repo, 'A'*30)
    file_basename = os.path.basename(filepath)
    url_to_file = url+'reg_repo/'+file_basename
    downloaded_file = os.path.join(downloads, file_basename)

    if using_tuf:
      tuf_repo = os.path.join(root_repo, 'tuf_repo')
      
      # Update TUF metadata before attacker modifies anything.
      util_test_tools.tuf_refresh_repo(root_repo, keyids)

      # Modify the url.  Remember that the interposition will intercept 
      # urls that have 'localhost:9999' hostname, which was specified in
      # the json interposition configuration file.  Look for 'hostname'
      # in 'util_test_tools.py'. Further, the 'file_basename' is the target
      # path relative to 'targets_dir'. 
      url_to_file = 'http://localhost:9999/'+file_basename


    # Client tries to download.
    # NOTE: if TUF is enabled the metadata files will be downloaded first.
    proc = Process(target=_download, args=(url_to_file, downloaded_file, using_tuf))
    proc.start()
    proc.join(WAIT_TIME)

    # In case the process did not exit or successfully exited, we failed.
    if not proc.exitcode:
      proc.terminate()
      raise SlowRetrievalAttackAlert(ERROR_MSG)

  finally:
    server_process.kill()
    util_test_tools.cleanup(root_repo, server_proc)





# Stimulates two kinds of slow retrieval attacks.
# mode_1: When download begins,the server blocks the download
# for a long time by doing nothing before it sends first byte of data.
# mode_2: During the download process, the server blocks the download 
# by sending just several characters every few seconds.
try:
  test_slow_retrieval_attack(using_tuf=False, mode = "mode_1")
except SlowRetrievalAttackAlert, error:
  print(error)
  print()

try:
  test_slow_retrieval_attack(using_tuf=False, mode = "mode_2")
except SlowRetrievalAttackAlert, error:
  print(error)
  print()

try:
  test_slow_retrieval_attack(using_tuf=True, mode = "mode_1")
except SlowRetrievalAttackAlert, error:
  print(error)
  print()

try:
  test_slow_retrieval_attack(using_tuf=True, mode = "mode_2")
except SlowRetrievalAttackAlert, error:
  print(error)
  print()





