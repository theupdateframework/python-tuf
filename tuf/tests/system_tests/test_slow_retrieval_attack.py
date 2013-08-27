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

NOTE: Currently TUF does not protect against slow retrieval attacks.

NOTE: The interposition provided by 'tuf.interposition' is used to intercept
all calls made by urllib/urillib2 to certain network locations specified in 
the interposition configuration file.  Look up interposition.py for more
information and illustration of a sample contents of the interposition 
configuration file.  Interposition was meant to make TUF integration with an
existing software updater an easy process.  This allows for more flexibility
to the existing software updater.  However, if you are planning to solely use
TUF there should be no need for interposition, all necessary calls will be
generated from within TUF.

Note: There is no difference between 'updates' and 'target' files.

"""

import os
import time
import urllib
import random
import subprocess
from multiprocessing import Process

import tuf.tests.system_tests.util_test_tools as util_test_tools
from tuf.interposition import urllib_tuf


class SlowRetrievalAttackAlert(Exception):
  pass


def _download(url, filename, tuf=False):
  if tuf:
    urllib_tuf.urlretrieve(url, filename)
    
  else:
    urllib.urlretrieve(url, filename)



def test_slow_retrieval_attack(TUF=False):

  WAIT_TIME = 5  # Number of seconds to wait until download completes.
  ERROR_MSG = '\tSlow Retrieval Attack was Successful!\n\n'

  # Launch the server.
  port = random.randint(30000, 45000)
  command = ['python', 'slow_retrieval_server.py', str(port)]
  server_process = subprocess.Popen(command, stdout=subprocess.PIPE,
                                             stderr=subprocess.PIPE)
  time.sleep(.1)

  try:
    # Setup.
    root_repo, url, server_proc, keyids = \
      util_test_tools.init_repo(tuf=TUF, port=port)
    reg_repo = os.path.join(root_repo, 'reg_repo')
    downloads = os.path.join(root_repo, 'downloads')
    
    # Add file to 'repo' directory: {root_repo}
    filepath = util_test_tools.add_file_to_repository(reg_repo, 'A'*10)
    file_basename = os.path.basename(filepath)
    url_to_file = url+'reg_repo/'+file_basename
    downloaded_file = os.path.join(downloads, file_basename)


    if TUF:
      print 'TUF ...'
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
    proc = Process(target=_download, args=(url_to_file, downloaded_file, TUF))
    proc.start()
    proc.join(WAIT_TIME)
    if proc.exitcode is None:
      proc.terminate()
      raise SlowRetrievalAttackAlert(ERROR_MSG)


  finally:
    if server_process.returncode is None:
      server_process.kill()
      print 'Slow server terminated.\n'

    util_test_tools.cleanup(root_repo, server_proc)





try:
  test_slow_retrieval_attack(TUF=False)
except SlowRetrievalAttackAlert, error:
  print error


try:
  test_slow_retrieval_attack(TUF=True)
except SlowRetrievalAttackAlert, error:
  print error
