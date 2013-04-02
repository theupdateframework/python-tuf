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

Note: The interposition provided by 'tuf.interposition' is used to intercept
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

# TODO: implement slow retrieval server...  And design the test.
# Should there be a time bracket, during which the download is
# expected to happen? 

import os
import time
import urllib
import random
import subprocess
import util_test_tools

from tuf.interposition import urllib_tuf


# Disable logging.
util_test_tools.disable_logging()



class SlowRetrievalAttackAlert(Exception):
  pass


def download_using_urlopen(url, tuf=False):
  if tuf:
    return urllib_tuf.urlopen(url)
  else:
    return urllib.urlopen(url)



def test_slow_retrieval_attack(TUF=True):

  ERROR_MSG = '\tSlow Retrieval Attack was Successful!\n\n'

  # Launch the server.
  port = random.randint(30000, 45000)
  print port
  command = ['python', 'slow_retrieval_server.py', str(port)]
  server_process = subprocess.Popen(command, stderr=subprocess.PIPE)
  time.sleep(.1)

  try:
    # Setup.
    root_repo, url, server_proc, keyids = util_test_tools.init_repo(tuf=TUF, port=port)
    print 'root_repo: '+root_repo
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



    # Download the content of the file using the server.
    # NOTE: if TUF is enabled the metadata files will be downloaded first.  This
    # WILL take a long time.
    file_content = download_using_urlopen(url_to_file, tuf=TUF)

    print file_content.read()


  finally:
    if server_process.returncode is None:
      server_process.kill()
      print 'Slow server terminated.\n'

    util_test_tools.cleanup(root_repo, server_proc)


test_slow_retrieval_attack()