"""
<Program Name>
  test_indefinite_freeze_attack.py

<Author>
  Konstantin Andrianov

<Started>
  March 10, 2012

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Simulate an indefinite freeze attack.

  In an indefinite freeze attack, attacker is able to respond to client's
  requests with the same, outdated metadata without the client being aware.

"""

# Help with Python 3 compatability, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division

import os
import sys
import time
import shutil
import urllib
import tempfile

import tuf
import tuf.formats
import tuf.interposition
import tuf.repo.signerlib as signerlib
import tuf.tests.util_test_tools as util_test_tools


class IndefiniteFreezeAttackAlert(Exception):
  pass


EXPIRATION = 1  # second(s)
version = 1


def _remake_timestamp(metadata_dir, keyids):
  """Create timestamp metadata object.  Modify expiration date.  Sign and
  write the metadata.
  """
  
  global version
  version = version+1
  expiration_date = tuf.formats.format_time(time.time()+EXPIRATION)
  
  release_filepath = os.path.join(metadata_dir, 'release.txt')
  timestamp_filepath = os.path.join(metadata_dir, 'timestamp.txt')
  timestamp_metadata = signerlib.generate_timestamp_metadata(release_filepath,
                                                             version,
                                                             expiration_date)
  signable = \
    signerlib.sign_metadata(timestamp_metadata, keyids, timestamp_filepath)
  signerlib.write_metadata_file(signable, timestamp_filepath)



def _download(url, filename, using_tuf=False):
  if using_tuf:
    tuf.interposition.urllib_tuf.urlretrieve(url, filename)
    
  else:
    urllib.urlretrieve(url, filename)





def test_indefinite_freeze_attack(using_tuf=False):
  """
  <Arguments>
    using_tuf:
      If set to 'False' all directories that start with 'tuf_' are ignored, 
      indicating that tuf is not implemented.

  The idea here is to expire timestamp metadata so that the attacker 

  """

  ERROR_MSG = '\tIndefinite Freeze Attack was Successful!\n\n'


  try:
    # Setup.
    root_repo, url, server_proc, keyids = util_test_tools.init_repo(using_tuf)
    reg_repo = os.path.join(root_repo, 'reg_repo')
    tuf_repo = os.path.join(root_repo, 'tuf_repo')
    metadata_dir = os.path.join(tuf_repo, 'metadata')
    downloads = os.path.join(root_repo, 'downloads')
    
    # Add file to 'repo' directory: {root_repo}
    filepath = util_test_tools.add_file_to_repository(reg_repo, 'Test A')
    file_basename = os.path.basename(filepath)
    url_to_repo = url+'reg_repo/'+file_basename
    downloaded_file = os.path.join(downloads, file_basename)

    if using_tuf:
      print('TUF ...')

      # Update TUF metadata before attacker modifies anything.
      util_test_tools.tuf_refresh_repo(root_repo, keyids)

      # Modify the url.  Remember that the interposition will intercept 
      # urls that have 'localhost:9999' hostname, which was specified in
      # the json interposition configuration file.  Look for 'hostname'
      # in 'util_test_tools.py'. Further, the 'file_basename' is the target
      # path relative to 'targets_dir'. 
      url_to_repo = 'http://localhost:9999/'+file_basename

      # Make timestamp metadata with close expiration date (2s).
      _remake_timestamp(metadata_dir, keyids)


    # Client performs initial download. If the computer is slow, it may
    # take longer time than expiration time. In this case you will see
    # an ExpiredMetadataError.
    try:
      _download(url_to_repo, downloaded_file, using_tuf)
    except:
      print('Initial download failed! It may be because your machine is '+ \
        'busy. Try again later.')
    else:
      # Expire timestamp.
      time.sleep(EXPIRATION)

      # Try downloading again, this should raise an error.
      try:
        _download(url_to_repo, downloaded_file, using_tuf)
      except tuf.ExpiredMetadataError, error:
        print('Caught an expiration error!')
      else:
        raise IndefiniteFreezeAttackAlert(ERROR_MSG)
  finally:
    util_test_tools.cleanup(root_repo, server_proc)





try:
  test_indefinite_freeze_attack(using_tuf=False)
except IndefiniteFreezeAttackAlert, error:
  print(error)


try:
  test_indefinite_freeze_attack(using_tuf=True)
except IndefiniteFreezeAttackAlert, error:
  print(error)
