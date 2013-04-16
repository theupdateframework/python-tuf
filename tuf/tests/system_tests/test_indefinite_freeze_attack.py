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

import os
import sys
import time
import shutil
import urllib
import tempfile
import util_test_tools

import tuf.formats
import tuf.repo.signerlib as signerlib
from tuf.interposition import urllib_tuf


# Disable logging.
util_test_tools.disable_logging()



class IndefiniteFreezeAttackAlert(Exception):
  pass



EXPIRATION = 1  # second(s)



def _remake_timestamp(metadata_dir, keyids):
  """Create timestamp metadata object.  Modify expiration date.  Sign and
  write the metadata.
  """
  release_filepath = os.path.join(metadata_dir, 'release.txt')
  timestamp_filepath = os.path.join(metadata_dir, 'timestamp.txt')
  timestamp_metadata = signerlib.generate_timestamp_metadata(release_filepath)
  timestamp_metadata['signed']['expires'] = \
    tuf.formats.format_time(time.time() + EXPIRATION)
  signable = \
    signerlib.sign_metadata(timestamp_metadata, keyids, timestamp_filepath)
  signerlib.write_metadata_file(signable, timestamp_filepath)



def _download(url, filename, tuf=False):
  if tuf:
    urllib_tuf.urlretrieve(url, filename)
    
  else:
    urllib.urlretrieve(url, filename)





def test_indefinite_freeze_attack(TUF=False):
  """
  <Arguments>
    TUF:
      If set to 'False' all directories that start with 'tuf_' are ignored, 
      indicating that tuf is not implemented.

  The idea here is to expire timestamp metadata so that the attacker 

  """

  ERROR_MSG = '\tIndefinite Freeze Attack was Successful!\n\n'


  try:
    # Setup.
    root_repo, url, server_proc, keyids = util_test_tools.init_repo(tuf=TUF)
    reg_repo = os.path.join(root_repo, 'reg_repo')
    tuf_repo = os.path.join(root_repo, 'tuf_repo')
    metadata_dir = os.path.join(tuf_repo, 'metadata')
    downloads = os.path.join(root_repo, 'downloads')
    
    # Add file to 'repo' directory: {root_repo}
    filepath = util_test_tools.add_file_to_repository(reg_repo, 'Test A')
    file_basename = os.path.basename(filepath)
    url_to_repo = url+'reg_repo/'+file_basename
    downloaded_file = os.path.join(downloads, file_basename)

    if TUF:
      print 'TUF ...'

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


    # Client performs initial download.
    try:
      _download(url=url_to_repo, filename=downloaded_file, tuf=TUF)
    except tuf.ExpiredMetadataError:
      msg = ('Metadata has expired too soon, extend expiration period. '+
             'Current expiration is set to: '+repr(EXPIRATION)+' second(s).')
      sys.exit(msg)

    # Expire timestamp.
    time.sleep(EXPIRATION)

    # Try downloading again, this should raise an error.
    try:
      _download(url=url_to_repo, filename=downloaded_file, tuf=TUF)
    except tuf.ExpiredMetadataError, error:
      pass
    else:
      raise IndefiniteFreezeAttackAlert(ERROR_MSG)


  finally:
    util_test_tools.cleanup(root_repo, server_proc)





try:
  test_indefinite_freeze_attack(TUF=False)
except IndefiniteFreezeAttackAlert, error:
  print error


try:
  test_indefinite_freeze_attack(TUF=True)
except IndefiniteFreezeAttackAlert, error:
  print error