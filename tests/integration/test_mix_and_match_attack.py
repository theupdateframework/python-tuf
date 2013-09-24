"""
<Program Name>
  test_mix_and_match_attack.py

<Author>
  Konstantin Andrianov

<Started>
  March 27, 2012

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Simulate slow retrieval attack.  A simple client update vs. client
  update implementing TUF.

  In the mix-and-match attack, attacker is able to trick clients into using
  combination of metadata that never existed together on the repository at
  the same time.

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

import os
import shutil
import urllib
import tempfile
import time

import tuf
import tuf.interposition
import tuf.tests.util_test_tools as util_test_tools


class MixAndMatchAttackAlert(Exception):
  pass


def _download(url, filename, using_tuf=False):
  if using_tuf:
    tuf.interposition.urllib_tuf.urlretrieve(url, filename)
    
  else:
    urllib.urlretrieve(url, filename)



def test_mix_and_match_attack(using_tuf=False):
  """
  Attack design:
    There are 3 stages:
      Stage 1: Consists of a usual mode of operations using tuf.  Client 
      downloads a target file. (Initial download)

      Stage 2: The target file is legitimately modified and metadata correctly
      updated.  Client downloads the target file again. (Patched target download)

      Stage 3: The target file is legitimately modified  and metadata correctly
      updated again.  However, before client gets to download the newly patched
      target file the attacker replaces the release metadata, targets metadata
      and the target file with the ones from stage 1 (mix-and-match attack).
      Note that timestamp metadata is untouched.  Further note that same would
      happen if only target metadata, and target file are reverted.
  """

  ERROR_MSG = '\tMix-And-Match Attack was Successful!\n\n'


  try:
    # Setup / Stage 1
    # ---------------
    root_repo, url, server_proc, keyids = util_test_tools.init_repo(using_tuf)
    reg_repo = os.path.join(root_repo, 'reg_repo')
    downloads = os.path.join(root_repo, 'downloads')
    evil_dir = tempfile.mkdtemp(dir=root_repo)
    
    # Add file to 'repo' directory: {root_repo}
    filepath = util_test_tools.add_file_to_repository(reg_repo, 'A'*10)
    file_basename = os.path.basename(filepath)
    url_to_file = url+'reg_repo/'+file_basename
    downloaded_file = os.path.join(downloads, file_basename)

    # Attacker saves the initial file.
    shutil.copy(filepath, evil_dir)
    unpatched_file = os.path.join(evil_dir, file_basename)


    if using_tuf:
      print('TUF ...')
      tuf_repo = os.path.join(root_repo, 'tuf_repo')
      tuf_targets = os.path.join(tuf_repo, 'targets')
      metadata_dir = os.path.join(tuf_repo, 'metadata')
      release_meta_file = os.path.join(metadata_dir, 'release.txt')
      targets_meta_file = os.path.join(metadata_dir, 'targets.txt')
      target = os.path.join(tuf_targets, file_basename)
      
      # Update TUF metadata before attacker modifies anything.
      util_test_tools.tuf_refresh_repo(root_repo, keyids)

      # Attacker saves the original metadata and the target file.
      #shutil.copy(target, evil_dir)
      shutil.copy(release_meta_file, evil_dir)
      shutil.copy(targets_meta_file, evil_dir)
      #target_old = os.path.join(evil_dir, file_basename)
      release_meta_file_old = os.path.join(evil_dir, 'release.txt')
      targets_meta_file_old = os.path.join(evil_dir, 'targets.txt')

      # Modify the url.  Remember that the interposition will intercept 
      # urls that have 'localhost:9999' hostname, which was specified in
      # the json interposition configuration file.  Look for 'hostname'
      # in 'util_test_tools.py'. Further, the 'file_basename' is the target
      # path relative to 'targets_dir'. 
      url_to_file = 'http://localhost:9999/'+file_basename


    # Wait for some time to let program set up local http server
    time.sleep(1)
    # Client's initial download.
    _download(url_to_file, downloaded_file, using_tuf)

    # Stage 2
    # -------
    # Developer patches the file and updates the repository.
    util_test_tools.modify_file_at_repository(filepath, 'B'*11)

    # Updating tuf repository.  This will copy files from regular repository
    # into tuf repository and refresh the metadata
    if using_tuf:
      util_test_tools.tuf_refresh_repo(root_repo, keyids)

    # Client downloads the patched file.
    _download(url_to_file, downloaded_file, using_tuf)

    downloaded_content = util_test_tools.read_file_content(downloaded_file)

    # Stage 3
    # -------
    # Developer patches the file and updates the repository again.
    util_test_tools.modify_file_at_repository(filepath, 'C'*10)

    # Updating tuf repository.  This will copy files from regular repository
    # into tuf repository and refresh the metadata
    if using_tuf:
      util_test_tools.tuf_refresh_repo(root_repo, keyids)

      # Attacker replaces the metadata and the target file.
      shutil.copyfile(unpatched_file, target)
      shutil.copyfile(release_meta_file_old, release_meta_file)
      shutil.copyfile(targets_meta_file_old, targets_meta_file)

    # Attacker replaces the patched file with the unpatched one.
    shutil.copyfile(unpatched_file, filepath)

    # Client tries to downloads the newly patched file.
    try:
      _download(url_to_file, downloaded_file, using_tuf)
    except tuf.NoWorkingMirrorError as errors:
      for mirror_url, mirror_error in errors.mirror_errors.iteritems():
        if type(mirror_error) == tuf.BadHashError:
          print('Caught a Bad Hash Error!')

    # Check whether the attack succeeded by inspecting the content of the
    # update.  The update should contain 'Test NOT A'.
    downloaded_content = util_test_tools.read_file_content(downloaded_file)
    if ('B'*11) != downloaded_content:
      raise MixAndMatchAttackAlert(ERROR_MSG)


  finally:
    util_test_tools.cleanup(root_repo, server_proc)





try:
  test_mix_and_match_attack(using_tuf=False)
except MixAndMatchAttackAlert, error:
  print(error)


try:
  test_mix_and_match_attack(using_tuf=True)
except MixAndMatchAttackAlert, error:
  print(error)
