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

Note: There is no difference between 'updates' and 'target' files.

"""


import os
import shutil
import urllib
import tempfile

import util_test_tools
from tuf.interposition import urllib_tuf


# Disable logging.
util_test_tools.disable_logging()



class MixAndMatchAttackAlert(Exception):
  pass


def _download(url, filename, tuf=False):
  if tuf:
    urllib_tuf.urlretrieve(url, filename)
    
  else:
    urllib.urlretrieve(url, filename)



def test_mix_and_match_attack(TUF=False):
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
    root_repo, url, server_proc, keyids = util_test_tools.init_repo(tuf=TUF)
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


    if TUF:
      print 'TUF ...'
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


    # Client's initial download.
    _download(url=url_to_file, filename=downloaded_file, tuf=TUF)

    # Stage 2
    # -------
    # Developer patches the file and updates the repository.
    util_test_tools.modify_file_at_repository(filepath, 'B'*11)

    # Updating tuf repository.  This will copy files from regular repository
    # into tuf repository and refresh the metadata
    if TUF:
      util_test_tools.tuf_refresh_repo(root_repo, keyids)

    # Client downloads the patched file.
    _download(url=url_to_file, filename=downloaded_file, tuf=TUF)

    downloaded_content = util_test_tools.read_file_content(downloaded_file)
    print downloaded_content

    # Stage 3
    # -------
    # Developer patches the file and updates the repository again.
    util_test_tools.modify_file_at_repository(filepath, 'C'*10)

    # Updating tuf repository.  This will copy files from regular repository
    # into tuf repository and refresh the metadata
    if TUF:
      util_test_tools.tuf_refresh_repo(root_repo, keyids)

      # Attacker replaces the metadata and the target file.
      shutil.copyfile(unpatched_file, target)
      shutil.copyfile(release_meta_file_old, release_meta_file)
      shutil.copyfile(targets_meta_file_old, targets_meta_file)

    # Attacker replaces the patched file with the unpatched one.
    shutil.copyfile(unpatched_file, filepath)

    # Client tries to downloads the newly patched file.
    _download(url=url_to_file, filename=downloaded_file, tuf=TUF)

    # Check whether the attack succeeded by inspecting the content of the
    # update.  The update should contain 'Test NOT A'.
    downloaded_content = util_test_tools.read_file_content(downloaded_file)
    if ('B'*10) != downloaded_content:
      print downloaded_content
      raise MixAndMatchAttackAlert(ERROR_MSG)


  finally:
  	pass
    #util_test_tools.cleanup(root_repo, server_proc)





try:
  test_mix_and_match_attack(TUF=False)
except MixAndMatchAttackAlert, error:
  print error


try:
  test_mix_and_match_attack(TUF=True)
except MixAndMatchAttackAlert, error:
  print error