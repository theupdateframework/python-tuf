#!/usr/bin/env python

"""
<Program Name>
  test_replay_attack.py

<Author>
  Konstantin Andrianov

<Started>
  February 22, 2012

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Simulate a replay attack.  A simple client update vs. client update 
  implementing TUF.

  In the replay attack an attacker is able to trick clients into installing
  software that is older than that which the client previously knew to be
  available.

  NOTE: The interposition provided by 'tuf.interposition' is used to intercept
  all calls made by urllib/urillib2 to certain hostname specified in 
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

import tuf.interposition
import tuf.tests.util_test_tools as util_test_tools


class TestSetupError(Exception): pass
class ReplayAttackAlert(Exception): pass


def _download(url, filename, using_tuf=False):
  if using_tuf:
    tuf.interposition.urllib_tuf.urlretrieve(url, filename)
    
  else:
    urllib.urlretrieve(url, filename)





def test_replay_attack(using_tuf=False):
  """
  <Arguments>
    using_tuf:
      If set to 'False' all directories that start with 'tuf_' are ignored, 
      indicating that tuf is not implemented.

  <Purpose>
    Illustrate replay attack vulnerability.

  """

  ERROR_MSG = '\tReplay Attack was Successful!\n\n'
  FIRST_CONTENT = 'Test A'
  SECOND_CONTENT = 'Test B'

  try:
    # Setup.
    root_repo, url, server_proc, keyids = \
      util_test_tools.init_repo(using_tuf=using_tuf)
    reg_repo = os.path.join(root_repo, 'reg_repo')
    tuf_repo = os.path.join(root_repo, 'tuf_repo')
    tuf_repo_copy = os.path.join(root_repo, 'tuf_repo_copy')
    downloads = os.path.join(root_repo, 'downloads')
    tuf_targets = os.path.join(tuf_repo, 'targets')

    # Add file to 'repo' directory: {root_repo}
    filepath = util_test_tools.add_file_to_repository(reg_repo, FIRST_CONTENT)
    file_basename = os.path.basename(filepath)
    url_to_repo = url+'reg_repo/'+file_basename
    downloaded_file = os.path.join(downloads, file_basename)

    # Attacker saves the original file into 'evil_dir'.
    evil_dir = tempfile.mkdtemp(dir=root_repo)
    original_file = os.path.join(evil_dir, file_basename)
    shutil.copy(filepath, evil_dir)

    if using_tuf:
      # Update TUF metadata before attacker modifies anything.
      util_test_tools.tuf_refresh_repo(root_repo, keyids)
      # Copy the first version of the repository for replay later.
      shutil.copytree(tuf_repo, tuf_repo_copy)

      # Modify the url.  Remember that the interposition will intercept 
      # urls that have 'localhost:9999' hostname, which was specified in
      # the json interposition configuration file.  Look for 'hostname'
      # in 'util_test_tools.py'. Further, the 'file_basename' is the target
      # path relative to 'targets_dir'. 
      url_to_repo = 'http://localhost:9999/'+file_basename
    # End of Setup.

    # Client performs initial update.
    _download(url=url_to_repo, filename=downloaded_file, using_tuf=using_tuf)

    # Downloads are stored in the same directory '{root_repo}/downloads/'
    # for regular and tuf clients.
    downloaded_content = util_test_tools.read_file_content(downloaded_file)
    if FIRST_CONTENT != downloaded_content:
      raise TestSetupError('[Initial Update] Failed to download the file.')

    # Developer patches the file and updates the repository.
    util_test_tools.modify_file_at_repository(filepath, SECOND_CONTENT)

    # Updating tuf repository.  This will copy files from regular repository
    # into tuf repository and refresh the metadata
    if using_tuf:
      util_test_tools.tuf_refresh_repo(root_repo, keyids)

    # Client downloads the patched file.
    _download(url=url_to_repo, filename=downloaded_file, using_tuf=using_tuf)

    # Content of the downloaded file.
    downloaded_content = util_test_tools.read_file_content(downloaded_file)
    if SECOND_CONTENT != downloaded_content:
      raise TestSetupError('[Update] Failed to update the file.')

    # Attacker tries to be clever, he manages to modifies regular and tuf 
    # targets directory by replacing a patched file with an old one.
    if using_tuf:
      # Delete the current TUF repository...
      shutil.rmtree(tuf_repo)
      # ...and replace it with a previous copy.
      shutil.move(tuf_repo_copy, tuf_repo)
    else:
      # Delete the current file...
      util_test_tools.delete_file_at_repository(filepath)
      # ...and replace it with a previous copy.
      shutil.copy(original_file, reg_repo)

    try:
      # Client downloads the file once more.
      _download(url=url_to_repo, filename=downloaded_file, using_tuf=using_tuf)
    except tuf.NoWorkingMirrorError, exception:
      replayed_metadata_attack = False

      for mirror_url, mirror_error in exception.mirror_errors.iteritems():
        if isinstance(mirror_error, tuf.ReplayedMetadataError):
          replayed_metadata_attack = True
          break

      # In case we did not detect what was likely a replayed metadata attack,
      # we reraise the exception to indicate that replayed metadata attack
      # detection failed.
      if not replayed_metadata_attack: raise
    else:
      # Check whether the attack succeeded by inspecting the content of the
      # update.  The update should contain 'Test NOT A'.
      downloaded_content = util_test_tools.read_file_content(downloaded_file)
      # If we ended up downloading replayed content, then we failed.
      if FIRST_CONTENT == downloaded_content:
        raise ReplayAttackAlert(ERROR_MSG)

  finally:
    util_test_tools.cleanup(root_repo, server_proc)





try:
  test_replay_attack(using_tuf=False)
except ReplayAttackAlert, exception:
  print('Download without TUF fell prey to replayed metadata attack.')

  try:
    test_replay_attack(using_tuf=True)
  except ReplayAttackAlert, exception:
    print('Download with TUF fell prey to replayed metadata attack!')
  except Exception, exception:
    print('Download with TUF failed due to: '+str(exception))
  else:
    print('Download with TUF defended against replayed metadata attack.')
except Exception, exception:
  print('Download without TUF failed due to: '+str(exception))
else:
  print('Download without TUF did NOT fail due to replayed metadata attack!')
