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

"""

import os
import shutil
import urllib
import tempfile
import util_test_tools

import tuf.interposition


class TestSetupError(Exception):
  pass

class ReplayAttackError(Exception):
  pass


def test_replay_attack(TUF=False):
  """
  <Arguments>
    TUF:
      If set to 'False' all directories that start with 'tuf_' are ignored, 
      indicating that tuf is not implemented.

  <Purpose>
    Illustrate replay attack vulnerability.

  """

  try:
    # Setup.
    root_repo, url, server_proc, keyids, interpose_json = \
      util_test_tools.init_repo(tuf=TUF)
    reg_repo = os.path.join(root_repo, 'reg_repo')
    tuf_repo = os.path.join(root_repo, 'tuf_repo')
    downloads = os.path.join(root_repo, 'downloads')
    tuf_targets = os.path.join(tuf_repo, 'targets')

    # Add file to 'repo' directory: {root_repo}
    filepath = util_test_tools.add_file_to_repository(reg_repo, 'Test A')
    file_basename = os.path.basename(filepath)
    url_to_repo = url+'reg_repo/'+file_basename
    downloaded_file = os.path.join(downloads, file_basename)

    # Attacker saves the original file into 'evil_dir'.
    evil_dir = tempfile.mkdtemp(dir=root_repo)
    vulnerable_file = os.path.join(evil_dir, file_basename)
    shutil.copy(filepath, evil_dir)

    # Refresh the tuf repository and apply tuf interpose.
    if TUF:
      util_test_tools.tuf_refresh_repo(root_repo, keyids)
      tuf.interposition.configure(interpose_json)
      tuf.interposition.interpose()

    # End Setup.

    # Client performs initial update.
    urllib.urlretrieve(url_to_repo, downloaded_file)

    # Downloads are stored in the same directory '{root_repo}/downloads/'
    # for regular and tuf clients.
    downloaded_content = util_test_tools.read_file_content(downloaded_file)
    msg = '[Initial Updata] Failed to download the file.'
    if 'Test A' != downloaded_content:
      raise TestSetupError(msg)

    # Developer patches the file and updates the repository.
    util_test_tools.modify_file_at_repository(filepath, 'Test NOT A')

    # Updating tuf repository.  This will copy files from regular repository
    # into tuf repository and refresh the metad 
    if TUF:
      util_test_tools.tuf_refresh_repo(root_repo, keyids)

    # Client downloads the patched file.
    urllib.urlretrieve(url_to_repo, downloaded_file)

    # Content of the downloaded file.
    downloaded_content = util_test_tools.read_file_content(downloaded_file)
    msg = '[Update] Failed to update the file.'
    if 'Test NOT A' != downloaded_content:
      raise TestSetupError(msg)

    # Attacker tries to be clever, he manages to modifies regular and tuf 
    # targets directory by replacing a patched file with an old one.
    if os.path.isdir(tuf_targets):
      target = os.path.join(tuf_targets, file_basename)
      util_test_tools.delete_file_at_repository(target)
      shutil.copy(vulnerable_file, tuf_targets)
      # Verify that 'target' is an old, un-patched file.
      target = os.path.join(tuf_targets, file_basename)
      target_content = util_test_tools.read_file_content(target)
      msg = "The 'target' file contains new data!"
      if 'Test A' != target_content:
        raise TestSetupError(msg)
    else:
      util_test_tools.delete_file_at_repository(filepath)
      shutil.copy(vulnerable_file, reg_repo)

    # Client downloads the file once time.
    urllib.urlretrieve(url_to_repo, downloaded_file)

    # Check whether the attack succeeded by inspecting the content of the
    # update.  The update should contain 'Test NOT A'.
    downloaded_content = util_test_tools.read_file_content(downloaded_file)
    msg = 'Replay attack was successful!\n'
    if 'Test NOT A' != downloaded_content:
      raise ReplayAttackError(msg)

  finally:
    tuf.interposition.go_away()
    util_test_tools.cleanup(root_repo, server_proc)





try:
  test_replay_attack(TUF=False)
except ReplayAttackError, error:
  print error

try:
  test_replay_attack(TUF=True)
except ReplayAttackError, error:
  print error