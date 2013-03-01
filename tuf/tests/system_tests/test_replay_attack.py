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


Note: There is no difference between 'updates' and 'target' files.
Note: If TUF is implemented - you would NOT use urllib like it's done here
for the testing purposes. TUF handles the downloads.

"""

import os
import shutil
import urllib
import tempfile
import util_test_tools



def test_replay_attack(tuf=False):
  """
  <Arguments>
    tuf:
      If set to 'False' all directories that start with 'tuf_' are ignored, 
      indicating that tuf is not implemented.

  <Purpose>
    Illustrate replay attack vulnerability.

  """

  # Setup.
  temp_root, url = util_test_tools.init_repo(tuf=tuf)
  repo = os.path.join(temp_root, 'repo')
  tuf_repo = os.path.join(temp_root, 'tuf_repo')
  downloads =os.path.join(temp_root, 'downloads')

  # Add file to 'repo' directory: {temp_root}
  filepath = util_test_tools.add_file_to_repository('Test A')
  file_basename = os.path.basename(filepath)
  url_to_repo = url+'repo/'+file_basename
  downloaded_file = os.path.join(downloads, file_basename)


  # Client performs initial update.
  if tuf:
    util_test_tools.tuf_refresh_and_download()
  else:
    urllib.urlretrieve(url_to_repo, downloaded_file)

  # Content of the downloaded file.
  # Downloads are stored in the same directory '{temp_root}/downloads/'
  # independent of who stores there (tuf or regular client).  See warning
  # in util_test_tools.init_repo().
  downloaded_content = util_test_tools.read_file_content(downloaded_file)
  msg = '[Initial Updata] Failed to download the file.'
  assert 'Test A' == downloaded_content, msg


  # Attacker finds a vulnerability in the file.
  evil_dir = tempfile.mkdtemp(dir=temp_root)
  vulnerable_file = os.path.join(evil_dir, file_basename)
  urllib.urlretrieve(url_to_repo, vulnerable_file)

  # Developer patches the file and updates the repository.
  util_test_tools.modify_file_at_repository(filepath, 'Test NOT A')


  # Client downloads the patched file.
  if tuf:
    util_test_tools.tuf_refresh_and_download()
  else:
    urllib.urlretrieve(url_to_repo, downloaded_file)

  # Content of the downloaded file.
  downloaded_content = util_test_tools.read_file_content(downloaded_file)
  msg = '[Updata] Failed to update the file.'
  assert 'Test NOT A' == downloaded_content, msg


  # Attacker tries to be clever, he manages to modifies tuf targets directory
  # by replacing a patched file with an old one.
  #
  # Since we don't really have any restriction where regular download 
  # retrieves the files from, this works fine.  On the other hand, when
  # tuf is used this will guarantee that tuf-client will be retrieving the
  # attacker's file.  This happens, because mirror's list is pointing to
  # the tuf repository.
  #
  # If tuf is False none of the tuf directories are created, but attacker
  # needs tuf targets directory in order to be able to attack both tuf and
  # non-tuf clients.  For this purpose he creates an artificial tuf targets
  # directory (Remember: the tuf is not setup at this point!).  
  targets_dir = os.path.join(tuf_repo, 'targets')
  if not os.path.isdir(targets_dir):
    os.makedirs(targets_dir)
  shutil.copy(vulnerable_file, targets_dir)
  url_to_tuf = url+'tuf_repo/targets/'+file_basename

  # Verify that 'target' is an old, un-patched file.
  target = os.path.join(targets_dir, file_basename)
  target_content = util_test_tools.read_file_content(target)
  msg = 'The \'target\' file contains new data!'
  assert 'Test A' == target_content, msg


  # Client downloads the file once time.
  if tuf:
    util_test_tools.tuf_refresh_and_download()
  else:
    urllib.urlretrieve(url_to_tuf, downloaded_file)

  # Check whether the attack succeeded by inspecting the content of the
  # update.  The update should contain 'Test NOT A'.
  downloaded_content = util_test_tools.read_file_content(downloaded_file)
  msg = 'Replay attack was successful!\n'
  assert 'Test NOT A' == downloaded_content, msg





try:
  test_replay_attack(tuf=False)
except AssertionError, e:
  print 'Expected Failure: '+repr(e)
else:
  print 'Unexpected Failure!'
finally:
  util_test_tools.cleanup()


try:
  test_replay_attack(tuf=True)
except AssertionError, e:
  print 'Unexpected Failure: '+repr(e)
else:
  print 'Expected Success!'
finally:
  util_test_tools.cleanup()