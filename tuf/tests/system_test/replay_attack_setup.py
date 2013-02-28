"""
<Program Name>
  replay_attack_setup.py

<Author>
  Konstantin Andrianov

<Started>
  February 22, 2012

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  A helper module that provides a method that simulates a replay
  attack.Simulate a replay attack. 

"""

import os
import shutil
import tempfile
import test_system_setup as setup



def _tuf_update_meta_and_download_files(target):
  """
  Client performs metadata update and downloads the files.
  Method returns file content of the 'target'.
  'target' should be a dictionary key from main rapository i.e.
  one of setup['repo']['repo_files'] elements.
  """
  setup.tuf_client_refresh_metadata()
  setup.tuf_client_download_updates()
  filename = setup.setup_info['repo'][target][0]
  targetpath = os.path.join(setup.setup_info['dest_path'], filename)
  msg = '[TUF] Failed to download files.'
  assert os.path.exists(targetpath), msg
  return setup.read_file_content(targetpath)





def replay_attack():
  """
  <Purpose>
    Illustrate replay attack vulnerability.

  """

  # try block is used here to remove temporary files.
  try:

    # Internal setup.
    repo_files = setup.setup_info['repo']['repo_files']

    # Attacker saves on of the initial file, in which he found a voulnerability.
    evil_dir = tempfile.mkdtemp(prefix='evil_', dir=os.getcwd())
    shutil.copy(setup.setup_info['repo'][repo_files[0]][1], evil_dir)

    # Client performs initial updates.
    if setup.setup_info['tuf']:
      downloaded_file_content = _tuf_update_meta_and_download_files(repo_files[0])
    else:
      downloaded_file_content = setup.client_download(repo_files[0])

    # Content of the file at the repository.
    file_content_at_repo = \
      setup.read_file_content(setup.setup_info['repo'][repo_files[0]][1])
    msg = '[Initial Updata] Failed to download the file.'
    assert file_content_at_repo == downloaded_file_content, msg

    # Developer patches 'repo_files[0]' file and updates the repository.
    new_data = 'NewData'
    setup.add_or_change_file_at_repository(repo_file=repo_files[0], data=new_data)
    if setup.setup_info['tuf']:
      # If TUF is implemented, the developer needs to refresh tuf repository.
      setup.refresh_tuf_repository()

    # Client downloads the patched file.
    if setup.setup_info['tuf']:
      downloaded_file_content = _tuf_update_meta_and_download_files(repo_files[0])
    else:
      downloaded_file_content = setup.client_download(repo_files[0])
    msg = '[Updata] Failed to update the file.'
    assert new_data == downloaded_file_content, msg

    # Attacker tries to be clever, redirects clients to his repo.
    rel_evil_dir = os.path.basename(evil_dir)
    setup.setup_info['url'] = \
      'http://localhost:'+str(setup.setup_info['port'])+'/'+rel_evil_dir+'/'

  # Client downloads the updated file 'repo_files[0]' one more time.
    if setup.setup_info['tuf']:
      downloaded_file_content = _tuf_update_meta_and_download_files(repo_files[0])
    else:
      downloaded_file_content = setup.client_download(repo_files[0])

    # Check whether the attack succeeded by inspecting the content of the
    # update.  The update should contain 'new_data'.
    msg = 'Replay attack was succeeded!\n'
    assert new_data == downloaded_file_content, msg

  finally:
    shutil.rmtree(evil_dir)