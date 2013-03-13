"""
<Program Name>
  test_extraneous_dependencies_attack.py

<Author>
  Konstantin Andrianov

<Started>
  February 19, 2012

<Copyright>
  See LICENSE for licensing information.

<Purpose>

<Plan>
  1) Create a delegation role.
  2) Make sure a client is able to download changes made by a delegation role.
  3) Make sure a client is unable to download changes made by a delegation to
     to parts of repository that he has no authority over.

"""

import os
import sys
import urllib
import tempfile

import util_test_tools
import tuf.repo.signerlib as signerlib
import tuf.repo.signercli as signercli
from tuf.interposition import urllib_tuf


# Disable logging.
util_test_tools.disable_logging()


def create_delegation(tuf_repo, delegated_targets_path, keyid, keyid_password,
                      parent_role, new_role_name):
  keystore_dir = os.path.join(tuf_repo, 'keystore')
  metadata_dir = os.path.join(tuf_repo, 'metadata')

  #  Create method to patch signercli._get_metadata_directory()
  def _mock_get_meta_dir(directory=metadata_dir):
    return directory


  #  Mock method for signercli._prompt().
  def _mock_prompt(msg, junk, targets_path=delegated_targets_path,
                  parent_role=parent_role, new_role_name=new_role_name):
    if msg.startswith('\nThe directory entered'):
      return targets_path
    elif msg.startswith('\nChoose and enter the parent'):
      return parent_role
    elif msg.endswith('\nEnter the delegated role\'s name: '):
      return new_role_name
    else:
      error_msg = ('Prompt: '+'\''+msg+'\''+
                   ' did not match any predefined mock prompts.')
      sys.exit(error_msg)


  #  Mock method for signercli._get_password().
  def _mock_get_password(msg, keyid=keyid, password=keyid_password):
    _keyid = keyid[0]
    if msg.endswith('('+_keyid+'): '):
      return keyid_password
    else:
      return 'test'  # password for targets' keyid.


  #  Method to patch signercli._get_keyids()
  def _mock_get_keyid(junk, keyid=keyid):
    return keyid


  #  Patch signercli._get_metadata_directory()
  signercli._get_metadata_directory = _mock_get_meta_dir

  #  Patch signercli._prompt().
  signercli._prompt = _mock_prompt

  #  Patch signercli._get_password().
  signercli._get_password = _mock_get_password

  #  Patch signercli._get_keyids().
  signercli._get_keyids = _mock_get_keyid

  signercli.make_delegation(keystore_dir)






def test():

  try:

    # Setup.
    root_repo, url, server_proc, keyids = util_test_tools.init_repo(tuf=True)
    reg_repo = os.path.join(root_repo, 'reg_repo')
    tuf_repo = os.path.join(root_repo, 'tuf_repo')
    keystore_dir = os.path.join(tuf_repo, 'keystore')
    metadata_dir = os.path.join(tuf_repo, 'metadata')
    downloads_dir = os.path.join(root_repo, 'downloads')
    targets_dir = os.path.join(tuf_repo, 'targets')

    # Add files to 'reg_repo' directory: {root_repo}
    role1_path = tempfile.mkdtemp(dir=reg_repo)
    filepath_1 = util_test_tools.add_file_to_repository(role1_path, 'Test A')

    # Update TUF repository.
    util_test_tools.make_targets_meta(root_repo)
    util_test_tools.make_release_meta(root_repo)
    util_test_tools.make_timestamp_meta(root_repo)

    # Indicate which file client downloads.
    rel_filepath_1 = os.path.relpath(filepath_1, reg_repo)
    url_to_file = url+'reg_repo/'+rel_filepath_1
    target_1 = os.path.join(targets_dir, rel_filepath_1)
    junk, role1_relpath = os.path.split(role1_path)
    delegated_targets_path = os.path.join(targets_dir, role1_relpath)
    delegated_role_metadata_dir = os.path.join(metadata_dir, 'targets')

    # Create a key to sign a new delegated role.
    key = signerlib.generate_and_save_rsa_key(keystore_dir, 'pass1')
    delegated_targets_keyids = [key['keyid']]
    downloaded_file = os.path.join(downloads_dir, os.path.basename(filepath_1))

    # Create a delegation.
    create_delegation(tuf_repo, delegated_targets_path, delegated_targets_keyids,
                      'pass1', 'targets', 'role1')

    # Update TUF repository.
    util_test_tools.make_targets_meta(root_repo)
    util_test_tools.make_release_meta(root_repo)
    util_test_tools.make_timestamp_meta(root_repo)

    # END Setup.


    # Perform a client download.
    urllib_tuf.urlretrieve(url_to_file, downloaded_file)

    # The update should contain 'Test NOT A'.
    downloaded_content = util_test_tools.read_file_content(downloaded_file)
    msg = 'OUCH 1'
    if 'Test A' != downloaded_content:
      print msg


    # Modify a target that was delegated to 'role1'.
    util_test_tools.modify_file_at_repository(target_1, 'Test NOT A')

    # This is not correct!!!???
    # TODO: Use signercli's make_release_file() and make_timestamp().
    #util_test_tools.tuf_refresh_release_timestamp(metadata_dir, keyids)

    #  util_test_tools.tuf_refresh_repo(root_repo, keyids)

    # Rebuild the delegation role metadata.
    signerlib.build_delegated_role_file(delegated_targets_path, 
                                        delegated_targets_keyids, metadata_dir,
                                        delegated_role_metadata_dir, 'role1.txt')

    # Update release and timestamp metadata.
    util_test_tools.make_release_meta(root_repo)
    util_test_tools.make_timestamp_meta(root_repo)

    # Perform another client download.
    urllib.urlretrieve(url_to_file, downloaded_file)

    # The update should contain 'Test NOT A'.
    downloaded_content = util_test_tools.read_file_content(downloaded_file)
    msg = 'OUCH 2'
    if 'Test NOT A' != downloaded_content:
      print 'Test NOT A != '+downloaded_content
      print msg


  finally:  
    # NOTE: temporary files are created and NOT removed at this point.  This
    # is done in order to investigate the structure manually.
    # TODO: use cleanup()!
    server_proc.kill()
  
    print 'Done.'




test()