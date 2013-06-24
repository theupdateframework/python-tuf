#!/usr/bin/env python

"""
<Program Name>
  test_delegations.py

<Author>
  Konstantin Andrianov

<Started>
  February 19, 2012

<Copyright>
  See LICENSE for licensing information.

<Purpose>


"""

import os
import sys
import tempfile
import time
import unittest
import urllib

import tuf.formats
from tuf.interposition import urllib_tuf
import tuf.repo.keystore as keystore
import tuf.repo.signercli as signercli
import tuf.repo.signerlib as signerlib
import util_test_tools


# Disable logging.
#util_test_tools.disable_logging()



def setup_tuf_repository():
  root_repo, url, server_proc, keyids = util_test_tools.init_repo(tuf=True)

  # Server side repository.
  tuf_repo = os.path.join(root_repo, 'tuf_repo')
  keystore_dir = os.path.join(tuf_repo, 'keystore')
  metadata_dir = os.path.join(tuf_repo, 'metadata')
  targets_dir = os.path.join(tuf_repo, 'targets')

  # Add files to the server side repository.
  # target1 = 'targets_dir/target1_rand.txt'
  # target2 = 'targets_dir/target2_rand.txt'
  # target3 = 'targets_dir/level1_rand/target3_rand.txt'
  # target4 = 'targets_dir/level1_rand/target4_rand.txt'
  # target5 = 'targets_dir/level1_rand/level2_rand/target5_rand.txt'
  # target6 = 'targets_dir/level1_rand/level2_rand/target6_rand.txt'
  add_target = util_test_tools.add_file_to_repository
  level1 = tempfile.mkdtemp(dir=targets_dir, prefix='level1_')
  level2 = tempfile.mkdtemp(dir=level1, prefix='level2_')
  target1_path = add_target(targets_dir, data='target1')
  target2_path = add_target(targets_dir, data='target2')
  target3_path = add_target(level1, data='target3')
  target4_path = add_target(level1, data='target4')
  target5_path = add_target(level2, data='target5')
  target6_path = add_target(level2, data='target6')
  
  # Target paths relative to the 'targets_dir'.
  # Ex: targetX = 'level1_rand/targetX_rand.txt'
  target1 = os.path.relpath(target1_path, tuf_repo)
  target2 = os.path.relpath(target2_path, tuf_repo)
  target3 = os.path.relpath(target3_path, tuf_repo)
  target4 = os.path.relpath(target4_path, tuf_repo)
  target5 = os.path.relpath(target5_path, tuf_repo)
  target6 = os.path.relpath(target6_path, tuf_repo)

  # Relative to repository's targets directory.
  target_filepaths = [target1, target2, target3, target4, target5, target6]

  # Tracked targets.
  targets_tracked_targets = [target1]
  delegatee1_tracked_targets = [target1, target4]
  delegatee2_tracked_targets = [target2, target4, target5]
  delegatee3_tracked_targets = [target3, target4, target5, target6]

  # Assigned targets.
  delegatee1_assigned_targets = [target1, target3, target4, target5, target6]
  delegatee2_assigned_targets = [target2, target3, target4, target5, target6]
  delegatee3_assigned_targets = [target3, target4, target5, target6]

  # Make delegation directories at the server's repository.
  metadata_targets_dir = os.path.join(metadata_dir, 'targets')
  metadata_delegatee1_dir = os.path.join(metadata_targets_dir, 'delegatee1')
  os.makedirs(metadata_delegatee1_dir)

  # Delegations metadata paths.
  delegatee1_path = os.path.join(metadata_targets_dir, 'delegatee1.txt')
  delegatee2_path = os.path.join(metadata_targets_dir, 'delegatee2.txt')
  delegatee3_path = os.path.join(metadata_delegatee1_dir, 'delegatee3.txt')

  # Generate delegation metadata.
  generate_meta = signerlib.generate_targets_metadata
  delegatee1 = generate_meta(tuf_repo, delegatee1_tracked_targets)
  delegatee2 = generate_meta(tuf_repo, delegatee2_tracked_targets)
  delegatee3 = generate_meta(tuf_repo, delegatee3_tracked_targets)

  # Generate a set of RSA keys that will be assigned to the delegatees.
  key1 = signerlib.generate_and_save_rsa_key(keystore_dir, 'delegatee1')
  key2 = signerlib.generate_and_save_rsa_key(keystore_dir, 'delegatee2')
  key3 = signerlib.generate_and_save_rsa_key(keystore_dir, 'delegatee3')

  def _relative_path_to_targets(target_filepaths):
    # Ex: 'targets/more_targets/somefile.txt' -> 'more_targets/somefile.txt'
    # i.e. 'targets/' is removed from 'target'.
    new_target_filepaths = []
    for target in target_filepaths:
      relative_targetpath = os.path.sep.join(target.split(os.path.sep)[1:])
      new_target_filepaths.append(relative_targetpath)
    return new_target_filepaths


  # Create delegatee role metadata in order to later create 'delegations'
  # object:
  delegatee1_role_meta = \
  tuf.formats.make_role_metadata([key1['keyid']], 1, name='targets/delegatee1',
                                paths=_relative_path_to_targets(delegatee1_assigned_targets))
  delegatee2_role_meta = \
  tuf.formats.make_role_metadata([key2['keyid']], 1, name='targets/delegatee2',
                                paths=_relative_path_to_targets(delegatee2_assigned_targets))
  delegatee3_role_meta = \
  tuf.formats.make_role_metadata([key3['keyid']], 1, name='targets/delegatee1/delegatee3',
                                paths=_relative_path_to_targets(delegatee3_assigned_targets))

  # Create 'delegations' object for targets metadata:
  targets_delegations = {}
  key1_val = tuf.rsa_key.create_in_metadata_format(key1['keyval'])
  key2_val = tuf.rsa_key.create_in_metadata_format(key2['keyval'])
  targets_delegations['keys'] = {key1['keyid']:key1_val,
                                 key2['keyid']:key2_val}
  targets_delegations['roles'] = [delegatee1_role_meta, delegatee2_role_meta]

  # Create 'delegations' object for delegatee2 metadata:
  delegatee1_delegations = {}
  key3_val = tuf.rsa_key.create_in_metadata_format(key3['keyval'])
  delegatee1_delegations['keys'] = {key3['keyid']:key3_val}
  delegatee1_delegations['roles'] = [delegatee3_role_meta]
  delegatee1['signed']['delegations'] = delegatee1_delegations

  # Read targets.txt metadata and add the 'delegations' field.
  targets_metadata_path = os.path.join(metadata_dir, 'targets.txt')
  targets_signable = signerlib.read_metadata_file(targets_metadata_path)
  targets_metadata = targets_signable['signed']
  targets_metadata['delegations'] = targets_delegations

  sign = signerlib.sign_metadata
  write = signerlib.write_metadata_file

  # Sign and save new metadata objects.
  targets_signable = sign(targets_metadata, keyids, targets_metadata_path)
  delegatee1_signable = sign(delegatee1, [key1['keyid']], delegatee1_path)
  delegatee2_signable = sign(delegatee2, [key2['keyid']], delegatee2_path)
  delegatee3_signable = sign(delegatee3, [key3['keyid']], delegatee3_path)
  write(targets_signable, targets_metadata_path)
  write(delegatee1_signable, delegatee1_path)
  write(delegatee2_signable, delegatee2_path)
  write(delegatee3_signable, delegatee3_path)

  # Repository is set up.  Refresh release and timestamp metadata to reflect
  # the new changes.
  signerlib.build_release_file(keyids, metadata_dir)
  signerlib.build_timestamp_file(keyids, metadata_dir)

  # Unload all keys.
  keystore.clear_keystore()

  # We need to provide clients with a way to reach the tuf repository.
  tuf_repo_relpath = os.path.basename(tuf_repo)
  tuf_url = url+tuf_repo_relpath
  mirrors = {"mirror1": 
              {"url_prefix": tuf_url,
               "metadata_path": "metadata",
               "targets_path": "targets",
               "confined_target_dirs": [ "" ]}}

  return (root_repo, mirrors, server_proc, keyids,
          _relative_path_to_targets(target_filepaths))





def test(rm_repo=True):
  """
  rm_repo:
    Boolean signalling whether or not we should remove the created repos.
  """

  # Setup.
  root_repo, mirrors, server_proc, keyids, target_filepaths = \
  setup_tuf_repository()

  # Server side repository.
  tuf_repo = os.path.join(root_repo, 'tuf_repo')
  keystore_dir = os.path.join(tuf_repo, 'keystore')
  metadata_dir = os.path.join(tuf_repo, 'metadata')
  targets_dir = os.path.join(tuf_repo, 'targets')

  # Client side repository.
  tuf_client = os.path.join(root_repo, 'tuf_client')
  current_dir = os.path.join(tuf_client, 'metadata', 'current')
  previous_dir = os.path.join(tuf_client, 'metadata', 'previous')
  downloads_dir = os.path.join(root_repo, 'downloads')

  # Adjust client's configuration file.
  # Here the repository_directory is referred to client's local repository.
  original_repo = tuf.conf.repository_directory
  tuf.conf.repository_directory = tuf_client

  # At this point all metadata at the server's repository is in sync.
  
  start_time = time.time()
  _client_update(mirrors, downloads_dir, target_filepaths)
  end_time = time.time()
  print "Client update takes",
  print end_time - start_time,
  print "seconds."

  # TearDown and restore value of previous repository directory.
  tuf.conf.repository_directory = original_repo
  if rm_repo:
    server_proc.kill()
  else:
    util_test_tools.cleanup(root_repo, server_proc)





def _client_update(mirrors, dest, target_filepaths=[], initial_update=False):
  # We need to initialize an updater class.
  updater = tuf.client.updater.Updater('my_repo', mirrors)

  # Refresh the repository's top-level roles, store the target information for
  # all the targets tracked, and determine which of these targets have been
  # updated.
  updater.refresh()

  if initial_update:
    targets = updater.all_targets()
  else:
    targets = []
    for target_filepath in target_filepaths:
      target_info = updater.target(target_filepath)
      targets.append(target_info)

  updated_targets = updater.updated_targets(targets, dest)

  # Download each of these updated targets and save them locally.
  for target in updated_targets:
    try:
      print('Downloading target '+str(target))
      updater.download_target(target, dest)
    except tuf.DownloadError, e:
      pass





if __name__ == '__main__':
  start_time = time.time()
  test(True)
  end_time = time.time()
  print end_time - start_time
