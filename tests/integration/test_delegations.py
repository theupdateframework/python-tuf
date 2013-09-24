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
  Ensure that TUF meets expectations about target delegations.
"""

import os
import time
import tempfile
import unittest

import tuf.formats
import tuf.repo.keystore as keystore
import tuf.repo.signercli as signercli
import tuf.repo.signerlib as signerlib
import tuf.tests.util_test_tools as util_test_tools

version = 1
# Modify the number of iterations (from the higher default count) so the unit
# tests run faster.
keystore._PBKDF2_ITERATIONS = 1000


class TestDelegationFunctions(unittest.TestCase):


  def do_update(self):
    # Client side repository.
    tuf_client = os.path.join(self.root_repo, 'tuf_client')
    downloads_dir = os.path.join(self.root_repo, 'downloads')

    # Adjust client's configuration file.
    tuf.conf.repository_directory = tuf_client

    updater = tuf.client.updater.Updater('my_repo', self.mirrors)

    # Refresh the repository's top-level roles, store the target information for
    # all the targets tracked, and determine which of these targets have been
    # updated.
    updater.refresh()

    # Obtain a list of available targets.
    targets = []
    relative_target_filepaths = self.relpath_from_targets(self.target_filepaths)
    for target_filepath in relative_target_filepaths:
      target_info = updater.target(target_filepath)
      targets.append(target_info)

    # Download each of these updated targets and save them locally.
    updated_targets = updater.updated_targets(targets, downloads_dir)
    for target in updated_targets:
      updater.download_target(target, downloads_dir)

    # Return metadata about downloaded targets.
    make_fileinfo = signerlib.get_metadata_file_info
    targets_metadata = {}
    for target_filepath in relative_target_filepaths:
      download_filepath = os.path.join(downloads_dir, target_filepath)
      target_fileinfo = signerlib.get_metadata_file_info(download_filepath)
      targets_metadata[target_filepath] = target_fileinfo
    return targets_metadata


  def make_targets_metadata(self):
    """Subclasses will override this method to generate metadata for all
    targets roles, with the understanding that there is a fixed structure of
    the targets roles."""

    raise NotImplementedError()


  def relpath_from_targets(self, target_filepaths):
    """Ex: 'targets/more_targets/somefile.txt' -> 'more_targets/somefile.txt'
    i.e. 'targets/' is removed from 'target'."""

    new_target_filepaths = []
    for target in target_filepaths:
      relative_targetpath = os.path.sep.join(target.split(os.path.sep)[1:])
      new_target_filepaths.append(relative_targetpath)
    return new_target_filepaths


  def setUp(self):
    """
    The target delegations tree is fixed as such:
      targets -> [T1, T2]
      T1 -> [T3]
    """
    global version
    version = version+1
    expiration = tuf.formats.format_time(time.time()+86400)

    root_repo, url, server_proc, keyids = util_test_tools.init_repo(using_tuf=True)

    # Server side repository.
    tuf_repo = os.path.join(root_repo, 'tuf_repo')
    keystore_dir = os.path.join(tuf_repo, 'keystore')
    metadata_dir = os.path.join(tuf_repo, 'metadata')
    targets_dir = os.path.join(tuf_repo, 'targets')

    # We need to provide clients with a way to reach the tuf repository.
    tuf_repo_relpath = os.path.basename(tuf_repo)
    tuf_url = url+tuf_repo_relpath

    # Add files to the server side repository.
    # target1 = 'targets_dir/[random].txt'
    # target2 = 'targets_dir/[random].txt'
    add_target = util_test_tools.add_file_to_repository
    target1_path = add_target(targets_dir, data='target1')
    target2_path = add_target(targets_dir, data='target2')

    # Target paths relative to the 'targets_dir'.
    # Ex: targetX = 'targets/delegator/delegatee.txt'
    target1 = os.path.relpath(target1_path, tuf_repo)
    target2 = os.path.relpath(target2_path, tuf_repo)

    # Relative to repository's targets directory.
    target_filepaths = [target1, target2]

    # Store in self only the variables relevant for tests.
    self.root_repo = root_repo
    self.tuf_repo = tuf_repo
    self.server_proc = server_proc
    self.target_filepaths = target_filepaths
    # Targets delegated from A to B.
    self.delegated_targets = {}
    # Targets actually signed by B.
    self.signed_targets = {}
    self.mirrors = {
      "mirror1": {
        "url_prefix": tuf_url,
        "metadata_path": "metadata",
        "targets_path": "targets",
        "confined_target_dirs": [""]
      }
    }
    # Aliases for targets roles.
    self.T0 = 'targets'
    self.T1 = 'targets/T1'
    self.T2 = 'targets/T2'
    self.T3 = 'targets/T1/T3'

    # Get tracked and assigned targets, and generate targets metadata.
    self.make_targets_metadata()
    assert hasattr(self, 'T0_metadata')
    assert hasattr(self, 'T1_metadata')
    assert hasattr(self, 'T2_metadata')
    assert hasattr(self, 'T3_metadata')

    # Make delegation directories at the server's repository.
    metadata_targets_dir = os.path.join(metadata_dir, 'targets')
    metadata_T1_dir = os.path.join(metadata_targets_dir, 'T1')
    os.makedirs(metadata_T1_dir)

    # Delegations metadata paths for the 3 delegated targets roles.
    T0_path = os.path.join(metadata_dir, 'targets.txt')
    T1_path = os.path.join(metadata_targets_dir, 'T1.txt')
    T2_path = os.path.join(metadata_targets_dir, 'T2.txt')
    T3_path = os.path.join(metadata_T1_dir, 'T3.txt')

    # Generate RSA keys for the 3 delegatees.
    key1 = signerlib.generate_and_save_rsa_key(keystore_dir, 'T1')
    key2 = signerlib.generate_and_save_rsa_key(keystore_dir, 'T2')
    key3 = signerlib.generate_and_save_rsa_key(keystore_dir, 'T3')

    # ID for each of the 3 keys.
    key1_id = key1['keyid']
    key2_id = key2['keyid']
    key3_id = key3['keyid']

    # ID, in a list, for each of the 3 keys.
    key1_ids = [key1_id]
    key2_ids = [key2_id]
    key3_ids = [key3_id]

    # Public-key JSON for each of the 3 keys.
    key1_val = tuf.rsa_key.create_in_metadata_format(key1['keyval'])
    key2_val = tuf.rsa_key.create_in_metadata_format(key2['keyval'])
    key3_val = tuf.rsa_key.create_in_metadata_format(key3['keyval'])

    # Create delegation role metadata for each of the 3 delegated targets roles.
    make_role_metadata = tuf.formats.make_role_metadata

    T1_targets = self.relpath_from_targets(self.delegated_targets[self.T1])
    T1_role = make_role_metadata(key1_ids, 1, name=self.T1, paths=T1_targets)

    T2_targets = self.relpath_from_targets(self.delegated_targets[self.T2])
    T2_role = make_role_metadata(key2_ids, 1, name=self.T2, paths=T2_targets)

    T3_targets = self.relpath_from_targets(self.delegated_targets[self.T3])
    T3_role = make_role_metadata(key3_ids, 1, name=self.T3, paths=T3_targets)

    # Assign 'delegations' object for 'targets':
    self.T0_metadata['signed']['delegations'] = {
      'keys': {key1_id: key1_val, key2_id: key2_val},
      'roles': [T1_role, T2_role]
    }

    # Assign 'delegations' object for 'targets/T1':
    self.T1_metadata['signed']['delegations'] = {
      'keys': {key3_id: key3_val},
      'roles': [T3_role]
    }

    sign = signerlib.sign_metadata
    write = signerlib.write_metadata_file

    # Sign new metadata objects.
    T0_signable = sign(self.T0_metadata, keyids, T0_path)
    T1_signable = sign(self.T1_metadata, key1_ids, T1_path)
    T2_signable = sign(self.T2_metadata, key2_ids, T2_path)
    T3_signable = sign(self.T3_metadata, key3_ids, T3_path)
    # Save new metadata objects.
    write(T0_signable, T0_path)
    write(T1_signable, T1_path)
    write(T2_signable, T2_path)
    write(T3_signable, T3_path)

    # Timestamp a new release to reflect latest targets.
    signerlib.build_release_file(keyids, metadata_dir, version, expiration)
    signerlib.build_timestamp_file(keyids, metadata_dir, version, expiration)

    # Unload all keys.
    keystore.clear_keystore()


  def tearDown(self):
    util_test_tools.cleanup(self.root_repo, server_process=self.server_proc)





class TestInitialUpdateWithTargetDelegations(TestDelegationFunctions):
  """We show that making target delegations results in a successful initial
  update of targets."""


  def make_targets_metadata(self):
    global version
    version = version+1
    expiration = tuf.formats.format_time(time.time()+86400)
    make_metadata = signerlib.generate_targets_metadata
    target1, target2 = self.target_filepaths

    # Targets signed for by each of the targets roles.
    self.signed_targets[self.T0] = [target1]
    self.signed_targets[self.T1] = [target1]
    self.signed_targets[self.T2] = [target2]
    self.signed_targets[self.T3] = [target1, target2]

    # Targets delegated to each of the delegated targets roles.
    self.delegated_targets[self.T1] = [target1]
    self.delegated_targets[self.T2] = [target2]
    self.delegated_targets[self.T3] = [target1, target2]

    self.T0_metadata =\
      make_metadata(self.tuf_repo, self.signed_targets[self.T0],
                    version, expiration)
    self.T1_metadata =\
      make_metadata(self.tuf_repo, self.signed_targets[self.T1],
                    version, expiration)
    self.T2_metadata =\
      make_metadata(self.tuf_repo, self.signed_targets[self.T2],
                    version, expiration)
    self.T3_metadata = \
      make_metadata(self.tuf_repo, self.signed_targets[self.T3],
                    version, expiration)


  def test_that_initial_update_works_with_target_delegations(self):
    # Get relative target paths, because that is what TUF recognizes.
    relative_target_filepaths = self.relpath_from_targets(self.target_filepaths)
    # Get metadata about downloaded targets.
    targets_metadata = self.do_update()
    # Do we have metadata about all the expected targets?
    for target_filepath in relative_target_filepaths:
      self.assertIn(target_filepath, targets_metadata)





class TestBreachOfTargetDelegation(TestDelegationFunctions):
  """We show that a delegated targets role B cannot talk about targets that A
  did not delegate to B."""


  def make_targets_metadata(self):
    global version
    version = version+1
    expiration = tuf.formats.format_time(time.time()+86400)

    make_metadata = signerlib.generate_targets_metadata
    target1, target2 = self.target_filepaths

    # Targets signed for by each of the targets roles.
    self.signed_targets[self.T0] = []
    self.signed_targets[self.T1] = [target2]
    self.signed_targets[self.T2] = [target1]
    self.signed_targets[self.T3] = []

    # Targets delegated to each of the delegated targets roles.
    self.delegated_targets[self.T1] = [target1]
    self.delegated_targets[self.T2] = [target2]
    self.delegated_targets[self.T3] = []

    self.T0_metadata =\
      make_metadata(self.tuf_repo, self.signed_targets[self.T0],
                    version, expiration)
    self.T1_metadata =\
      make_metadata(self.tuf_repo, self.signed_targets[self.T1],
                    version, expiration)
    self.T2_metadata =\
      make_metadata(self.tuf_repo, self.signed_targets[self.T2],
                    version, expiration)
    self.T3_metadata =\
      make_metadata(self.tuf_repo, self.signed_targets[self.T3],
                    version, expiration)


  def test_that_initial_update_fails_with_undelegated_signing_of_targets(self):
    """We expect to see ForbiddenTargetError on initial update because
    delegated targets roles sign for targets that they were not delegated
    to."""

    # http://docs.python.org/2/library/unittest.html#unittest.TestCase.assertRaises
    with self.assertRaises(tuf.NoWorkingMirrorError) as context_manager:
      self.do_update()

    mirror_errors = context_manager.exception.mirror_errors
    forbidden_target_error = False

    for mirror_url, mirror_error in mirror_errors.iteritems():
      if isinstance(mirror_error, tuf.ForbiddenTargetError):
        forbidden_target_error = True
        break 

    self.assertEqual(forbidden_target_error, True)





class TestOrderOfTargetDelegationWithSuccess(TestDelegationFunctions):
  """We show that when multiple delegated targets roles talk about a target,
  the first one in order of appearance of delegation wins.

  In this case, the first role has the correct metadata about the target."""


  def make_targets_metadata(self):
    global version
    version = version+1
    expiration = tuf.formats.format_time(time.time()+86400)
    
    make_metadata = signerlib.generate_targets_metadata
    target1, target2 = self.target_filepaths

    # Targets signed for by each of the targets roles.
    self.signed_targets[self.T0] = [target2]
    self.signed_targets[self.T1] = []
    self.signed_targets[self.T2] = [target1]
    self.signed_targets[self.T3] = [target1]

    # Targets delegated to each of the delegated targets roles.
    self.delegated_targets[self.T1] = [target1]
    self.delegated_targets[self.T2] = [target1]
    self.delegated_targets[self.T3] = [target1]

    self.T0_metadata =\
      make_metadata(self.tuf_repo, self.signed_targets[self.T0],
                    version, expiration)
    self.T1_metadata =\
      make_metadata(self.tuf_repo, self.signed_targets[self.T1],
                    version, expiration)
    self.T2_metadata =\
      make_metadata(self.tuf_repo, self.signed_targets[self.T2],
                    version, expiration)
    self.T3_metadata = \
      make_metadata(self.tuf_repo, self.signed_targets[self.T3],
                    version, expiration)

    # Modify the hash for target1 in T2.
    for target_filepath in self.relpath_from_targets([target1]):
      target_metadata = self.T2_metadata['signed']['targets'][target_filepath]
      sha256_hash = target_metadata['hashes']['sha256']
      last_character = sha256_hash[-1]
      last_character = chr(ord(last_character)-1)
      # "Subtract" the last character of the hash.
      target_metadata['hashes']['sha256'] = sha256_hash[:-1] + last_character


  def test_that_initial_update_works_with_many_roles_sharing_a_target(self):
    # Get relative target paths, because that is what TUF recognizes.
    relative_target_filepaths = self.relpath_from_targets(self.target_filepaths)
    # Get metadata about downloaded targets.
    targets_metadata = self.do_update()
    # Do we have metadata about all the expected targets?
    for target_filepath in relative_target_filepaths:
      self.assertIn(target_filepath, targets_metadata)





class TestOrderOfTargetDelegationWithFailure(TestDelegationFunctions):
  """We show that when multiple delegated targets roles talk about a target,
  the first one in order of appearance of delegation wins.

  In this case, the first role has the wrong metadata about the target."""


  def make_targets_metadata(self):
    global version
    version = version+1
    expiration = tuf.formats.format_time(time.time()+86400)
    make_metadata = signerlib.generate_targets_metadata
    target1, target2 = self.target_filepaths

    # Targets signed for by each of the targets roles.
    self.signed_targets[self.T0] = [target2]
    self.signed_targets[self.T1] = []
    self.signed_targets[self.T2] = [target1]
    self.signed_targets[self.T3] = [target1]

    # Targets delegated to each of the delegated targets roles.
    self.delegated_targets[self.T1] = [target1]
    self.delegated_targets[self.T2] = [target1]
    self.delegated_targets[self.T3] = [target1]

    self.T0_metadata =\
      make_metadata(self.tuf_repo, self.signed_targets[self.T0],
                    version, expiration)
    self.T1_metadata =\
      make_metadata(self.tuf_repo, self.signed_targets[self.T1],
                    version, expiration)
    self.T2_metadata =\
      make_metadata(self.tuf_repo, self.signed_targets[self.T2],
                    version, expiration)
    self.T3_metadata = \
      make_metadata(self.tuf_repo, self.signed_targets[self.T3],
                    version, expiration)

    # Modify the hash for target1 in T3.
    for target_filepath in self.relpath_from_targets([target1]):
      target_metadata = self.T3_metadata['signed']['targets'][target_filepath]
      sha256_hash = target_metadata['hashes']['sha256']
      last_character = sha256_hash[-1]
      last_character = chr(ord(last_character)-1)
      # "Subtract" the last character of the hash.
      target_metadata['hashes']['sha256'] = sha256_hash[:-1] + last_character


  def test_that_initial_update_fails_with_many_roles_sharing_a_target(self):
    """We expect to see BadHashError on initial update because the hash
    metadata mismatches the target."""

    # http://docs.python.org/2/library/unittest.html#unittest.TestCase.assertRaises
    with self.assertRaises(tuf.NoWorkingMirrorError) as context_manager:
      self.do_update()

    mirror_errors = context_manager.exception.mirror_errors
    bad_hash_error = False

    for mirror_url, mirror_error in mirror_errors.iteritems():
      if isinstance(mirror_error, tuf.BadHashError):
        bad_hash_error = True
        break 

    self.assertEqual(bad_hash_error, True)





class TestConservationOfTargetDelegation(TestDelegationFunctions):
  """We show that delegated targets roles have to neither sign for targets
  delegated to them nor further delegate them."""


  def make_targets_metadata(self):
    global version
    expiration = tuf.formats.format_time(time.time()+86400)

    make_metadata = signerlib.generate_targets_metadata
    target1, target2 = self.target_filepaths

    # Targets signed for by each of the targets roles.
    self.signed_targets[self.T0] = []
    self.signed_targets[self.T1] = [target1]
    self.signed_targets[self.T2] = [target2]
    self.signed_targets[self.T3] = []

    # Targets delegated to each of the delegated targets roles.
    self.delegated_targets[self.T1] = [target1, target2]
    self.delegated_targets[self.T2] = [target1, target2]
    self.delegated_targets[self.T3] = []

    self.T0_metadata =\
      make_metadata(self.tuf_repo, self.signed_targets[self.T0],
                    version, expiration)
    self.T1_metadata =\
      make_metadata(self.tuf_repo, self.signed_targets[self.T1],
                    version, expiration)
    self.T2_metadata =\
      make_metadata(self.tuf_repo, self.signed_targets[self.T2],
                    version, expiration)
    self.T3_metadata = \
      make_metadata(self.tuf_repo, self.signed_targets[self.T3],
                    version, expiration)


  def test_that_initial_update_works_with_unconserved_targets(self):
    # Get relative target paths, because that is what TUF recognizes.
    relative_target_filepaths = self.relpath_from_targets(self.target_filepaths)
    # Get metadata about downloaded targets.
    targets_metadata = self.do_update()
    # Do we have metadata about all the expected targets?
    for target_filepath in relative_target_filepaths:
      self.assertIn(target_filepath, targets_metadata)





if __name__ == '__main__':
  unittest.main()
