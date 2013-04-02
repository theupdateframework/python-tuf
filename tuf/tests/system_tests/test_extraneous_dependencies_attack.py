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
  Simulate an extraneous dependencies attack.

  In an extraneous dependencies attack, attacker is able to cause clients to
  download software dependencies that are not the intended dependencies.

"""

import os
import sys
import urllib
import tempfile

import util_test_tools
import tuf.repo.keystore
import tuf.repo.signerlib as signerlib
import tuf.repo.signercli as signercli
from tuf.interposition import urllib_tuf


# Disable logging.
util_test_tools.disable_logging()



def test_extraneous_dependencies_attack():

  try:

    # Setup.
    root_repo, url, server_proc, keyids = util_test_tools.init_repo(tuf=True)
    reg_repo = os.path.join(root_repo, 'reg_repo')
    tuf_repo = os.path.join(root_repo, 'tuf_repo')
    keystore_dir = os.path.join(tuf_repo, 'keystore')
    metadata_dir = os.path.join(tuf_repo, 'metadata')
    downloads_dir = os.path.join(root_repo, 'downloads')
    targets_dir = os.path.join(tuf_repo, 'targets')

    # 'roles' holds information about delegated roles.
    roles = {'role1':{'password':['pass1']},
                       'role2':{'password':['pass2']}}

    # Add files to 'reg_repo' directory: {root_repo}
    role1_path = tempfile.mkdtemp(dir=reg_repo)
    roles['role1']['filepath'] = \
      util_test_tools.add_file_to_repository(role1_path, 'Test A')

    role2_path = tempfile.mkdtemp(dir=reg_repo)
    roles['role2']['filepath'] = \
      util_test_tools.add_file_to_repository(role2_path, 'Test B')

    # Update TUF repository.
    util_test_tools.make_targets_meta(root_repo)
    util_test_tools.make_release_meta(root_repo)
    util_test_tools.make_timestamp_meta(root_repo)


    def _make_delegation(rolename):

      # Indicate which file client downloads.
      rel_filepath = os.path.relpath(roles[rolename]['filepath'], reg_repo)
      roles[rolename]['target_path'] = os.path.join(targets_dir, rel_filepath)
      rolepath, file_basename = os.path.split(roles[rolename]['filepath'])
      junk, role_relpath = os.path.split(rolepath)
      roles[rolename]['targets_dir'] = os.path.join(targets_dir, role_relpath)
      roles[rolename]['metadata_dir'] =  os.path.join(metadata_dir, 'targets')

      # Create a key to sign a new delegated role.
      password = roles[rolename]['password'][0]
      key = signerlib.generate_and_save_rsa_key(keystore_dir, password)
      roles[rolename]['keyid'] = [key['keyid']]
      roles[rolename]['dest_path'] = os.path.join(downloads_dir, file_basename)

      # Create delegation one.
      util_test_tools.create_delegation(tuf_repo, 
                                        roles[rolename]['targets_dir'], 
                                        roles[rolename]['keyid'], password, 
                                        'targets', rolename)

      # Update TUF repository.
      # util_test_tools.make_targets_meta(root_repo)
      util_test_tools.make_release_meta(root_repo)
      util_test_tools.make_timestamp_meta(root_repo)

      # Modify the url.  Remember that the interposition will intercept 
      # urls that have 'localhost:9999' hostname, which was specified in
      # the json interposition configuration file.  Look for 'hostname'
      # in 'util_test_tools.py'. Further, the 'file_basename' is the target
      # path relative to 'targets_dir'. 
      roles[rolename]['url'] = 'http://localhost:9999/'+rel_filepath

      # Perform a client download.
      urllib_tuf.urlretrieve(roles[rolename]['url'],
                             roles[rolename]['dest_path'])


    _make_delegation('role1')
    _make_delegation('role2')


    # The attack.
    # Modify a target that was delegated to 'role2'.
    util_test_tools.modify_file_at_repository(roles['role2']['target_path'], 
                                              'Test NOT B')

    # Load the keystore before rebuilding the metadata.
    tuf.repo.keystore.load_keystore_from_keyfiles(keystore_dir,
                                                  roles['role1']['keyid'],
                                                  roles['role1']['password'])

    # Rebuild the delegation role metadata.
    signerlib.build_delegated_role_file(roles['role2']['targets_dir'], 
                                        roles['role1']['keyid'], metadata_dir,
                                        roles['role1']['metadata_dir'],
                                        'role1.txt')

    # Update release and timestamp metadata.
    util_test_tools.make_release_meta(root_repo)
    util_test_tools.make_timestamp_meta(root_repo)


    # Perform another client download.
    try:
      urllib_tuf.urlretrieve(roles['role2']['url'], roles['role2']['dest_path'])
    except tuf.MetadataNotAvailableError, e:
      raise


  finally:  
    server_proc.kill()
    util_test_tools.cleanup(root_repo, server_proc)



try:
  test_extraneous_dependencies_attack()
except tuf.MetadataNotAvailableError, error:
  print str(error)+'\n'
else:
  print 'Extraneous Dependencies Attack Succeeded!\n'