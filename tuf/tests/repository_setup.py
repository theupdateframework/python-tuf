"""
<Program Name>
  repository_setup.py

<Author>
  Konstantin Andrianov

<Started>
  October 15, 2012

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  To provide a quick repository structure to be used in conjunction with
  test modules like test_updater.py for instance.

"""

import os
import sys
import time
import shutil
import tempfile

import tuf.formats
import tuf.rsa_key as rsa_key
import tuf.repo.keystore as keystore
import tuf.repo.signerlib as signerlib
import tuf.repo.signercli as signercli
import tuf.tests.unittest_toolbox as unittest_toolbox



#  Role:keyids dictionary.
role_keyids = {}


def _init_role_keyids():
  # Populating 'rsa_keystore' and 'rsa_passwords' dictionaries.
  # We will need them in creating the keystore directory and metadata files.
  unittest_toolbox.Modified_TestCase.bind_keys_to_roles()

  global role_keyids

  for role in unittest_toolbox.Modified_TestCase.semi_roledict.keys():
    role_keyids[role] = unittest_toolbox.Modified_TestCase.semi_roledict[role]['keyids']




def _create_keystore(keystore_directory):
  """
  <Purpose>
    Populate 'keystore_directory' with keys (.key files).
  """
  
  _rsa_keystore = unittest_toolbox.Modified_TestCase.rsa_keystore
  _rsa_derived_keys = unittest_toolbox.Modified_TestCase.rsa_derived_keys
  if not _rsa_keystore or not _rsa_derived_keys:
    msg = 'Populate \'rsa_keystore\' and \'rsa_passwords\''+\
          ' before invoking this method.'
    sys.exit(msg)

  keystore._keystore = _rsa_keystore
  keystore._derived_keys = _rsa_derived_keys
  keystore.save_keystore_to_keyfiles(keystore_directory)





def build_server_repository(server_repository_dir, targets_dir):
  """
  <Purpose>
    'build_server_repository' builds a complete repository based on target
    files provided in the 'targets_dir'.  Delegated roles are included.
  """

  # Save the originals of the functions patched by this function.
  # The patched functions will be restored prior to returning.
  original_get_metadata = signercli._get_metadata_directory
  original_prompt = signercli._prompt
  original_get_password = signercli._get_password
  original_get_keyids = signercli._get_keyids
 
  # The expiration date for created metadata, required by the 'signercli.py'
  # script.  The expiration date is set to 259200 seconds ahead of the current
  # time.  Set all the metadata versions numbers to 1.
  expiration_date = tuf.formats.format_time(time.time()+259200)
  expiration_date = expiration_date[0:expiration_date.rfind(' UTC')] 
  version = 1
  
  server_metadata_dir = os.path.join(server_repository_dir, 'metadata')
  keystore_dir = os.path.join(server_repository_dir, 'keystore')

  #  Remove 'server_metadata_dir' and 'keystore_dir' if they already exist.
  if os.path.exists(server_metadata_dir):
    shutil.rmtree(server_metadata_dir)
  if os.path.exists(keystore_dir):
    shutil.rmtree(keystore_dir)

  #  Make metadata directory inside server repository dir.
  os.mkdir(server_metadata_dir)

  #  Make a keystore directory inside server's repository and populate it.
  os.mkdir(keystore_dir)
  _create_keystore(keystore_dir)

  #  Build config file.
  build_config = signerlib.build_config_file
  top_level_role_info = unittest_toolbox.Modified_TestCase.top_level_role_info
  config_filepath = build_config(server_repository_dir, 365, top_level_role_info)


  # BUILD ROLE FILES.
  #  Build root file.
  signerlib.build_root_file(config_filepath, role_keyids['root'],
                            server_metadata_dir, version)

  #  Build targets file.
  signerlib.build_targets_file([targets_dir], role_keyids['targets'],
                            server_metadata_dir, version, expiration_date+' UTC')

  # MAKE DELEGATIONS.
  #  We will need to patch a few signercli prompts.
  #  Specifically, signercli.make_delegations() asks user input for:
  #  metadata directory, delegated targets directory, parent role,
  #  passwords for parent role's keyids, delegated role's name, and
  #  the keyid to be assigned to the delegated role.  Take a look at
  #  signercli's make_delegation() to gain bit more insight in what is
  #  happening.

  # 'load_key' is a reference to the 'load_keystore_from_keyfiles function'.
  load_keys = keystore.load_keystore_from_keyfiles

  #  Setup first level delegated role.
  delegated_level1 = os.path.join(targets_dir, 'delegated_level1')
  delegated_targets_dir = delegated_level1
  parent_role = 'targets'
  delegated_role_name = 'delegated_role1'
  signing_keyids = role_keyids['targets/delegated_role1'] 
  

  #  Patching the 'signercli' prompts.
  
  #  Mock method for signercli._get_metadata_directory().
  def _mock_get_metadata_directory():
    return server_metadata_dir

  #  Mock method for signercli._prompt().
  def _mock_prompt(msg, junk):
    if msg.startswith('\nThe paths entered'):
      return delegated_targets_dir
    elif msg.startswith('\nChoose and enter the parent'):
      return parent_role
    elif msg.startswith('\nEnter the delegated role\'s name: '):
      return delegated_role_name
    elif msg.startswith('\nCurrent time:'):
      return expiration_date
    else:
      error_msg = ('Prompt: '+'\''+msg+'\''+
                   ' did not match any predefined mock prompts.')
      sys.exit(error_msg)
   
  #  Mock method for signercli._get_password().
  def _mock_get_password(msg):
    for keyid in unittest_toolbox.Modified_TestCase.rsa_keyids:
      if msg.endswith('('+keyid+'): '):
        return unittest_toolbox.Modified_TestCase.rsa_passwords[keyid]


  #  Method to patch signercli._get_keyids()
  def _mock_get_keyids(junk):
    if signing_keyids:
      for keyid in signing_keyids:
        password = unittest_toolbox.Modified_TestCase.rsa_passwords[keyid]
        #  Load the keyfile.
        load_keys(keystore_dir, [keyid], [password])
    return signing_keyids


  #  Patch signercli._get_metadata_directory().
  signercli._get_metadata_directory = _mock_get_metadata_directory
  
  #  Patch signercli._prompt().
  signercli._prompt = _mock_prompt

  #  Patch signercli._get_password().
  signercli._get_password = _mock_get_password

  #  Patch signercli._get_keyids().
  signercli._get_keyids = _mock_get_keyids
 
  #  Clear kestore's dictionaries, by detaching them from unittest_toolbox's
  #  dictionaries.
  keystore._keystore = {}
  keystore._derived_keys = {}

  #  Make first level delegation.
  signercli.make_delegation(keystore_dir)

  #  Setup second level delegated role.
  delegated_level2 =  os.path.join(delegated_level1, 'delegated_level2')
  delegated_targets_dir = delegated_level2
  parent_role = 'targets/delegated_role1'
  delegated_role_name = 'delegated_role2'
  signing_keyids = role_keyids['targets/delegated_role1/delegated_role2']

  #  Clear kestore's dictionaries.
  keystore.clear_keystore()

  #  Make second level delegation.
  signercli.make_delegation(keystore_dir)


  keystore._keystore = unittest_toolbox.Modified_TestCase.rsa_keystore
  keystore._derived_keys = unittest_toolbox.Modified_TestCase.rsa_passwords

  #  Build release file.
  signerlib.build_release_file(role_keyids['release'], server_metadata_dir,
                               version, expiration_date+' UTC')

  #  Build timestamp file.
  signerlib.build_timestamp_file(role_keyids['timestamp'], server_metadata_dir,
                                 version, expiration_date+' UTC')

  keystore._keystore = {}
  keystore._derived_keys = {}

  # RESTORE
  signercli._get_metadata_directory = original_get_metadata
  signercli._prompt = original_prompt
  signercli._get_password = original_get_password
  signercli._get_keyids = original_get_keyids



#  Create a complete server and client repositories.
def create_repositories():
  """
  Main directories have the following structure:

                        main_repository
                             |
                     ------------------
                     |                |
       client_repository_dir      server_repository_dir



                      client_repository
                             |
                          metadata
                             |
                      ----------------
                      |              |
                  previous        current


                      server_repository
                             |
                 ----------------------------
                 |           |              |
             metadata     targets        keystore
                             |
                      delegation_level1
                             |
                      delegation_level2



  NOTE: Do not forget to remove the directory using remove_all_repositories
        after the tests.

  <Return>
    A dictionary of all repositories, with the following keys:
    (main_repository, client_repository, server_repository)

  """

  # Ensure the keyids for the required roles are loaded.  Role keyids are
  # needed for the creation of metadata file and the keystore.
  _init_role_keyids()

  #  Make a temporary general repository directory.
  repository_dir = tempfile.mkdtemp()


  #  Make server repository and client repository directories.
  server_repository_dir  = os.path.join(repository_dir, 'server_repository')
  client_repository_dir  = os.path.join(repository_dir, 'client_repository')
  os.mkdir(server_repository_dir)
  os.mkdir(client_repository_dir)


  #  Make metadata directory inside client repository dir.
  client_metadata_dir = os.path.join(client_repository_dir, 'metadata')
  os.mkdir(client_metadata_dir)

  #  Create a 'targets' directory.
  targets = os.path.join(server_repository_dir, 'targets')
  delegated_level1 = os.path.join(targets, 'delegated_level1')
  delegated_level2 = os.path.join(delegated_level1, 'delegated_level2')
  os.makedirs(delegated_level2)

  #  Populate the project directory with files.
  file_path_1 = tempfile.mkstemp(suffix='.txt', dir=targets)
  file_path_2 = tempfile.mkstemp(suffix='.txt', dir=targets)
  file_path_3 = tempfile.mkstemp(suffix='.txt', dir=delegated_level1)
  file_path_4 = tempfile.mkstemp(suffix='.txt', dir=delegated_level2)

  def data():
    return 'Stored data: '+unittest_toolbox.Modified_TestCase.random_string()

  file_1 = open(file_path_1[1], 'wb')
  file_1.write(data())
  file_1.close()
  file_2 = open(file_path_2[1], 'wb')
  file_2.write(data())
  file_2.close()
  file_3 = open(file_path_3[1], 'wb')
  file_3.write(data())
  file_3.close()
  file_4 = open(file_path_4[1], 'wb')
  file_4.write(data())
  file_4.close()


  #  Build server's repository.
  build_server_repository(server_repository_dir, targets)

  #  Build client's repository.
  client_repository_include_all_role_files(repository_dir)

  repositories = {'main_repository': repository_dir,
                  'client_repository': client_repository_dir,
                  'server_repository': server_repository_dir,
                  'targets_directory': targets}

  return repositories





#  client_repository_include_all_role_files() copies all of the metadata file.
def client_repository_include_all_role_files(repository_dir):
  if repository_dir is None:
    msg = ('Please provide main repository directory where client '+
           'repository is located.')
    sys.exit(msg)

  #  Destination directories.
  current_dir = os.path.join(repository_dir, 'client_repository', 'metadata',
                             'current')
  previous_dir = os.path.join(repository_dir, 'client_repository', 'metadata',
                             'previous')
  #  Source directory.
  metadata_files = os.path.join(repository_dir, 'server_repository',
                                'metadata')

  #  Copy the whole source directory to destination directories.
  shutil.copytree(metadata_files, current_dir)
  shutil.copytree(metadata_files, previous_dir)





#  Supply the main repository directory.
def remove_all_repositories(repository_directory):
  #  Check if 'repository_directory' is an existing directory.
  if os.path.isdir(repository_directory):
    shutil.rmtree(repository_directory)
  else:
    print '\nInvalid repository directory.'





if __name__ == '__main__':
  repos = create_repositories()
  remove_all_repositories(repos['main_repository'])
