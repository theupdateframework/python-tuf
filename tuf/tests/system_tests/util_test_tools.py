"""
<Program Name>
  util_test_tools.py

<Author>
  Konstantin Andrianov

<Started>
  February 19, 2012

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  A utility modules that provides convenient methods to make the laborious
  process of test construction a bit easier.  

  A structure that does NOT implementing TUF.  A direct download over http.
  Repository + Server    <--------------->    Client

  The TUF structure is described bellow in the class and tuf_tearDown() docs.
  Repository + TUF + Server    <--------->    TUF + Client

<Directories>
  Initialized by init_repo()

  The server is pointing to 'temp_root' directory, including the '/'.

                          temp_root
                              |
    -------------------------------------------------------
    |        |             |              |               | 
  repo     tuf_repo     tuf_client    tuf_downloads    downloads

  '{temp_repo}/downloads/': stores all direct downloads made by the client.
  '{temp_repo}/tuf_downloads/': stores all downloads made by the client using
  tuf.

      
                             repo
                              |
                -----------------------------
                |          |      ...       |
            file(1)    file(2)    ...     file(n)

  '{temp_repo}/repo/': main developer's repository that contains files or
  updates that need to be distributed.


                           tuf_repo
                              |
          ------------------------------------------
        |                     |                    |
    keystore              metadata              targets
        |                     |                    |
  key1.key ...          role.txt ...           file(1) ...

  '{temp_repo}/tuf_repo/': developer's tuf-repository directory containing
  following subdirectories:
    '{temp_repo}/tuf_repo/keystore/': directory where all signing keys are
    stored.
    '{temp_repo}/tuf_repo/metadata/': directory where all metadata signed 
    metadata files are stored.
    '{temp_repo}/tuf_repo/targets/': directory where all tuf verified files
    are stored.
 
                          tuf_client
                              |
                           metadata
                              |
                  ---------------------------
                  |                         |  
               current                   previous
                  |                         | 
             role.txt ...              role.txt ...

  '{temp_repo}/tuf_cleint/': client directory containing tuf metadata.
  '{temp_repo}/tuf_cleint/metadata/current': directory where client stores 
  latest metadata files.
  '{temp_repo}/tuf_cleint/metadata/current': directory where client stores 
  previous metadata files.

<Methods>
  init_repo(tuf=True):
    Initializes the repositories (depicted in the diagram above) and
    starts the server process.  init_repo takes one boolean argument
    which when True sets-up tuf repository i.e. adds all of the
    directories that start with 'tuf_' in the temp_root (depicted above).
    Returns a tuple - full path of the 'temp_root' directory, and the url.
    This should be sufficient to construct the tests.

  cleanup():
    Deletes all of the created repositories and shuts down the server.

  add_file_to_repository(data):
    Adds a file to the 'repo' directory and writes 'data' into it.
    Returns full file path of the new file.

  modify_file_at_repository(filepath, data):
    Modifies a file at the 'repo' directory by writing 'data' into it.
    'filepath' has to be an existing file at the 'repo' directory.
    Returns full file path of the modified file.

  delete_file_at_repository(filepath):
    Deletes a file at the 'repo' directory.
    'filepath' has to be an existing file at the 'repo' directory.

  read_file_content(filepath):
    Returns data string of the 'filepath' content.

  init_tuf():
    Builds tuf repository creating all necessary directories, metadata files,
    and keys.

  tuf_refresh_repo():
    Refreshes metadata files at the 'tuf_repo' directory i.e. role.txt's at
    '{temp_root}/tuf_repo/metadata/'.  Following roles are refreshed:
    targets, release and timestamp.  Also, the whole 'repo' directory is
    copied to targets directory i.e. '{temp_root}/tuf_repo/targets/'.

  tuf_refresh_client_metadata():
    Downloads latests metadata files from '{temp_root}/tuf_repo/metadata/'
    into '{temp_root}/tuf_client/metadata/current/'.

  tuf_download_updates()
    Downloads files in the secure manner and then performs all tuf security
    checks i.e. length and hash comparisons based on the information in the
    metadata files.

  tuf_refresh_and_download()
    Combines tuf_refresh_repo(), tuf_refresh_client_metadata(), and
    tuf_download_updates().
    Returns 'tuf_downloads' directory where all tuf downloaded files are
    located.

Note: metadata files are root.txt, targets.txt, release.txt and
timestamp.txt (denoted as 'role.txt in the diagrams').  There could be
more metadata files such us mirrors.txt.  The metadata files are signed
by their corresponding roles i.e. root, targets etc.

More documentation is provided in the comment and doc blocks.

"""

import os
import sys
import time
import shutil
import random
import logging
import tempfile
import subprocess

import tuf.client.updater
import tuf.repo.signerlib as signerlib


# Disable/Enable logging.  Comment-out to Enable logging.
logging.getLogger('tuf')
logging.disable(logging.CRITICAL)


# 'setup_info' stores all important setup information like the path of the
# 'temp_root' directory, etc.
setup_info = {}


def init_repo(tuf=False):
  setup_info['tuf'] = tuf

  # Temp root directory for regular and tuf repositories.
  # WARNING: tuf client stores files in '{temp_root}/downloads/' directory!
  # Make sure regular download are NOT stored in the that directory when
  # tuf stores its downloads there.  If regular download needs to happen at
  # the time when tuf has or will have tuf downloads stored there just create
  # a separate directory in {temp_root} to store regular downloads in.
  # Ex: mkdir(temp_root, 'reg_downloads').
  setup_info['temp_root'] = temp_root = tempfile.mkdtemp(dir=os.getcwd())
  setup_info['repo'] = os.path.join(temp_root, 'repo')
  setup_info['downloads'] = os.path.join(temp_root, 'downloads')
  os.mkdir(setup_info['repo'])
  os.mkdir(setup_info['downloads'])

  # Start a simple server pointing to the repository directory.
  port = random.randint(30000, 45000)
  command = ['python', '-m', 'SimpleHTTPServer', str(port)]
  setup_info['server_proc'] = subprocess.Popen(command, stderr=subprocess.PIPE)

  # Tailor url for the repository.  In order to download a 'file.txt' 
  # from 'repo' do: url+'repo/file.txt'
  relpath = os.path.basename(temp_root)
  setup_info['url'] = url = 'http://localhost:'+str(port)+'/'+relpath+'/'

  # NOTE: The delay is needed to make up for asynchronous subprocess.
  # Otherwise following error might be raised:
  #    <urlopen error [Errno 111] Connection refused>
  time.sleep(.3)
  if tuf:
    init_tuf()

  return temp_root, url





def cleanup():
  if not setup_info:
    msg = 'init_repo() must be called before cleanup().\n'
    sys.exit(msg)
  
  if setup_info['server_proc'].returncode is None:
    setup_info['server_proc'].kill()
    print 'Server terminated.\n'

  # Removing repository directory.
  try:
    shutil.rmtree(setup_info['temp_root'])
  except OSError, e:
    pass




def add_file_to_repository(data='Test String'):
  junk, filepath = tempfile.mkstemp(dir=setup_info['repo'])
  fileobj = open(filepath, 'wb')
  fileobj.write(data)
  fileobj.close()
  return filepath





def modify_file_at_repository(filepath, data='Modified String'):
  repo = os.path.dirname(filepath)
  if repo != setup_info['repo'] or not os.path.isfile(filepath):
    msg = 'Provide a valid file on the repository to modify.'
    sys.exit(msg)

  fileobj = open(filepath, 'wb')
  fileobj.write(data)
  fileobj.close()
  return filepath





def delete_file_at_repository(filepath):
  """
  <Purpose>
    Attempt to delete a file at the repository setup_info['repo_path'].

  """

  repo = os.path.dirname(filepath)
  if repo != setup_info['repo'] or not os.path.isfile(filepath):
    msg = 'Provide a valid file on the repository to delete.'
    sys.exit(msg)

  os.remove(filepath)





def read_file_content(filepath):
  if not os.path.isfile(filepath):
    msg = 'Provide a valid file to read.'
    sys.exit(msg)

  fileobj = open(filepath, 'rb')
  data = fileobj.read()
  fileobj.close()
  return data





def init_tuf():
  """
  <Purpose>
    Setup TUF directory structure and populated it with TUF metadata and 
    congfiguration files.

  """ 

  passwd = 'test'
  threshold = 1

  # Setup TUF-repo directory structure.
  setup_info['tuf_repo'] = tuf_repo = \
    os.path.join(setup_info['temp_root'], 'tuf_repo')
  keystore_dir = os.path.join(tuf_repo, 'keystore')
  metadata_dir = os.path.join(tuf_repo, 'metadata')
  targets_dir = os.path.join(tuf_repo, 'targets')

  os.mkdir(tuf_repo)
  os.mkdir(keystore_dir)
  os.mkdir(metadata_dir)
  shutil.copytree(setup_info['repo'], targets_dir)

  # Setting TUF-client directory structure.
  # 'tuf.client.updater.py' expects the 'current' and 'previous'
  # directories to exist under client's 'metadata' directory.
  setup_info['tuf_client'] = tuf_client = \
    os.path.join(setup_info['temp_root'], 'tuf_client')
  tuf_client_metadata_dir = os.path.join(tuf_client, 'metadata')
  current_dir = os.path.join(tuf_client_metadata_dir, 'current')
  previous_dir = os.path.join(tuf_client_metadata_dir, 'previous')
  os.makedirs(tuf_client_metadata_dir)

  # Generate at least one rsa key.
  key = signerlib.generate_and_save_rsa_key(keystore_dir, passwd)
  keyid = [key['keyid']]
  setup_info['keyid'] = keyid

  # Set role info.
  info = {'keyids': [key['keyid']], 'threshold': threshold}

  # 'role_info' dictionary looks like this:
  # {role : {'keyids : [keyid1, ...] , 'threshold' : 1}}
  # In our case 'role_info[keyids]' will only have on entry since only one
  # is being used.
  role_info = {}
  role_list = ['root', 'targets', 'release', 'timestamp']
  for role in role_list:
    role_info[role] = info

  # At this point there is enough information to create TUF configuration 
  # and metadata files.

  # Build the configuration file.
  conf_path = signerlib.build_config_file(metadata_dir, 365, role_info)

  # Generate the 'root.txt' metadata file.
  signerlib.build_root_file(conf_path, keyid, metadata_dir)

  # Generate the 'targets.txt' metadata file. 
  signerlib.build_targets_file(targets_dir, keyid, metadata_dir)

  # Generate the 'release.txt' metadata file.
  signerlib.build_release_file(keyid, metadata_dir)

  # Generate the 'timestamp.txt' metadata file.
  signerlib.build_timestamp_file(keyid, metadata_dir)

  # Move the metadata to the client's 'current' and 'previous' directories.
  shutil.copytree(metadata_dir, current_dir)
  shutil.copytree(metadata_dir, previous_dir)

  # The repository is now setup!

  # Here is a mirrors dictionary that will allow a client to seek out
  # places to download the metadata and targets from.
  tuf_repo_relpath = os.path.basename(tuf_repo)
  url_prefix = setup_info['url']+tuf_repo_relpath+'/'
  setup_info['mirrors'] = {'mirror1': 
                            {'url_prefix': url_prefix,
                             'metadata_path': 'metadata',
                             'targets_path': 'targets',
                             'confined_target_dirs': ['']}}

  # Adjusting configuration file (tuf.conf.py).
  tuf.conf.repository_directory = setup_info['tuf_client']

  # Instantiate an updater.
  setup_info['updater'] = \
    tuf.client.updater.Updater('updater', setup_info['mirrors'])





def tuf_refresh_repo():
  """
  <Purpose>
    Update TUF metadata files.  Call this method whenever targets files have
    changed in the 'repo'.

  """

  if not setup_info['tuf']:
    msg = 'TUF needs to be initialized.\n'
    sys.exist(msg)

  keyid = setup_info['keyid']
  metadata_dir = os.path.join(setup_info['tuf_repo'], 'metadata')
  targets_dir = os.path.join(setup_info['tuf_repo'], 'targets')
  shutil.rmtree(targets_dir)
  shutil.copytree(setup_info['repo'], targets_dir)

  # Regenerate the 'targets.txt' metadata file. 
  signerlib.build_targets_file(targets_dir, keyid, metadata_dir)

  # Regenerate the 'release.txt' metadata file.
  signerlib.build_release_file(keyid, metadata_dir)

  # Regenerate the 'timestamp.txt' metadata file.
  signerlib.build_timestamp_file(keyid, metadata_dir)





def tuf_refresh_client_metadata():
  if not setup_info['tuf']:
    msg = 'TUF needs to be initialized.\n'
    sys.exist(msg)

  # Update all metadata.
  setup_info['updater'].refresh()





def tuf_download_updates():
  """
  Here it is assumed that client has already downloaded latest metadata files.
  """
  if not setup_info['tuf']:
    msg = 'TUF needs to be initialized.\n'
    sys.exist(msg)

  # Get the latest information on targets.
  targets = setup_info['updater'].all_targets()

  # Create destination directory for the tuf targets.
  dest = setup_info['downloads']

  # Determine which targets have changed or are new.
  updated_targets = \
    setup_info['updater'].updated_targets(targets, dest)

  # Download new/changed targets and store them in the 'tuf_downloads' dir.
  for target in updated_targets:
    setup_info['updater'].download_target(target, dest)





def tuf_refresh_and_download():
  """
  Combines tuf_refresh_repo(), tuf_refresh_client_metadata(), and
  tuf_download_updates().
  Returns 'tuf_downloads' directory.
  """
  tuf_refresh_repo()
  tuf_refresh_client_metadata()
  tuf_download_updates()
  return setup_info['downloads']
