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

  The server is pointing to 'root_repo' directory, including the '/'.

                          root_repo
                              |
           ----------------------------------------
           |          |            |              |
        reg_repo    tuf_repo    tuf_client     downloads

  '{root_repo}/downloads/': stores all direct downloads made by the client.
  '{root_repo}/tuf_downloads/': stores all downloads made by the client using
  tuf.

      
                          reg_repo
                              |
                -----------------------------
                |          |      ...       |
            file(1)    file(2)    ...     file(n)

  '{root_repo}/reg_repo/': main developer's repository that contains files or
  updates that need to be distributed.


                           tuf_repo
                              |
        --------------------------------------------
        |                     |                    |
    keystore              metadata              targets
        |                     |                    |
  key1.key ...          role.txt ...           file(1) ...

  '{root_repo}/tuf_repo/': developer's tuf-repository directory containing
  following subdirectories:
  '{root_repo}/tuf_repo/keystore/': directory where all signing keys are
  stored.
  '{root_repo}/tuf_repo/metadata/': directory where all metadata signed 
  metadata files are stored.
  '{root_repo}/tuf_repo/targets/': directory where all tuf verified files
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

  '{root_repo}/tuf_client/': client directory containing tuf metadata.
  '{root_repo}/tuf_client/metadata/current': directory where client stores 
  latest metadata files.
  '{root_repo}/tuf_client/metadata/current': directory where client stores 
  previous metadata files.

<Methods>
  init_repo(tuf=True):
    Initializes the repositories (depicted in the diagram above) and
    starts the server process.  init_repo takes one boolean argument
    which when True sets-up tuf repository i.e. adds all of the
    directories that start with 'tuf_' in the root_repo (depicted above).
    Returns a tuple - full path of the 'root_repo' directory, and the url.
    This should be sufficient to construct the tests.

  cleanup():
    Deletes all of the created repositories and shuts down the server.

  add_file_to_repository(data):
    Adds a file to the 'reg_repo' directory and writes 'data' into it.
    Returns full file path of the new file.

  modify_file_at_repository(filepath, data):
    Modifies a file at the 'reg_repo' directory by writing 'data' into it.
    'filepath' has to be an existing file at the 'reg_repo' directory.
    Returns full file path of the modified file.

  delete_file_at_repository(filepath):
    Deletes a file at the 'reg_repo' directory.
    'filepath' has to be an existing file at the 'reg_repo' directory.

  read_file_content(filepath):
    Returns data string of the 'filepath' content.

  init_tuf():
    Builds tuf repository creating all necessary directories, metadata files,
    and keys.

  tuf_refresh_repo():
    Refreshes metadata files at the 'tuf_repo' directory i.e. role.txt's at
    '{root_repo}/tuf_repo/metadata/'.  Following roles are refreshed:
    targets, release and timestamp.  Also, the whole 'reg_repo' directory is
    copied to targets directory i.e. '{root_repo}/tuf_repo/targets/'.

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

import tuf.util
import tuf.interposition
import tuf.client.updater
import tuf.repo.signerlib as signerlib


# Disable/Enable logging.  Comment-out to Enable logging.
logging.getLogger('tuf')
logging.disable(logging.CRITICAL)


# 'setup_info' stores all important setup information like the path of the
# 'root_repo' directory, etc.


def init_repo(tuf=False):
  # Temp root directory for regular and tuf repositories.
  # WARNING: tuf client stores files in '{root_repo}/downloads/' directory!
  # Make sure regular download are NOT stored in the that directory when
  # tuf stores its downloads there.  If regular download needs to happen at
  # the time when tuf has or will have tuf downloads stored there, create
  # a separate directory in {root_repo} to store regular downloads in.
  # Ex: mkdir(root_repo, 'reg_downloads').
  root_repo = tempfile.mkdtemp(dir=os.getcwd())
  os.mkdir(os.path.join(root_repo, 'reg_repo'))
  os.mkdir(os.path.join(root_repo, 'downloads'))

  # Start a simple server pointing to the repository directory.
  port = random.randint(30000, 45000)
  command = ['python', '-m', 'SimpleHTTPServer', str(port)]
  server_proc = subprocess.Popen(command, stderr=subprocess.PIPE)

  # Tailor url for the repository.  In order to download a 'file.txt' 
  # from 'reg_repo' do: url+'reg_repo/file.txt'
  relpath = os.path.basename(root_repo)
  url = 'http://localhost:'+str(port)+'/'+relpath+'/'

  # NOTE: The delay is needed to make up for asynchronous subprocess.
  # Otherwise following error might be raised:
  #    <urlopen error [Errno 111] Connection refused>
  time.sleep(.3)
  if tuf:
    keyids, interpose_json = init_tuf(root_repo, url)

  return root_repo, url, server_proc, keyids, interpose_json





def cleanup(root_repo, server_process):
  if server_process.returncode is None:
    server_process.kill()
    print 'Server terminated.\n'

  # Removing repository directory.
  try:
    shutil.rmtree(root_repo)
  except OSError, e:
    pass





def add_file_to_repository(directory, data='Test String'):
  junk, filepath = tempfile.mkstemp(dir=directory)
  fileobj = open(filepath, 'wb')
  fileobj.write(data)
  fileobj.close()
  return filepath





def modify_file_at_repository(filepath, data='Modified String'):
  if not os.path.isfile(filepath):
    msg = ('Cannot modify file path '+repr(filepath)+', it does not exist.')
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

  if not os.path.isfile(filepath):
    msg = ('Cannot remove file path '+repr(filepath)+', it does not exist.')
    sys.exit(msg)

  os.remove(filepath)





def read_file_content(filepath):
  if not os.path.isfile(filepath):
    msg = ('File path '+repr(filepath)+' does not exist.  '+
           'Provide a valid file to read.')
    sys.exit(msg)

  fileobj = open(filepath, 'rb')
  data = fileobj.read()
  fileobj.close()
  return data





def init_tuf(root_repo, url):
  """
  <Purpose>
    Setup TUF directory structure and populated it with TUF metadata and 
    congfiguration files.

  """ 

  passwd = 'test'
  threshold = 1

  # Setup TUF-repo directory structure.
  tuf_repo = os.path.join(root_repo, 'tuf_repo')
  keystore_dir = os.path.join(tuf_repo, 'keystore')
  metadata_dir = os.path.join(tuf_repo, 'metadata')
  targets_dir = os.path.join(tuf_repo, 'targets')

  os.mkdir(tuf_repo)
  os.mkdir(keystore_dir)
  os.mkdir(metadata_dir)
  shutil.copytree(os.path.join(root_repo, 'reg_repo'), targets_dir)

  # Setting TUF-client directory structure.
  # 'tuf.client.updater.py' expects the 'current' and 'previous'
  # directories to exist under client's 'metadata' directory.
  tuf_client = os.path.join(root_repo, 'tuf_client')
  tuf_client_metadata_dir = os.path.join(tuf_client, 'metadata')
  current_dir = os.path.join(tuf_client_metadata_dir, 'current')
  previous_dir = os.path.join(tuf_client_metadata_dir, 'previous')
  os.makedirs(tuf_client_metadata_dir)

  # Generate at least one rsa key.
  key = signerlib.generate_and_save_rsa_key(keystore_dir, passwd)
  keyids = [key['keyid']]

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
  signerlib.build_root_file(conf_path, keyids, metadata_dir)

  # Generate the 'targets.txt' metadata file. 
  signerlib.build_targets_file(targets_dir, keyids, metadata_dir)

  # Generate the 'release.txt' metadata file.
  signerlib.build_release_file(keyids, metadata_dir)

  # Generate the 'timestamp.txt' metadata file.
  signerlib.build_timestamp_file(keyids, metadata_dir)

  # Move the metadata to the client's 'current' and 'previous' directories.
  shutil.copytree(metadata_dir, current_dir)
  shutil.copytree(metadata_dir, previous_dir)

  # The repository is now setup!

  # Here is a mirrors dictionary that will allow a client to seek out
  # places to download the metadata and targets from.
  tuf_repo_relpath = os.path.basename(tuf_repo)
  tuf_url = url+tuf_repo_relpath
  mirrors = {'mirror1': {'url_prefix': tuf_url,
                         'metadata_path': 'metadata',
                         'targets_path': 'targets',
                         'confined_target_dirs': ['']}}

  # Adjusting configuration file (tuf.conf.py).
  tuf.conf.repository_directory = tuf_client

  # In order to implement interposition we need to have a config file with
  # the following dictionary JSON-serialized.
  # tuf_url: http://localhost:port/root_repo/tuf_repo/
  interposition_dict = {"configurations":
                          {"localhost": 
                            {"repository_directory": tuf_client+'/',
                             "repository_mirrors" : 
                              {"mirror1": 
                                {"url_prefix": tuf_url,
                                 "metadata_path": "metadata",
                                 "targets_path": "targets",
                                 "confined_target_dirs": [ "" ]}},
                                 "target_paths": [ { "(.*\\.html)": "{0}" } ]}}}

  junk, interpose_json = tempfile.mkstemp(prefix='conf_', dir=root_repo)
  with open(interpose_json, 'wb') as fileobj:
    tuf.util.json.dump(interposition_dict, fileobj)

  return keyids, interpose_json





def tuf_refresh_repo(root_repo, keyids):
  """
  <Purpose>
    Update TUF metadata files.  Call this method whenever targets files have
    changed in the 'reg_repo'.

  """

  reg_repo = os.path.join(root_repo, 'reg_repo')
  tuf_repo = os.path.join(root_repo, 'tuf_repo')
  targets_dir = os.path.join(tuf_repo, 'targets')
  metadata_dir = os.path.join(tuf_repo, 'metadata')

  for directory in [reg_repo, tuf_repo, targets_dir, metadata_dir]:
    if not os.path.isdir(directory):
      msg = ('Directory '+repr(directory)+' does not exist.  '+
             'Verify that all directories were setup properly.')
      raise OSError(msg)

  shutil.rmtree(targets_dir)
  shutil.copytree(reg_repo, targets_dir)

  # Regenerate the 'targets.txt' metadata file. 
  signerlib.build_targets_file(targets_dir, keyids, metadata_dir)

  # Regenerate the 'release.txt' metadata file.
  signerlib.build_release_file(keyids, metadata_dir)

  # Regenerate the 'timestamp.txt' metadata file.
  signerlib.build_timestamp_file(keyids, metadata_dir)





def tuf_refresh_release_timestamp(metadata_dir, keyids):
  # Regenerate the 'release.txt' metadata file.
  signerlib.build_release_file(keyids, metadata_dir)

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
