"""
<Program Name>
  test_system_setup.py

<Author>
  Konstantin Andrianov

<Started>
  February 19, 2012

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Provide automatic setup and clean-up functionality.

  Initial repository looks like this:
  simple server -->           repository_dir
                                   |
                       --------------------------
                       |                        |
                     file0                    file1

  This modules uses unittest module to provide easy setup and tear down
  capability.

  Essentially there are two choices: either a system that simply performs
  update downloads without any protections or a system that utilizes TUF to
  perform secure update downloads.

  A structure that does NOT implementing TUF.  A direct download over http.
  Repository + Server    <--------------->    Client

  The TUF structure is described bellow in the class and tuf_tearDown() docs.
  Repository + TUF + Server    <--------->    TUF + Client

"""

# Repository setup.  Repository will consist of a temporary  directory
# with few files in it.

import os
import sys
import time
import shutil
import random
import urllib2
import logging
import tempfile
import subprocess

import tuf.client.updater
import tuf.repo.signerlib as signerlib


# Disable/Enable logging.  Comment-out to Enable logging.
logging.getLogger('tuf')
logging.disable(logging.CRITICAL)


"""

client_download(repo_file):
  Downloads a file ('repo_file') from the 'url' (described bellow).
  Returns the contents of the file.

add_or_change_file_at_repository(filename, data):
  Allows to add or change a file on the repository ('repo_path').
  Modifies 'setup_info' and returns full path of the added/changed file.

delete_file_at_repository(filename):
  Deletes a file on the repository ('repository_dir').

refresh_tuf_repository()
  Updates TUF metadata and targets paths.

setup_info:
  Main dictionary where all setup related information is stored.
  Ex: setup_info['repo_path']

  repo_path:
    Repository directory, where updates are located.

  repo:
    file#:
      Stores a tuple of file's basename and full path of the file.
      setup_info['repo']['file0'] = (filename, fullpath)

      Note:
      *Access the files using the 'file#' (or whatever str) dictionary keys.
      *'filename' is appended to the url in order to get the file.

    repo_files:
      A list that stores all dictionary keys of files available at the
      repository that is all 'file#' dictionary keys described above.
      setup_info['repo']['repo_files'] = ['file0', 'file1']
    
  server_proc:
    A subprocess object.
    Ex: setup_info['server_proc']

  url:
    A loop-back address pointing to the repository directory.
    Ex: setup_info['url']


  TUF related variables.  Refer to the diagram in init_tuf().

  tuf_repo_path:
    A tuf repository that contains all tuf related directories, such as
    metadata, targets, and keystore. (Read docs on how to handle keys!)

  tuf_repo:
    metadata:
      Metadata directory that contains metadata files and is located in the 
      tuf repository directory ('tuf_repository_dir').
      Ex: setup_info['tuf_repo']['metadata']

    keystore:
      Contains all tuf keys, i.e. keys that are used to sign metadata roles.
      It's located in the tuf repository directory ('tuf_repo_path').
      Ex: setup_info['tuf_repo']['keystore']

    targets:
      All target files (updates) are stored in tuf targets directory.
      Basically contains all 'repo_path' files (devel's repository).
      It's located in the tuf repository directory ('tuf_repository_dir').
      Ex: setup_info['tuf_repo']['targets']

  tuf_client_path:
    Client side tuf directory.  It contains current and previous metadata
    files.
    Ex: setup_info['tuf_client_path']

  tuf_client:
    metadata_path:
      Stores path of client's metadata directory.
      Ex; setup_info['tuf_client']['metadata_path']

    metadata:
      Client needs to keep track of metadata files.

      current:
        Latest known to client metadata is stored here.
        Ex: setup_info['tuf_client']['metadata']['current']

      previous:
        Previous metadata is stored here.  It's used during metadata update
        process.
        Ex: setup_info['tuf_client']['metadata']['previous']
    
  tuf_client_metadata_dir:
    Contains current and previous versions of metadata files.


  Note: metadata files are root.txt, targets.txt, release.txt and
  timestamp.txt.  There could be more metadata files such us mirrors.txt.
  The metadata files are signed by their corresponding roles i.e. root,
  targets etc.

More documentation is provided in comments and doc blocks.

"""
setup_info = {}
def init_repo(tuf=False):
  # Repository directory with few files in it.
  setup_info['tuf'] = tuf
  setup_info['repo_path'] = tempfile.mkdtemp(dir=os.getcwd())
  setup_info['dest_path'] = tempfile.mkdtemp(dir=os.getcwd())
  setup_info['repo'] = {'repo_files':[]}
  add_or_change_file_at_repository(repo_file='file0', data='SystemTestFile0')
  add_or_change_file_at_repository(repo_file='file1', data='SystemTestFile1')

  # Start a simple server pointing to the repository directory.
  setup_info['port'] = port = random.randint(30000, 45000)
  command = ['python', '-m', 'SimpleHTTPServer', str(port)]
  setup_info['server_proc'] = subprocess.Popen(command, stderr=subprocess.PIPE)

  # Tailor url for the repository.
  repo_relpath = os.path.basename(setup_info['repo_path'])
  setup_info['url'] = 'http://localhost:'+str(port)+'/'+repo_relpath+'/'

  # NOTE: The delay is needed to make up for asynchronous subprocess.
  # Otherwise following error might be raised:
  #    <urlopen error [Errno 111] Connection refused>
  time.sleep(.1)

  if tuf:
    init_tuf()





def cleanup():
  if not setup_info:
    msg = 'init_repo() must be called before cleanup().\n'
    sys.exit(msg)
  
  if setup_info['server_proc'].returncode is None:
    setup_info['server_proc'].kill()
    print 'Server terminated.\n'

  # Removing repository directory.
  shutil.rmtree(setup_info['repo_path'])
  shutil.rmtree(setup_info['dest_path'])

  if setup_info['tuf']:
    cleanup_tuf()





def add_or_change_file_at_repository(repo_file, data=None):
  """
  <Purpose>
    Adds or changes a file at the repository setup_info[repo_path].

  <Arguments>
    repo_file:
      A key to setup_info[repo] dictionary.

    data:
      A string to write to the indicated file.  If None, 'test' string is
      used.

  """

  if isinstance(repo_file, basestring):
    if not setup_info['repo'].has_key(repo_file):
      junk, filepath = tempfile.mkstemp(dir=setup_info['repo_path'])
      filename = os.path.basename(filepath)
      setup_info['repo'][repo_file] = [filename, filepath]
      setup_info['repo']['repo_files'].append(repo_file)

    fileobj = open(setup_info['repo'][repo_file][1], 'wb')

    if data is None:
      data = 'test'

    fileobj.write(data)
    fileobj.close()
    return setup_info['repo'][repo_file][1]

  msg = 'Nothing was added or changed.  Provide a valid string.\n'
  sys.exit(msg)





def delete_file_at_repository(repo_file):
  """
  <Purpose>
    Attempt to delete a file at the repository setup_info['repo_path'].

  """

  if isinstance(repo_file, basestring):
    if not setup_info['repo'].has_key(repo_file):
      msg = 'Provide a valid dictionary key to remove the file.\n'
      sys.exit(msg)

    os.remove(setup_info['repo'][repo_file][1])
    del setup_info['repo'][repo_file]





def _open_connection(url):
  try:
    request = urllib2.Request(url)
    connection = urllib2.urlopen(request)
  except Exception, e:
    msg = 'Couldn\'t open connection: ' + repr(e)
    sys.exit(msg)
  return connection





def client_download(repo_file):
  """
  <Purpose>
    Attempt to download a file from repository without TUF.

  """

  if not isinstance(repo_file, basestring) or \
     not setup_info['repo'].has_key(repo_file):
    msg = 'Provide a valid key for a file that exists on the repository.\n'
    sys.exit(msg)

  connection = _open_connection(setup_info['url']+setup_info['repo'][repo_file][0])
  data = connection.read()
  connection.close()
  return data





def read_file_content(filepath):
  try:
    fileobj = open(filepath, 'rb')
  except Exception, e:
    raise

  data = fileobj.read()
  fileobj.close()
  return data




def init_tuf():
  """
  <Purpose>
    Setup TUF directory structure and populated it with TUF metadata and 
    congfiguration files.

                         tuf_repository_dir
                                |
          --------------------------------------------
          |                     |                    |
       keystore              metadata             targets
          |                     |                    |
    key.key files         role.txt files       targets (updates)
         ...                   ...                  ...


                           tuf_client_dir
                                |
                             metadata
                                |
                    ---------------------------
                    |                         |  
                 current                   previous
                    |                         |
              role.txt files            role.txt files
                   ...                       ...

  """ 

  passwd = 'test'
  threshold = 1

  # Setup TUF-repo directory structure.
  setup_info['tuf_repo_path'] = \
    tempfile.mkdtemp(prefix='tuf_repo_', dir=os.getcwd())
  keystore_dir = os.path.join(setup_info['tuf_repo_path'], 'keystore')
  metadata_dir = os.path.join(setup_info['tuf_repo_path'], 'metadata')
  targets_dir = os.path.join(setup_info['tuf_repo_path'], 'targets')
  setup_info['tuf_repo'] = {'keystore':keystore_dir,
                            'metadata':metadata_dir,
                            'targets':targets_dir}
  os.mkdir(setup_info['tuf_repo']['keystore'])
  os.mkdir(setup_info['tuf_repo']['metadata'])
  shutil.copytree(setup_info['repo_path'], setup_info['tuf_repo']['targets'])

  # Setting TUF-client directory structure.
  # 'tuf.client.updater.py' expects the 'current' and 'previous'
  # directories to exist under client's 'metadata' directory.
  setup_info['tuf_client_path'] = tempfile.mkdtemp(suffix='tuf_client_', dir=os.getcwd())
  tuf_client_metadata_dir = os.path.join(setup_info['tuf_client_path'], 'metadata')
  current_dir = os.path.join(setup_info['tuf_client_path'], 'metadata', 'current')
  previous_dir = os.path.join(setup_info['tuf_client_path'], 'metadata', 'previous')
  setup_info['tuf_client'] = {'metadata_path': tuf_client_metadata_dir,
                              'metadata': {'current':current_dir,
                                           'previous':previous_dir}}
  os.mkdir(setup_info['tuf_client']['metadata_path'])

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
  tuf_repo_relpath = os.path.basename(setup_info['tuf_repo_path'])
  setup_info['tuf_url'] = 'http://localhost:'+ \
                          str(setup_info['port'])+'/'+tuf_repo_relpath+'/'
  setup_info['mirrors'] = {'mirror1': 
                            {'url_prefix': setup_info['tuf_url'],
                             'metadata_path': 'metadata',
                             'targets_path': 'targets',
                             'confined_target_dirs': ['']}}

  # Adjusting configuration file (tuf.conf.py).
  tuf.conf.repository_directory = setup_info['tuf_client_path']

  # Instantiate an updater.
  setup_info['tuf_client']['updater'] = \
    tuf.client.updater.Updater('updater', setup_info['mirrors'])





def cleanup_tuf():
  """
  <Purpose>
    Clean-up method, removes all TUF directories created using
    tuf_init().

  """

  shutil.rmtree(setup_info['tuf_repo_path'])
  shutil.rmtree(setup_info['tuf_client_path'])





def refresh_tuf_repository():
  """
  <Purpose>
    Update TUF metadata files.  Call this method whenever targets files have
    changed in the 'repository_dir'.

  """

  if not setup_info['tuf']:
    msg = 'TUF needs to be initialized.\n'
    sys.exist(msg)

  shutil.rmtree(setup_info['tuf_repo']['targets'])
  shutil.copytree(setup_info['repo_path'], setup_info['tuf_repo']['targets'])

  # Regenerate the 'targets.txt' metadata file. 
  signerlib.build_targets_file(setup_info['tuf_repo']['targets'],
                                setup_info['keyid'],
                                setup_info['tuf_repo']['metadata'])

  # Regenerate the 'release.txt' metadata file.
  signerlib.build_release_file(setup_info['keyid'],
                                setup_info['tuf_repo']['metadata'])

  # Regenerate the 'timestamp.txt' metadata file.
  signerlib.build_timestamp_file(setup_info['keyid'], 
                                  setup_info['tuf_repo']['metadata'])





def tuf_client_refresh_metadata():
  if not setup_info['tuf']:
    msg = 'TUF needs to be initialized.\n'
    sys.exist(msg)

  # Update all metadata.
  setup_info['tuf_client']['updater'].refresh()





def tuf_client_download_updates():
  if not setup_info['tuf']:
    msg = 'TUF needs to be initialized.\n'
    sys.exist(msg)

  # Get the latest information on targets.
  targets = setup_info['tuf_client']['updater'].all_targets()

  # Determine which targets have changed or are new.
  updated_targets = \
    setup_info['tuf_client']['updater'].updated_targets(targets, setup_info['dest_path'])

  # Download new/changed targets and store them in the destination
  # directory 'destination_dir'.
  for target in updated_targets:
    setup_info['tuf_client']['updater'].download_target(target, setup_info['dest_path'])





#===========================================#
#  Bellow are few quick tests to make sure  #
#  that everything works smoothly.          #
#===========================================#
def test_client_download():
  init_repo()
  data = client_download('file0')
  assert data == 'SystemTestFile0'





def test_tuf_setup():
  init_repo(tuf=True)

  # Verify that all necessary TUF-paths exist.
  for role in ['root', 'targets', 'release', 'timestamp']:
    # Repository side.
    role_file = os.path.join(setup_info['tuf_repo']['metadata'], role+'.txt')
    msg = repr(role)+'repository metadata file missing!'
    assert os.path.isfile(role_file), msg

    # Client side.
    current_dir = setup_info['tuf_client']['metadata']['current']
    role_file = os.path.join(current_dir, role+'.txt')
    msg = repr(role)+'client metadata file missing!'
    assert os.path.isfile(role_file), msg

  targets_dir = setup_info['tuf_repo']['targets']
  target1 = os.path.join(targets_dir, setup_info['repo']['file0'][0])
  target2 = os.path.join(targets_dir, setup_info['repo']['file1'][0])
  msg = 'missing target file!'
  assert os.path.isfile(target1), msg
  assert os.path.isfile(target2), msg





def test_methods():
  """
  Making sure following methods work as intended:
  - add_or_change_file_at_repository()
  - delete_file_at_repository()
  - refresh_tuf_repository()
  """
  init_repo(tuf=True)
  new_file = add_or_change_file_at_repository('file2')
  fileobj = open(new_file, 'rb')
  msg = 'add_or_change_file_at_repository() failed on file creation.'
  assert os.path.exists(new_file), msg
  msg = 'content of the new file did not match expected data.'
  assert 'test' == fileobj.read(), msg
  fileobj.close()

  old_file = add_or_change_file_at_repository(repo_file='file1')
  fileobj = open(old_file, 'rb')
  msg = 'add_or_change_file_at_repository() failed on changing content of a file.'
  assert os.path.exists(old_file), msg
  msg = 'content of the changed file did not match expected data.'
  assert 'test' == fileobj.read(), msg
  fileobj.close()

  old_file = add_or_change_file_at_repository(repo_file='file1', data='1234')
  fileobj = open(old_file, 'rb')
  msg = 'add_or_change_file_at_repository() failed on changing content of a file.'
  assert os.path.exists(old_file), msg
  msg = 'content of the changed file did not match expected data.'
  assert '1234' == fileobj.read(), msg
  fileobj.close()

  refresh_tuf_repository()
  targets_dir = setup_info['tuf_repo']['targets']
  new_target = os.path.join(targets_dir, os.path.basename(new_file))
  msg = 'failed to add a target to the tuf targets directory on refresh.'
  assert os.path.exists(new_target)
  # Here it's assumed that all relevant metadata has been updated
  # successfully.  This is tested in signerlib and other unit tests.

  delete_file_at_repository('file2')
  msg = 'failed to delete a file on the repository.'
  assert not os.path.exists(new_file), msg





if __name__ == '__main__':
  tests = [test_client_download, test_tuf_setup, test_methods]
  for test in tests:
    try:
      test()
      print repr(test)+'.......  OKAY'
    except Exception, e:
      raise
    finally:
      cleanup()
      setup_info = {}