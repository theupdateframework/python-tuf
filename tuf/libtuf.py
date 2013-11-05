"""
<Program Name>
  libtuf.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  October 19, 2013 

<Copyright>
  See LICENSE for licensing information.

<Purpose>
"""

import os
import errno
import sys
import time
import getpass
import logging
import json

import tuf
import tuf.formats
import tuf.util
import tuf.keydb
import tuf.roledb
import tuf.keys
import tuf.sig
import tuf.log


# See 'log.py' to learn how logging is handled in TUF.
logger = logging.getLogger('tuf.libtuf')

# Recommended RSA key sizes:
# http://www.emc.com/emc-plus/rsa-labs/historical/twirl-and-rsa-key-size.htm#table1 
# According to the document above, revised May 6, 2003, RSA keys of
# size 3072 provide security through 2031 and beyond.  2048-bit keys
# are the recommended minimum and are good from the present through 2030.
DEFAULT_RSA_KEY_BITS = 3072

# The metadata filenames of the top-level roles.
ROOT_FILENAME = 'root.txt'
TARGETS_FILENAME = 'targets.txt'
RELEASE_FILENAME = 'release.txt'
TIMESTAMP_FILENAME = 'timestamp.txt'

# The targets and metadata directory names.
METADATA_DIRECTORY_NAME = 'metadata'
TARGETS_DIRECTORY_NAME = 'targets' 

# Expiration date delta, in seconds, of the top-level roles.  A metadata
# expiration date is set by taking the current time and adding the expiration
# seconds listed below.

# Initial 'root.txt' expiration time of 1 year. 
ROOT_EXPIRATION = 31556900

# Initial 'targets.txt' expiration time of 3 months. 
TARGETS_EXPIRATION = 7889230 

# Initial 'release.txt' expiration time of 1 week. 
RELEASE_EXPIRATION = 604800 

# Initial 'timestamp.txt' expiration time of 1 day.
TIMESTAMP_EXPIRATION = 86400

# The suffix added to metadata filenames of partially written metadata.
# Partial metadata may contain insufficient number of signatures and require
# multiple repository maintainers to independently sign them.
PARTIAL_METADATA_SUFFIX = '.partial'


class Repository(object):
  """
  <Purpose>
  
  <Arguments>
    repository_directory:

    metadata_directory:

    targets_directory:

  <Exceptions>
    tuf.FormatError, if the arguments are improperly formatted.

  <Side Effects>

  <Returns>
    Repository object.
  """
 
  def __init__(self, repository_directory, metadata_directory, targets_directory):
  
    # Do the arguments have the correct format?
    # Raise 'tuf.FormatError' if any of the arguments are improperly formatted.
    tuf.formats.PATH_SCHEMA.check_match(repository_directory)
    tuf.formats.PATH_SCHEMA.check_match(metadata_directory)
    tuf.formats.PATH_SCHEMA.check_match(targets_directory)
    
    self._repository_directory = repository_directory
    self._metadata_directory = metadata_directory
    self._targets_directory = targets_directory
   
    # Set the top-level role objects.
    self.root = Root() 
    self.release = Release()
    self.timestamp = Timestamp()
    self.targets = Targets('targets', self._targets_directory)
  
  
  
  def status(self):
    """
    <Purpose>
    
    <Arguments>
      None.

    <Exceptions>

    <Side Effects>

    <Returns>
    """
    
    # tuf.sig
  
  
  def write(self):
    """
    <Purpose>
      Write all the JSON Metadata objects to their corresponding files.  
    
    <Arguments>

    <Exceptions>

    <Side Effects>

    <Returns>
    """
    
    # At this point the keystore is built and the 'role_info' dictionary
    # looks something like this:
    # {'keyids : [keyid1, keyid2] , 'threshold' : 2}
    filenames = get_metadata_filenames(self._metadata_directory)
    root_filename = filenames[ROOT_FILENAME] 
    targets_filename = filenames[TARGETS_FILENAME] 
    release_filename = filenames[RELEASE_FILENAME] 
    timestamp_filename = filenames[TIMESTAMP_FILENAME] 

    # Generate the 'root.txt' metadata file. 
    # Newly created metadata start at version 1.  The expiration date for the
    # 'Root' role is extracted from the configuration file that was set, above,
    # by the user.
    root_keyids = tuf.roledb.get_role_keyids(self.root.rolename)
    root_version = self.root.version
    root_expiration = self.root.expiration 
    if root_expiration is None: 
      root_expiration = tuf.formats.format_time(time.time()+ROOT_EXPIRATION) 
    root_metadata = generate_root_metadata(root_version, root_expiration)
    write_metadata_file(root_metadata, root_filename, compression=None)

    # Generate the 'targets.txt' metadata file.
    targets_keyids = tuf.roledb.get_role_keyids(self.targets.rolename)
    targets_version = self.targets.version
    targets_expiration = self.targets.expiration
    targets_files = self.targets.target_files
    if targets_expiration is None: 
      targets_expiration = \
        tuf.formats.format_time(time.time()+TARGETS_EXPIRATION) 
    targets_metadata = generate_targets_metadata(self._repository_directory,
                                                 targets_files, targets_version,
                                                 targets_expiration)
    write_metadata_file(targets_metadata, targets_filename, compression=None)

    # Generate the 'release.txt' metadata file.
    release_keyids = tuf.roledb.get_role_keyids(self.release.rolename)
    release_version = self.release.version
    release_expiration = self.release.expiration
    if release_expiration is None: 
      release_expiration = \
        tuf.formats.format_time(time.time()+RELEASE_EXPIRATION) 
    release_metadata = generate_release_metadata(self._metadata_directory,
                                                release_version,
                                                release_expiration)
    write_metadata_file(release_metadata, release_filename, compression=None)
    
    # Generate the 'timestamp.txt' metadata file.
    timestamp_keyids = tuf.roledb.get_role_keyids(self.timestamp.rolename)
    timestamp_version = self.timestamp.version
    timestamp_expiration = self.timestamp.expiration
    if timestamp_expiration is None: 
      timestamp_expiration = \
        tuf.formats.format_time(time.time()+TIMESTAMP_EXPIRATION) 
    timestamp_metadata = generate_timestamp_metadata(release_filename,
                                                     timestamp_version,
                                                     timestamp_expiration,
                                                     compressions=())
    write_metadata_file(timestamp_metadata, timestamp_filename, compression=None)
  


  def partial_write():
    """
    <Purpose>

    <Arguments>

    <Exceptions>

    <Side Effects>

    <Returns>
      None.
    """
    
    #PARTIAL_METADATA_SUFFIX 



  def get_filepaths_in_directory(files_directory, recursive_walk=False,
                                 followlinks=True):
    """
    <Purpose>
      Walk the given files_directory to build a list of target files in it.

    <Arguments>
      files_directory:
        The path to a directory of target files.

      recursive_walk:
        To recursively walk the directory, set recursive_walk=True.

      followlinks:
        To follow symbolic links, set followlinks=True.

    <Exceptions>
      Python IO exceptions.

    <Side Effects>
      None.

    <Returns>
      A list of absolute paths to target files in the given files_directory.
    """

    targets = []

    # FIXME: We need a way to tell Python 2, but not Python 3, to return
    # filenames in Unicode; see #61 and:
    # http://docs.python.org/2/howto/unicode.html#unicode-filenames
    for dirpath, dirnames, filenames in os.walk(files_directory,
                                                followlinks=followlinks):
      for filename in filenames:
        full_target_path = os.path.join(dirpath, filename)
        targets.append(full_target_path)

      # Prune the subdirectories to walk right now if we do not wish to
      # recursively walk files_directory.
      if recursive_walk is False:
        del dirnames[:]

    return targets





class Metadata(object):
  """
  <Purpose>
    Write all the Metadata objects' JSON contents to the corresponding files. 
  
  <Arguments>

  <Exceptions>

  <Side Effects>

  <Returns>
  """

  def __init__(self):
    self._rolename = None    
    self._signing_keys = []
    
    self._version = 1
    self._threshold = 1
    self._role_keys = [] 
    self._signatures = []
    self._expiration = None 
  
  
  
  def add_key(self, key):
    """
    <Purpose>

      >>> 
      >>> 
      >>> 

    <Arguments>
      key:
        tuf.formats.ANYKEY_SCHEMA

    <Exceptions>

    <Side Effects>

    <Returns>
      None.
    """
    
    tuf.formats.ANYKEY_SCHEMA.check_match(key)

    try:
      tuf.keydb.add_key(key)
    except tuf.KeyAlreadyExistsError, e:
      pass
   
    keyid = key['keyid']
    roleinfo = tuf.roledb.get_roleinfo(self._rolename)
    roleinfo['keyids'].append(keyid)
    tuf.roledb.update_roleinfo(self._rolename, roleinfo)
    
    self._role_keys.append(keyid) 
 

 
  @property
  def threshold(self):
    """

    """

    return self._threshold



  @threshold.setter 
  def threshold(self, threshold):
    """
    <Purpose>

      >>> 
      >>> 
      >>> 

    <Arguments>
      threshold:
        tuf.formats.THRESHOLD_SCHEMA

    <Exceptions>
      tuf.FormatError, if the argument is improperly formatted.

    <Side Effects>
      Modifies the threshold attribute of the Repository object.

    <Returns>
      None.
    """
    
    tuf.formats.THRESHOLD_SCHEMA.check_match(threshold)
    
    roleinfo = tuf.roledb.get_roleinfo(self._rolename)
    roleinfo['threshold'] = threshold
    
    tuf.roledb.update_roleinfo(self._rolename, roleinfo)
    self._threshold = threshold
 

  @property
  def expiration(self):
    """
    <Purpose>

      >>> 
      >>> 
      >>> 

    <Arguments>
      None.
    
    <Exceptions>
      None.

    <Side Effects>
      None.

    <Returns>
      The role's expiration datetime, conformant to tuf.formats.DATETIME_SCHEMA.
    """

    return self._expiration



  @expiration.setter
  def expiration(self, expiration_datetime_utc):
    """
    <Purpose>

      >>>  
      >>> 
      >>> 

    <Arguments>
      expiration_datetime_utc:
        tuf.formats.DATETIME_SCHEMA

    <Exceptions>
      tuf.FormatError, if the argument is improperly formatted.
    
    <Side Effects>
      Modifies the expiration attribute of the Repository object.

    <Returns>
      None.
    """
    
    # Does 'expiration_datetime_utc' have the correct format?
    # Raise 'tuf.FormatError' if there is a mismatch.
    tuf.formats.DATETIME_SCHEMA.check_match(expiration_datetime_utc)
   
    expiration_datetime_utc = expiration_datetime_utc+' UTC'
    try:
      unix_timestamp = tuf.formats.parse_time(expiration_datetime_utc)
    except (tuf.FormatError, ValueError), e:
      message = 'Invalid datetime argument: '+repr(expiration_datetime_utc)
      raise tuf.FormatError(message)
    
    if unix_timestamp < time.time():
      message = 'The expiration date must occur after the current date.'
      raise tuf.FormatError(message)
    
    self._expiration = expiration_datetime_utc



  def write_partial(self, object):
    """
    <Purpose>

      >>> 
      >>> 
      >>> 

    <Arguments>

    <Exceptions>

    <Side Effects>

    <Returns>
    """
    
    raise NotImplementedError()





class Root(Metadata):
  """
  <Purpose>

    >>> 
    >>> 
    >>> 

  <Arguments>

  <Exceptions>

  <Side Effects>

  <Returns>
  """

  def __init__(self):
    
    super(Root, self).__init__() 
    
    self._rolename = 'root'
    
    roleinfo = {'keyids': [], 'threshold': 1}
    tuf.roledb.add_role(self._rolename, roleinfo)


  def write_partial(self):
    pass





class Timestamp(Metadata):
  """
  <Purpose>

    >>>
    >>>
    >>>

  <Arguments>

  <Exceptions>

  <Side Effects>

  <Returns>
  """

  def __init__(self):
    
    super(Timestamp, self).__init__() 
    
    self._rolename = 'timestamp' 
    
    roleinfo = {'keyids': [], 'threshold': 1}
    tuf.roledb.add_role(self._rolename, roleinfo)



  def write_partial(self):
    pass





class Release(Metadata):
  """
  <Purpose>

    >>> 
    >>>
    >>>

  <Arguments>

  <Exceptions>

  <Side Effects>

  <Returns>
  """

  def __init__(self):
    
    super(Release, self).__init__() 
    
    self._rolename = 'release' 
    
    roleinfo = {'keyids': [], 'threshold': 1}
    tuf.roledb.add_role(self._rolename, roleinfo)



  def write_partial(self):
    pass





class Targets(Metadata):
  """
  <Purpose>

    >>> 
    >>>
    >>>

  <Arguments>
    targets_directory:
      The targets directory of the Repository object.

  <Exceptions>
    tuf.FormatError, if the targets directory argument is improerly formatted.

  <Side Effects>
    Mofifies the roleinfo of the targets role in 'tuf.roledb'.
  
  <Returns>
    None.
  """
  
  def __init__(self, rolename, targets_directory):
   
    # Do the arguments have the correct format?
    # Raise 'tuf.FormatError' if any are improperly formatted.
    tuf.formats.ROLENAME_SCHEMA.check_match(rolename)
    tuf.formats.PATH_SCHEMA.check_match(targets_directory)
    
    super(Targets, self).__init__()
    self._targets_directory = targets_directory
    self._rolename = rolename 
    self._target_files = []
    self._delegations = {}

    roleinfo = {'keyids': [], 'threshold': 1, 'paths': [],
                'path_hash_prefixes': [],
                'delegations': {'keys': {},
                                'roles': []}}

    tuf.roledb.add_role(self._rolename, roleinfo)



  @property
  def target_files(self):
    """
    <Purpose>

      >>> 
      >>>
      >>>

    <Arguments>
      targets_directory:
        The targets directory of the Repository object.

    <Exceptions>
      tuf.FormatError, if the targets directory argument is improerly formatted.

    <Side Effects>
      Mofifies the roleinfo of the targets role in 'tuf.roledb'.
    
    <Returns>
      None.
    """

    return self._target_files



  def write_partial(self):
    pass




  def add_target(self, filepath):
    """
    <Purpose>
      Add a filepath (relative to 'self.targets_directory') to the Targets
      object.  This function does not actually create 'filepath' on the file
      system.  'filepath' must already exist on the file system.
      
      Support regular expresssions?

      >>> 
      >>>
      >>>

    <Arguments>
      filepath:

    <Exceptions>
      tuf.FormatError, if 'filepath' is improperly formatted.

    <Side Effects>
      Adds 'filepath' to this role's list of targets.  This role's
      'tuf.roledb.py' is also updated.

    <Returns>
      None.
    """
    
    # Does 'filepath' have the correct format?
    # Raise 'tuf.FormatError' if there is a mismatch.
    tuf.formats.PATH_SCHEMA.check_match(filepath)

    filepath = os.path.abspath(filepath)
    
    if not os.path.commonprefix([self._targets_directory, filepath]) == \
                                self._targets_directory:
      message = repr(filepath)+' is not under the Repository\'s targets '+\
        'directory: '+repr(self._targets_directory)
      raise tuf.Error(message)

    # TODO: Ensure is an allowed target path according to the parent's
    # delegation.
    """
        for child_target in actual_child_targets:
          for allowed_child_path in allowed_child_paths:
            prefix = os.path.commonprefix([child_target, allowed_child_path])
            if prefix == allowed_child_path:
              break
    """

    # Add 'filepath' (i.e., relative to the targets directory) to the role's
    # list of targets. 
    if os.path.isfile(filepath):
      
      # Update the role's 'tuf.roledb.py' entry and 'self._target_files'.
      targets_directory_length = len(self._targets_directory) 
      roleinfo = tuf.roledb.get_roleinfo(self._rolename)
      roleinfo['paths'].append(filepath[targets_directory_length+1:])
      tuf.roledb.update_roleinfo(self._rolename, roleinfo)
      self._target_files.append(filepath)
    
    else:
      message = repr(filepath)+' is not a valid file.'
      raise tuf.Error(message)
 

  
  def add_targets(self, list_of_targets):
    """
    <Purpose>
      Add a list of target filepaths (all relative to 'self.targets_directory').
      This function does not actually create files on the file system.  The
      list of target must already exist.
      
      >>> 
      >>>
      >>>

    <Arguments>
      list_of_targets:

    <Exceptions>

    <Side Effects>
      
    <Returns>
      None.
    """

    # Does 'list_of_targets' have the correct format?
    # Raise 'tuf.FormatError' if it is improperly formatted.
    tuf.formats.RELPATHS_SCHEMA.check_match(list_of_targets)

    # TODO: Ensure list of targets allowed paths according to the parent's
    # delegation.

    # TODO: Update the tuf.roledb entry.
    targets_directory_length = len(self._targets_directory) 
    absolute_paths_list_of_targets = []
    relative_list_of_targets = []
    
    for target in list_of_targets:
      filepath = os.path.abspath(filepath)
      
      if not os.path.commonprefix([self._targets_directory, filepath]) == \
                                  self._targets_directory:
        message = repr(filepath)+' is not under the Repository\'s targets '+\
          'directory: '+repr(self._targets_directory)
        raise tuf.Error(message)
      if os.path.isfile(filepath):
        absolute_paths_list_of_targets.append(filepath)
        relative_list_of_targets.append(filepath[targets_directory_length+1:])
      else:
        message = repr(filepath)+' is not a valid file.'
        raise tuf.Error(message)

    # Update the role's target_files and its 'tuf.roledb.py' entry.
    self._target_files.extend(absolute_list_of_targets)
    roleinfo = tuf.roledb.get_roleinfo(self._rolename)
    roleinfo['paths'].extend(relative_list_of_targets)
    tuf.roledb.update_roleinfo(self._rolename, roleinfo)
  
  
  
  def remove_target(self, filepath):
    """
    <Purpose>
      Takes a filepath relative to the targets directory.  Regular expresssions
      would be useful here.

      >>> 
      >>>
      >>>

    <Arguments>
      filepath:

    <Exceptions>
      tuf.FormatError, if 'filepath' is improperly formatted.

    <Side Effects>
      Modifies the target role's 'tuf.roledb.py' entry.
    <Returns>
      None.
    """
  
  
  
  
  
  def delegate(self, rolename, public_keys, list_of_targets, restricted_paths=None):
    """
    <Purpose>
      'targets' is a list of target filepaths, and can be empty.

      >>> 
      >>>
      >>>

    <Arguments>
      rolename:

      public_keys:

      list_of_targets:

      restricted_paths:

    <Exceptions>
      tuf.FormatError, if any of the arguments are improperly formatted.

    <Side Effects>
      A new Target object is created for 'rolename' that is accessible to the
      caller (i.e., targets.unclaimed.<rolename>).  The 'tuf.keydb.py' and
      'tuf.roledb.py' stores are updated with 'public_keys'.

    <Returns>
      None.
    """

    # Do the arguments have the correct format?
    # Raise 'tuf.FormatError' if any of the arguments are improperly formatted.
    tuf.formats.ROLENAME_SCHEMA.check_match(rolename)
    tuf.formats.ANYKEYLIST_SCHEMA.check_match(public_keys)
    tuf.formats.RELPATHS_SCHEMA.check_match(list_of_targets)

    # Validate 'list_of_targets'
    # Ensure 'restricted_paths' is allowed by current role according to the
    # parent. 
    
    # Update the 'delegations' field of the current role.
   
    full_rolename = self._rolename+'/'+rolename 
    keyids = [] 
      
    # Add public keys to tuf.keydb
    for key in public_keys:
      
      try:
        tuf.keydb.add_key(key)
      except tuf.KeyAlreadyExistsError, e:
        pass

      keyid = key['keyid']
      keyids.append(keyid)

    # Add role to 'tuf.roledb.py'
    roleinfo = {'keyids': keyids,
                'threshold': 1,
                'signatures': [],
                'paths': list_of_targets,
                'delegations': {'keys': {},
                                'roles': []}}
    tuf.roledb.add_role(full_rolename, roleinfo)
    
    new_targets_object = Targets(rolename, self._targets_directory)
    
    # Update 'new_targets_object' attributes.
    for key in public_keys:
      new_targets_object.add_key(key)

    self.__setattr__(rolename, new_targets_object)
  
  
  
  def revoke(self, rolename):
    """
    <Purpose>

      >>>
      >>>
      >>>

    <Arguments>
      rolename:
        Not the full rolename ('Django' in 'targets/unclaimed/Django') of the role the
        parent role (this role) wants to revoke.

    <Exceptions>
      tuf.FormatError, if 'rolename' is improperly formatted.

    <Side Effects>

    <Returns>
      None.
    """

    tuf.formats.ROLENAME_SCHEMA.check_match(rolename) 
    
    self.__delattr__(rolename)

    # Remove from this Target's delegations dict.

    # Remove from 'tuf.roledb.py'

    # Remove


def _prompt(message, result_type=str):
  """
    Prompt the user for input by printing 'message', converting
    the input to 'result_type', and returning the value to the
    caller.
  """

  return result_type(raw_input(message))





def _get_password(prompt='Password: ', confirm=False):
  """
    Return the password entered by the user.  If 'confirm'
    is True, the user is asked to enter the previously
    entered password once again.  If they match, the
    password is returned to the caller.
  """

  while True:
    # getpass() prompts the user for a password without echoing
    # the user input.
    password = getpass.getpass(prompt, sys.stderr)
    if not confirm:
      return password
    password2 = getpass.getpass('Confirm: ', sys.stderr)
    if password == password2:
      return password
    else:
      print 'Mismatch; try again.'





def _check_directory(directory):
  """
  <Purpose>
    Ensure 'directory' is valid and it exists.  This is not a security check,
    but a way for the caller to determine the cause of an invalid directory
    provided by the user.  If the directory argument is valid, it is returned
    normalized and as an absolute path.

  <Arguments>
    directory:
      The directory to check.

  <Exceptions>
    tuf.Error, if 'directory' could not be validated.

    tuf.FormatError, if 'directory' is not properly formatted.

  <Side Effects>
    None.

  <Returns>
    The normalized absolutized path of 'directory'.
  """

  # Does 'directory' have the correct format?
  # Raise 'tuf.FormatError' if there is a mismatch.
  tuf.formats.PATH_SCHEMA.check_match(directory)

  # Check if the directory exists.
  if not os.path.isdir(directory):
    raise tuf.Error(repr(directory)+' directory does not exist')

  directory = os.path.abspath(directory)
  
  return directory





def create_new_repository(repository_directory):
  """
  <Purpose>
    Create a new repository with barebones metadata and return a Repository
    object.

  <Arguments>
    repository_directory:

  <Exceptions>

  <Side Effects>

  <Returns>
    libtuf.Repository object.
  """

  tuf.formats.PATH_SCHEMA.check_match(repository_directory)

  # Create the repository, metadata, and target directories.
  repository_directory = os.path.abspath(repository_directory)
  metadata_directory = None
  targets_directory = None
  
  # Try to create 'repository_directory' if it does not exist.
  try:
    os.makedirs(repository_directory)
  # 'OSError' raised if the leaf directory already exists or cannot be created.
  except OSError, e:
    if e.errno == errno.EEXIST:
      pass 
    else:
      raise
  
  #  
  metadata_directory = \
    os.path.join(repository_directory, METADATA_DIRECTORY_NAME)
  targets_directory = \
    os.path.join(repository_directory, TARGETS_DIRECTORY_NAME) 
  
  # Try to create the metadata directory that will hold all of the metadata
  # files, such as 'root.txt' and 'release.txt'.
  try:
    message = 'Creating '+repr(metadata_directory)
    logger.info(message)
    os.mkdir(metadata_directory)
  except OSError, e:
    if e.errno == errno.EEXIST:
      pass
    else:
      raise
  
  # Try to create the targets directory that will hold all of the target files.
  try:
    message = 'Creating '+repr(targets_directory)
    logger.info(message)
    os.mkdir(targets_directory)
  except OSError, e:
    if e.errno == errno.EEXIST:
      pass
    else:
      raise
  
  repository = Repository(repository_directory, metadata_directory,
                          targets_directory)
  
  return repository



def load_repository(repository_directory, partial_metadata_suffix=None):
  """
  <Purpose>
    Return a repository object that represents an existing repository.

  <Arguments>
    repository_directory:

    partial_metadata_suffix:

  <Exceptions>

  <Side Effects>

  <Returns>
    libtuf.Repository object.
  """




def generate_and_write_rsa_keypair(filepath, bits=DEFAULT_RSA_KEY_BITS,
                                   password=None):
  """
  <Purpose>
    Return a repository object that represents an existing repository.

  <Arguments>
    filepath:
      The public and private key files are saved to <filepath>.pub, <filepath>,
      respectively.
    
    bits:
      The number of bits of the generated RSA key. 

    password:

  <Exceptions>

  <Side Effects>

  <Returns>
  """

  # Does 'filepath' have the correct format?
  # Raise 'tuf.FormatError' if there is a mismatch.
  tuf.formats.PATH_SCHEMA.check_match(filepath)

  # Does 'bits' have the correct format?
  tuf.formats.RSAKEYBITS_SCHEMA.check_match(bits)

  # If the caller does not provide a password argument, prompt for one.
  if password is None:
    message = 'Enter a password for the RSA key: '
    password = _get_password(message, confirm=True)

  # Does 'password' have the correct format?
  tuf.formats.PASSWORD_SCHEMA.check_match(password)
  
  rsa_key = tuf.keys.generate_rsa_key(bits)
  public = rsa_key['keyval']['public']
  private = rsa_key['keyval']['private']
  encrypted_pem = tuf.keys.create_rsa_encrypted_pem(private, password) 
 
  # Write public key (i.e., 'public', which is in PEM format) to
  # '<filepath>.pub'
  with open(filepath+'.pub', 'w') as file_object:
    file_object.write(public)

  # Write the private key in encrypted PEM format to '<filepath>'.
  with open(filepath, 'w') as file_object:
    file_object.write(encrypted_pem)





def import_rsa_privatekey_from_file(filepath, password=None):
  """
  <Purpose>

  <Arguments>
    filepath:
      <filepath> file, an RSA encrypted PEM file.
    
    password:
      The passphrase to decrypt 'filepath'.

  <Exceptions>

  <Side Effects>

  <Returns>
  """

  # Does 'filepath' have the correct format?
  # Raise 'tuf.FormatError' if there is a mismatch.
  tuf.formats.PATH_SCHEMA.check_match(filepath)

  # If the caller does not provide a password argument, prompt for one.
  if password is None:
    message = 'Enter a password for the RSA key: '
    password = _get_password(message, confirm=True)

  # Does 'password' have the correct format?
  tuf.formats.PASSWORD_SCHEMA.check_match(password)

  encrypted_pem = None

  with open(filepath, 'rb') as file_object:
    encrypted_pem = file_object.read()

  rsa_key = tuf.keys.import_rsakey_from_encrypted_pem(encrypted_pem, password)
  
  return rsa_key





def import_rsa_publickey_from_file(filepath):
  """
  <Purpose>

  <Arguments>
    filepath:
      <filepath>.pub file, an RSA PEM file.
    
  <Exceptions>

  <Side Effects>

  <Returns>
  """

  # Does 'filepath' have the correct format?
  # Raise 'tuf.FormatError' if there is a mismatch.
  tuf.formats.PATH_SCHEMA.check_match(filepath)

  with open(filepath, 'rb') as file_object:
    rsa_pubkey_pem = file_object.read()

  rsakey_dict = tuf.keys.format_rsakey_from_pem(rsa_pubkey_pem)

  return rsakey_dict





def expiration_datetime_utc(input_datetime_utc):
  """
  <Purpose>
    TODO: return 'input_datetime_utc' in ISO 8601 format.

  <Arguments>
    input_datetime_utc:

  <Exceptions>
    tuf.FormatError, if 'input_datetime_utc' is invalid. 

  <Side Effects>
    None.

  <Returns>
  """
  if not tuf.formats.DATETIME_SCHEMA.matches(input_datetime_utc):
    message = 'The datetime argument must be in "YYYY-MM-DD HH:MM:SS" format.'
    raise tuf.FormatError(message)
  try:
    unix_timestamp = tuf.formats.parse_time(input_datetime_utc+' UTC')
  except (tuf.FormatError, ValueError), e:
    raise tuf.FormatError('Invalid date entered.')
  
  if unix_timestamp < time.time():
    message = 'The expiration date must occur after the current date.'
    raise tuf.FormatError(message)
  
  return input_datetime_utc+' UTC'




def get_metadata_filenames(metadata_directory=None):
  """
  <Purpose>
    Return a dictionary containing the filenames of the top-level roles.
    If 'metadata_directory' is set to 'metadata', the dictionary
    returned would contain:

    filenames = {'root': 'metadata/root.txt',
                 'targets': 'metadata/targets.txt',
                 'release': 'metadata/release.txt',
                 'timestamp': 'metadata/timestamp.txt'}

    If the metadata directory is not set by the caller, the current
    directory is used.

  <Arguments>
    metadata_directory:
      The directory containing the metadata files.

  <Exceptions>
    tuf.FormatError, if 'metadata_directory' is improperly formatted.

  <Side Effects>
    None.

  <Returns>
    A dictionary containing the expected filenames of the top-level
    metadata files, such as 'root.txt' and 'release.txt'.
  """

  if metadata_directory is None:
    metadata_directory = '.'

  # Does 'metadata_directory' have the correct format?
  # Raise 'tuf.FormatError' if there is a mismatch. 
  tuf.formats.PATH_SCHEMA.check_match(metadata_directory)

  filenames = {}
  filenames[ROOT_FILENAME] = os.path.join(metadata_directory, ROOT_FILENAME)
  filenames[TARGETS_FILENAME] = os.path.join(metadata_directory, TARGETS_FILENAME)
  filenames[RELEASE_FILENAME] = os.path.join(metadata_directory, RELEASE_FILENAME)
  filenames[TIMESTAMP_FILENAME] = os.path.join(metadata_directory, TIMESTAMP_FILENAME)

  return filenames





def get_metadata_file_info(filename):
  """
  <Purpose>
    Retrieve the file information for 'filename'.  The object returned
    conforms to 'tuf.formats.FILEINFO_SCHEMA'.  The information
    generated for 'filename' is stored in metadata files like 'targets.txt'.
    The fileinfo object returned has the form:
    fileinfo = {'length': 1024,
                'hashes': {'sha256': 1233dfba312, ...},
                'custom': {...}}

  <Arguments>
    filename:
      The metadata file whose file information is needed.

  <Exceptions>
    tuf.FormatError, if 'filename' is improperly formatted.

    tuf.Error, if 'filename' doesn't exist.

  <Side Effects>
    The file is opened and information about the file is generated,
    such as file size and its hash.

  <Returns>
    A dictionary conformant to 'tuf.formats.FILEINFO_SCHEMA'.  This
    dictionary contains the length, hashes, and custom data about
    the 'filename' metadata file.
  """

  # Does 'filename' have the correct format?
  # Raise 'tuf.FormatError' if there is a mismatch.
  tuf.formats.PATH_SCHEMA.check_match(filename)

  if not os.path.isfile(filename):
    message = repr(filename)+' is not a file.'
    raise tuf.Error(message)
  
  # Note: 'filehashes' is a dictionary of the form
  # {'sha256': 1233dfba312, ...}.  'custom' is an optional
  # dictionary that a client might define to include additional
  # file information, such as the file's author, version/revision
  # numbers, etc.
  filesize, filehashes = tuf.util.get_file_details(filename)
  custom = None

  return tuf.formats.make_fileinfo(filesize, filehashes, custom)





def generate_root_metadata(version, expiration_date):
  """
  <Purpose>
    Create the root metadata.  'tuf.roledb.py' and 'tuf.keydb.py' are read and the
    information returned by these modules are used to generate the root metadata
    object.

  <Arguments>
    version:
      The metadata version number.  Clients use the version number to
      determine if the downloaded version is newer than the one currently
      trusted.
    
    expiration_date:

  <Exceptions>
    tuf.FormatError, if the generated root metadata object could not
    be generated with the correct format.

    tuf.Error, if an error is encountered while generating the root
    metadata object.
  
  <Side Effects>
    The contents of 'tuf.keydb.py' and 'tuf.roledb.py' are read.

  <Returns>
    A root 'signable' object conformant to 'tuf.formats.SIGNABLE_SCHEMA'.
  """

  # Do the arguments have the correct format?
  # Raise 'tuf.FormatError' if any of the arguments are improperly formatted.
  tuf.formats.METADATAVERSION_SCHEMA.check_match(version)
  tuf.formats.TIME_SCHEMA.check_match(expiration_date)

  # The role and key dictionaries to be saved in the root metadata object.
  roledict = {}
  keydict = {}

  # Extract the role, threshold, and keyid information from the config.
  # The necessary role metadata is generated from this information.
  for rolename in ['root', 'targets', 'release', 'timestamp']:
    
    # If a top-level role is missing from 'tuf.roledb.py', raise an exception.
    if not tuf.roledb.role_exists(rolename):
      raise tuf.Error(repr(rolename)+' not in "tuf.roledb".')
    
    keyids = []
    # Generate keys for the keyids listed by the role being processed.
    for keyid in tuf.roledb.get_role_keyids(rolename):
      key = tuf.keydb.get_key(keyid)

      # If 'key' is an RSA key, it would conform to 'tuf.formats.RSAKEY_SCHEMA',
      # and have the form:
      # {'keytype': 'rsa',
      #  'keyid': keyid,
      #  'keyval': {'public': '-----BEGIN RSA PUBLIC KEY----- ...',
      #             'private': '-----BEGIN RSA PRIVATE KEY----- ...'}}
      keyid = key['keyid']
      if keyid not in keydict:
        
        # This appears to be a new keyid.  Let's generate the key for it.
        if key['keytype'] in ['rsa', 'ed25519']:
          keytype = key['keytype']
          keyval = key['keyval']
          keydict[keyid] = \
            tuf.keys.format_keyval_to_metadata(keytype, keyval)
        
        # This is not a recognized key.  Raise an exception.
        else:
          raise tuf.Error('Unsupported keytype: '+keyid)
      
      # Do we have a duplicate?
      if keyid in keyids:
        raise tuf.Error('Same keyid listed twice: '+keyid)
      
      # Add the loaded keyid for the role being processed.
      keyids.append(keyid)
    
    # Generate and store the role data belonging to the processed role.
    role_threshold = tuf.roledb.get_role_threshold(rolename)
    role_metadata = tuf.formats.make_role_metadata(keyids, role_threshold)
    roledict[rolename] = role_metadata

  # Generate the root metadata object.
  root_metadata = tuf.formats.RootFile.make_metadata(version, expiration_date,
                                                     keydict, roledict)

  # Note: make_signable() returns the following dictionary:
  # {'signed' : role_metadata, 'signatures' : []}
  return tuf.formats.make_signable(root_metadata)





def generate_targets_metadata(repository_directory, target_files, version,
                              expiration_date):
  """
  <Purpose>
    Generate the targets metadata object. The targets must exist at the same
    path they should on the repo.  'target_files' is a list of targets. We're
    not worrying about custom metadata at the moment. It is allowed to not
    provide keys.

  <Arguments>
    target_files:
      The target files tracked by 'targets.txt'.  'target_files' is a list of
      paths/directories of target files that are relative to the repository
      (e.g., ['targets/file1.txt', ...]).  If the target files are saved in
      the root folder 'targets' on the repository, then 'targets' must be
      included in the target paths.  The repository does not have to name
      this folder 'targets'.

    repository_directory:
      The directory (absolute path) containing the metadata and target
      directories.

    version:
      The metadata version number.  Clients use the version number to
      determine if the downloaded version is newer than the one currently
      trusted.

    expiration_date:
      The expiration date, in UTC, of the metadata file.
      Conformant to 'tuf.formats.TIME_SCHEMA'.
  
  <Exceptions>
    tuf.FormatError, if an error occurred trying to generate the targets
    metadata object.

    tuf.Error, if any of the target files could not be read. 

  <Side Effects>
    The target files are read and file information generated about them.

  <Returns>
    A targets 'signable' object, conformant to 'tuf.formats.SIGNABLE_SCHEMA'.
  """

  # Do the arguments have the correct format.
  # Raise 'tuf.FormatError' if there is a mismatch.
  tuf.formats.PATHS_SCHEMA.check_match(target_files)
  tuf.formats.PATH_SCHEMA.check_match(repository_directory)
  tuf.formats.METADATAVERSION_SCHEMA.check_match(version)
  tuf.formats.TIME_SCHEMA.check_match(expiration_date)

  filedict = {}

  repository_directory = _check_directory(repository_directory)

  # Generate the file info for all the target files listed in 'target_files'.
  for target in target_files:
    # Strip 'targets/' from from 'target' and keep the rest (e.g.,
    # 'targets/more_targets/somefile.txt' -> 'more_targets/somefile.txt'
    relative_targetpath = os.path.sep.join(target.split(os.path.sep)[1:])
    target_path = os.path.join(repository_directory, target)
    if not os.path.exists(target_path):
      message = repr(target_path)+' could not be read.  Unable to generate '+\
        'targets metadata.'
      raise tuf.Error(message)
    filedict[relative_targetpath] = get_metadata_file_info(target_path)

  # Generate the targets metadata object.
  targets_metadata = tuf.formats.TargetsFile.make_metadata(version,
                                                           expiration_date,
                                                           filedict)

  return tuf.formats.make_signable(targets_metadata)





def generate_release_metadata(metadata_directory, version, expiration_date):
  """
  <Purpose>
    Create the release metadata.  The minimum metadata must exist
    (i.e., 'root.txt' and 'targets.txt'). This will also look through
    the 'targets/' directory in 'metadata_directory' and the resulting
    release file will list all the delegated roles.

  <Arguments>
    metadata_directory:
      The directory containing the 'root.txt' and 'targets.txt' metadata
      files.
    
    version:
      The metadata version number.  Clients use the version number to
      determine if the downloaded version is newer than the one currently
      trusted.

    expiration_date:
      The expiration date, in UTC, of the metadata file.
      Conformant to 'tuf.formats.TIME_SCHEMA'.

  <Exceptions>
    tuf.FormatError, if 'metadata_directory' is improperly formatted.

    tuf.Error, if an error occurred trying to generate the release metadata
    object.

  <Side Effects>
    The 'root.txt' and 'targets.txt' files are read.

  <Returns>
    The release 'signable' object, conformant to 'tuf.formats.SIGNABLE_SCHEMA'.
  """

  # Does 'metadata_directory' have the correct format?
  # Raise 'tuf.FormatError' if there is a mismatch.
  tuf.formats.PATH_SCHEMA.check_match(metadata_directory)
  tuf.formats.METADATAVERSION_SCHEMA.check_match(version)
  tuf.formats.TIME_SCHEMA.check_match(expiration_date)

  metadata_directory = _check_directory(metadata_directory)

  # Retrieve the full filepath of the root and targets metadata file.
  root_filename = os.path.join(metadata_directory, ROOT_FILENAME)
  targets_filename = os.path.join(metadata_directory, TARGETS_FILENAME)

  # Retrieve the file info of 'root.txt' and 'targets.txt'.  This file
  # information includes data such as file length, hashes of the file, etc.
  filedict = {}
  filedict[ROOT_FILENAME] = get_metadata_file_info(root_filename)
  filedict[TARGETS_FILENAME] = get_metadata_file_info(targets_filename)

  # Walk the 'targets/' directory and generate the file info for all
  # the files listed there.  This information is stored in the 'meta'
  # field of the release metadata object.
  targets_metadata = os.path.join(metadata_directory, 'targets')
  if os.path.exists(targets_metadata) and os.path.isdir(targets_metadata):
    for directory_path, junk, files in os.walk(targets_metadata):
      # 'files' here is a list of target file names.
      for basename in files:
        metadata_path = os.path.join(directory_path, basename)
        metadata_name = metadata_path[len(metadata_directory):].lstrip(os.path.sep)
        filedict[metadata_name] = get_metadata_file_info(metadata_path)

  # Generate the release metadata object.
  release_metadata = tuf.formats.ReleaseFile.make_metadata(version,
                                                           expiration_date,
                                                           filedict)

  return tuf.formats.make_signable(release_metadata)





def generate_timestamp_metadata(release_filename, version,
                                expiration_date, compressions=()):
  """
  <Purpose>
    Generate the timestamp metadata object.  The 'release.txt' file must exist.

  <Arguments>
    release_filename:
      The required filename of the release metadata file.
    
    version:
      The metadata version number.  Clients use the version number to
      determine if the downloaded version is newer than the one currently
      trusted.

    expiration_date:
      The expiration date, in UTC, of the metadata file.
      Conformant to 'tuf.formats.TIME_SCHEMA'.

    compressions:
      Compression extensions (e.g., 'gz').  If 'release.txt' is also saved in
      compressed form, these compression extensions should be stored in
      'compressions' so the compressed timestamp files can be added to the
      timestamp metadata object.

  <Exceptions>
    tuf.FormatError, if the generated timestamp metadata object could
    not be formatted correctly.

  <Side Effects>
    None.

  <Returns>
    A timestamp 'signable' object, conformant to 'tuf.formats.SIGNABLE_SCHEMA'.
  """

  # Do the arguments have the correct format?
  # Raise 'tuf.FormatError' if there is  mismatch.
  tuf.formats.PATH_SCHEMA.check_match(release_filename)
  tuf.formats.METADATAVERSION_SCHEMA.check_match(version)
  tuf.formats.TIME_SCHEMA.check_match(expiration_date)

  # Retrieve the file info for the release metadata file.
  # This file information contains hashes, file length, custom data, etc.
  fileinfo = {}
  fileinfo[RELEASE_FILENAME] = get_metadata_file_info(release_filename)

  # Save the file info of the compressed versions of 'timestamp.txt'.
  for file_extension in compressions:
    compressed_filename = release_filename + '.' + file_extension
    try:
      compressed_fileinfo = get_metadata_file_info(compressed_filename)
    except:
      logger.warn('Could not get fileinfo about '+str(compressed_filename))
    else:
      logger.info('Including fileinfo about '+str(compressed_filename))
      fileinfo[RELEASE_FILENAME+'.' + file_extension] = compressed_fileinfo

  # Generate the timestamp metadata object.
  timestamp_metadata = tuf.formats.TimestampFile.make_metadata(version,
                                                               expiration_date,
                                                               fileinfo)

  return tuf.formats.make_signable(timestamp_metadata)





def sign_metadata(metadata, keyids, filename):
  """
  <Purpose>
    Sign a metadata object. If any of the keyids have already signed the file,
    the old signature will be replaced.  The keys in 'keyids' must already be
    loaded in the keystore.

  <Arguments>
    metadata:
      The metadata object to sign.  For example, 'metadata' might correspond to
      'tuf.formats.ROOT_SCHEMA' or 'tuf.formats.TARGETS_SCHEMA'.

    keyids:
      The keyids list of the signing keys.

    filename:
      The intended filename of the signed metadata object.
      For example, 'root.txt' or 'targets.txt'.  This function
      does NOT save the signed metadata to this filename.

  <Exceptions>
    tuf.FormatError, if a valid 'signable' object could not be generated.

    tuf.Error, if an invalid keytype was found in the keystore. 
  
  <Side Effects>
    None.

  <Returns>
    A signable object conformant to 'tuf.formats.SIGNABLE_SCHEMA'.
  """

  # Does 'keyids' and 'filename' have the correct format?
  # Raise 'tuf.FormatError' if there is a mismatch.
  tuf.formats.KEYIDS_SCHEMA.check_match(keyids)
  tuf.formats.PATH_SCHEMA.check_match(filename)

  # Make sure the metadata is in 'signable' format.  That is,
  # it contains a 'signatures' field containing the result
  # of signing the 'signed' field of 'metadata' with each
  # keyid of 'keyids'.
  signable = tuf.formats.make_signable(metadata)

  # Sign the metadata with each keyid in 'keyids'.
  for keyid in keyids:
    # Load the signing key.
    key = tuf.repo.keystore.get_key(keyid)
    logger.info('Signing '+repr(filename)+' with '+key['keyid'])

    # Create a new signature list.  If 'keyid' is encountered,
    # do not add it to new list.
    signatures = []
    for signature in signable['signatures']:
      if not keyid == signature['keyid']:
        signatures.append(signature)
    signable['signatures'] = signatures

    # Generate the signature using the appropriate signing method.
    if key['keytype'] == 'rsa':
      signed = signable['signed']
      signature = tuf.sig.generate_rsa_signature(signed, key)
      signable['signatures'].append(signature)
    else:
      raise tuf.Error('The keystore contains a key with an invalid key type')

  # Raise 'tuf.FormatError' if the resulting 'signable' is not formatted
  # correctly.
  tuf.formats.check_signable_object_format(signable)

  return signable





def write_metadata_file(metadata, filename, compression=None):
  """
  <Purpose>
    Create the file containing the metadata.

  <Arguments>
    metadata:
      The object that will be saved to 'filename'.

    filename:
      The filename (absolute path) of the metadata to be
      written (e.g., 'root.txt').

    compression:
      Specify an algorithm as a string to compress the file; otherwise, the
      file will be left uncompressed. Available options are 'gz' (gzip).

  <Exceptions>
    tuf.FormatError, if the arguments are improperly formatted.

    tuf.Error, if 'filename' doesn't exist.

    Any other runtime (e.g. IO) exception.

  <Side Effects>
    The 'filename' file is created or overwritten if it exists.

  <Returns>
    The path to the written metadata file.
  """

  # Are the arguments properly formatted?
  # Raise 'tuf.FormatError' if there is a mismatch.
  tuf.formats.SIGNABLE_SCHEMA.check_match(metadata)
  tuf.formats.PATH_SCHEMA.check_match(filename)

  # Verify 'filename' directory.
  _check_directory(os.path.dirname(filename))

  # We choose a file-like object that depends on the compression algorithm.
  file_object = None
  # We may modify the filename, depending on the compression algorithm, so we
  # store it separately.
  filename_with_compression = filename

  # Take care of compression.
  if compression is None:
    logger.info('No compression for '+str(filename))
    file_object = open(filename_with_compression, 'w')
  elif compression == 'gz':
    logger.info('gzip compression for '+str(filename))
    filename_with_compression += '.gz'
    file_object = gzip.open(filename_with_compression, 'w')
  else:
    raise tuf.FormatError('Unknown compression algorithm: '+str(compression))

  try:
    tuf.formats.PATH_SCHEMA.check_match(filename_with_compression)
    logger.info('Writing to '+str(filename_with_compression))

    # The metadata object is saved to 'file_object'.  The keys
    # of the objects are sorted and indentation is used.
    json.dump(metadata, file_object, indent=1, sort_keys=True)

    file_object.write('\n')
  except:
    # Raise any runtime exception.
    raise
  else:
    # Otherwise, return the written filename.
    return filename_with_compression
  finally:
    # Always close the file.
    file_object.close()





def build_delegated_role_file(delegated_targets_directory, delegated_keyids, 
                              metadata_directory, delegation_metadata_directory,
                              delegation_role_name, version, expiration_date):
  """
  <Purpose>
    Build the targets metadata file using the signing keys in
    'delegated_keyids'.  The generated metadata file is saved to
    'metadata_directory'.  The target files located in 'targets_directory' will
    be tracked by the built targets metadata.

  <Arguments>
    delegated_targets_directory:
      The directory (absolute path) containing all the delegated target
      files.

    delegated_keyids:
      The list of keyids to be used as the signing keys for the delegated
      role file.

    metadata_directory:
      The metadata directory (absolute path) containing all the metadata files.

    delegation_metadata_directory:
      The location of the delegated role's metadata.

    delegation_role_name:
      The delegated role's file name ending in '.txt'.  Ex: 'role1.txt'.

    version:
      The metadata version number.  Clients use the version number to
      determine if the downloaded version is newer than the one currently
      trusted.

    expiration_date:
      The expiration date, in UTC, of the metadata file.
      Conformant to 'tuf.formats.TIME_SCHEMA'.

  <Exceptions>
    tuf.FormatError, if any of the arguments are improperly formatted.

    tuf.Error, if there was an error while building the targets file.

  <Side Effects>
    The targets metadata file is written to a file.

  <Returns>
    The path for the written targets metadata file.
  """

  # Do the arguments have the correct format?
  # Raise 'tuf.FormatError' if there is a mismatch.
  tuf.formats.PATH_SCHEMA.check_match(delegated_targets_directory)
  tuf.formats.KEYIDS_SCHEMA.check_match(delegated_keyids)
  tuf.formats.PATH_SCHEMA.check_match(metadata_directory)
  tuf.formats.PATH_SCHEMA.check_match(delegation_metadata_directory)
  tuf.formats.NAME_SCHEMA.check_match(delegation_role_name)

  # Check if 'targets_directory' and 'metadata_directory' are valid.
  targets_directory = _check_directory(delegated_targets_directory)
  metadata_directory = _check_directory(metadata_directory)

  repository_directory, junk = os.path.split(metadata_directory)
  repository_directory_length = len(repository_directory)

  # Get the list of targets.
  targets = []
  for root, directories, files in os.walk(targets_directory):
    for target_file in files:
      # Note: '+1' in the line below is there to remove '/'.
      filename = os.path.join(root, target_file)[repository_directory_length+1:]
      targets.append(filename)

  # Create the targets metadata object.
  targets_metadata = generate_targets_metadata(repository_directory, targets,
                                               version, expiration_date)

  # Sign it.
  targets_filepath = os.path.join(delegation_metadata_directory,
                                  delegation_role_name)
  signable = sign_metadata(targets_metadata, delegated_keyids, targets_filepath)

  return write_metadata_file(signable, targets_filepath)



if __name__ == '__main__':
  # The interactive sessions of the documentation strings can
  # be tested by running libtuf.py as a standalone module.
  # python libtuf.py.
  import doctest
  doctest.testmod()
