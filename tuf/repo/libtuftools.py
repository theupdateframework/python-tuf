"""
<Program Name>
  libtuftools.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  October 19, 2013 

<Copyright>
  See LICENSE for licensing information.

<Purpose>
"""

import getpass
import sys

import tuf
import tuf.formats
import tuf.keys


# Recommended RSA key sizes:
# http://www.emc.com/emc-plus/rsa-labs/historical/twirl-and-rsa-key-size.htm#table1 
# According to the document above, revised May 6, 2003, RSA keys of
# size 3072 provide security through 2031 and beyond.  2048-bit keys
# are the recommended minimum and are good from the present through 2030.
DEFAULT_RSA_KEY_BITS = 3072

# The metadata filenames for the top-level roles.
ROOT_FILENAME = 'root.json'
TARGETS_FILENAME = 'targets.json'
RELEASE_FILENAME = 'release.json'
TIMESTAMP_FILENAME = 'timestamp.json'

# Expiration date, in seconds, of the top-level roles (excluding 'Root').
# The expiration time of the 'Root' role is set by the user.  A metadata
# expiration date is set by taking the current time and adding the expiration
# seconds listed below.
# Initial 'targets.txt' expiration time of 3 months. 
TARGETS_EXPIRATION = 7889230 

# Initial 'release.txt' expiration time of 1 week. 
RELEASE_EXPIRATION = 604800 

# Initial 'timestamp.txt' expiration time of 1 day.
TIMESTAMP_EXPIRATION = 86400


class Repository:
  """
  <Purpose>
  
  <Arguments>

  <Exceptions>

  <Side Effects>

  <Returns>
    Repository object.
  """
 
  def __init__(self):
    self.root
    self.release
    self.timestamp
    self.targets
  
  
  
  def write(self):
    """
    <Purpose>
      Write all the Metadata objects' JSON contents to the corresponding files. 
    
    <Arguments>

    <Exceptions>

    <Side Effects>

    <Returns>
    """





class Metadata:
  """
  <Purpose>
    Write all the Metadata objects' JSON contents to the corresponding files. 
  
  <Arguments>

  <Exceptions>

  <Side Effects>

  <Returns>
  """

  def __init__(self):
    
    # This gets modified when methods are called and attributes changed.
    self._JSON_contents

    # Reference to Repository object.
    self._repository

    self.expiration

  
  
  
  def refresh(self, object):
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
    
    self.root_keys
    self.root_threshold
    self.timestamp_keys
    self.release_keys
    self.targets_keys
    self.default_expiration
 


  def write(self):
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
    pass


  def refresh(self):
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
    pass


  def refresh(self):
    pass





class Targets(Metadata):
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
    
    self.target_list
    self.delegation_list



  def refresh(self):
    pass




  def add_target(self, filepath):
    """
    <Purpose>
      Takes a filepath relative to the targets directory.  Regular expresssion
      would be useful here.

      >>> 
      >>>
      >>>

    <Arguments>
      filepath:

    <Exceptions>

    <Side Effects>

    <Returns>
    """
  
  
  
  
  
  def remove_target(self, filepath):
    """
    <Purpose>
      Takes a filepath relative to the targets directory.  Regular expresssion
      would be useful here.

      >>> 
      >>>
      >>>

    <Arguments>
      filepath:

    <Exceptions>

    <Side Effects>

    <Returns>
    """
  
  
  
  
  
  def delegate(self, rolename, public_keys, targets):
    """
    <Purpose>
      'targets' is a list of target filepaths, and can be empty.

      >>> 
      >>>
      >>>

    <Arguments>
      rolename:

      public_keys:

      targets:

    <Exceptions>

    <Side Effects>

    <Returns>
    """
  
  
  
  
  
  def revoke(self, rolename):
    """
    <Purpose>

      >>>
      >>>
      >>>

    <Arguments>
      rolename:

    <Exceptions>

    <Side Effects>

    <Returns>
    """
    




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
  




def create_new_repository(repository_directory):
  """
  <Purpose>
    Create a new repository with barebones metadata and return a Repository
    object representing it.

  <Arguments>
    repository_directory:

  <Exceptions>

  <Side Effects>

  <Returns>
    libtuftools.Repository object.
  """
  
  # Build the repository directories.
  metadata_directory = None
  targets_directory = None

  # Save the repository directory to the current directory, with
  # an initial name of 'repository'.  The repository maintainer
  # may opt to rename this directory and should transfer it elsewhere,
  # such as the webserver that will respond to TUF requests.
  repository_directory = os.path.join(os.getcwd(), 'repository')
  
  # Copy the files from the project directory to the repository's targets
  # directory.  The targets directory will hold all the individual
  # target files.
  targets_directory = os.path.join(repository_directory, 'targets')
  temporary_directory = tempfile.mkdtemp()
  temporary_targets = os.path.join(temporary_directory, 'targets')
  shutil.copytree(project_directory, temporary_targets)
  
  # Remove the log file created by the tuf logger, if it exists.
  # It might exist if the current directory was specified as the
  # project directory on the command-line.
  log_filename = tuf.log._DEFAULT_LOG_FILENAME
  if log_filename in os.listdir(temporary_targets):
    log_file = os.path.join(temporary_targets, log_filename)
    os.remove(log_file)

  # Try to create the repository directory.
  try:
    os.mkdir(repository_directory)
  # 'OSError' raised if the directory cannot be created.
  except OSError, e:
    message = 'Trying to create a new repository over an old repository '+\
      'installation.  Remove '+repr(repository_directory)+' before '+\
      'trying again.'
    if e.errno == errno.EEXIST:
      raise tuf.RepositoryError(message)
    else:
      raise

  # Move the temporary targets directory into place now that repository
  # directory has been created and remove previously created temporary
  # directory.
  shutil.move(temporary_targets, targets_directory)
  os.rmdir(temporary_directory)
  
  # Try to create the metadata directory that will hold all of the
  # metadata files, such as 'root.txt' and 'release.txt'.
  try:
    metadata_directory = os.path.join(repository_directory, 'metadata')
    message = 'Creating '+repr(metadata_directory)
    logger.info(message)
    os.mkdir(metadata_directory)
  except OSError, e:
    if e.errno == errno.EEXIST:
      pass
    else:
      raise

  # At this point the keystore is built and the 'role_info' dictionary
  # looks something like this:
  # {'keyids : [keyid1, keyid2] , 'threshold' : 2}

  # Generate the 'root.txt' metadata file. 
  # Newly created metadata start at version 1.  The expiration date for the
  # 'Root' role is extracted from the configuration file that was set, above,
  # by the user.
  root_keyids = role_info['root']['keyids']
  tuf.repo.signerlib.build_root_file(config_filepath, root_keyids,
                                     metadata_directory, 1)

  # Generate the 'targets.txt' metadata file.
  targets_keyids = role_info['targets']['keyids']
  expiration_date = tuf.formats.format_time(time.time()+TARGETS_EXPIRATION)
  tuf.repo.signerlib.build_targets_file([targets_directory], targets_keyids,
                                        metadata_directory, 1,
                                        expiration_date)

  # Generate the 'release.txt' metadata file.
  release_keyids = role_info['release']['keyids']
  expiration_date = tuf.formats.format_time(time.time()+RELEASE_EXPIRATION)
  tuf.repo.signerlib.build_release_file(release_keyids, metadata_directory,
                                        1, expiration_date)

  # Generate the 'timestamp.txt' metadata file.
  timestamp_keyids = role_info['timestamp']['keyids']
  expiration_date = tuf.formats.format_time(time.time()+TIMESTAMP_EXPIRATION)
  tuf.repo.signerlib.build_timestamp_file(timestamp_keyids, metadata_directory,
                                          1, expiration_date)





def open_repository(filepath):
  """
  <Purpose>
    Return a repository object that represents an existing repository.

  <Arguments>
    filepath:

  <Exceptions>

  <Side Effects>

  <Returns>
    Repository object.
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

  tuf.formats.PEMRSA_SCHEMA.check_match(rsa_pubkey_pem)

  rsa_key = tuf.keys.import_rsakey_from_encrypted_pem(encrypted_pem, password)
  
  return rsa_key




def get_metadata_filenames(metadata_directory=None):
  """
  <Purpose>
    Return a dictionary containing the filenames of the top-level roles.
    If 'metadata_directory' is set to 'metadata', the dictionary
    returned would contain:

    filenames = {'root': 'metadata/root.json',
                 'targets': 'metadata/targets.json',
                 'release': 'metadata/release.json',
                 'timestamp': 'metadata/timestamp.json'}

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
    metadata files, such as 'root.json' and 'release.json'.
  """

  if metadata_directory is None:
    metadata_directory = '.'

  # Does 'metadata_directory' have the correct format?
  # Raise 'tuf.FormatError' if there is a mismatch. 
  tuf.formats.PATH_SCHEMA.check_match(metadata_directory)

  filenames = {}
  filenames['root'] = os.path.join(metadata_directory, ROOT_FILENAME)
  filenames['targets'] = os.path.join(metadata_directory, TARGETS_FILENAME)
  filenames['release'] = os.path.join(metadata_directory, RELEASE_FILENAME)
  filenames['timestamp'] = os.path.join(metadata_directory, TIMESTAMP_FILENAME)

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





def generate_root_metadata(config_filepath, version):
  """
  <Purpose>
    Create the root metadata.  'config_filepath' is read
    and the information contained in this file will be
    used to generate the root metadata object.

  <Arguments>
    config_filepath:
      The file containing metadata information such as the keyids
      of the top-level roles and expiration data.  'config_filepath'
      is an absolute path.
    
    version:
      The metadata version number.  Clients use the version number to
      determine if the downloaded version is newer than the one currently trusted.

  <Exceptions>
    tuf.FormatError, if the generated root metadata object could not
    be generated with the correct format.

    tuf.Error, if an error is encountered while generating the root
    metadata object.
  
  <Side Effects>
    'config_filepath' is read and its contents stored.

  <Returns>
    A root 'signable' object conformant to 'tuf.formats.SIGNABLE_SCHEMA'.
  """

  # Does 'config_filepath' have the correct format?
  # Raise 'tuf.FormatError' if the match fails.
  tuf.formats.PATH_SCHEMA.check_match(config_filepath)
  tuf.formats.METADATAVERSION_SCHEMA.check_match(version)

  # 'tuf.Error' raised if 'config_filepath' cannot be read. 
  config = read_config_file(config_filepath)

  # The role and key dictionaries to be saved in the root metadata object.
  roledict = {}
  keydict = {}

  # Extract the role, threshold, and keyid information from the config.
  # The necessary role metadata is generated from this information.
  for rolename in ['root', 'targets', 'release', 'timestamp']:
    # If a top-level role is missing from the config, raise an exception.
    if rolename not in config:
      raise tuf.Error('No '+rolename+' section found in config file.')
    keyids = []
    # Generate keys for the keyids listed by the role being processed.
    for config_keyid in config[rolename]['keyids']:
      key = tuf.repo.keystore.get_key(config_keyid)

      # If 'key' is an RSA key, it would conform to 'tuf.formats.RSAKEY_SCHEMA',
      # and have the form:
      # {'keytype': 'rsa',
      #  'keyid': keyid,
      #  'keyval': {'public': '-----BEGIN RSA PUBLIC KEY----- ...',
      #             'private': '-----BEGIN RSA PRIVATE KEY----- ...'}}
      keyid = key['keyid']
      # This appears to be a new keyid.  Let's generate the key for it.
      if keyid not in keydict:
        if key['keytype'] in ['rsa', 'ed25519']:
          keytype = key['keytype']
          keyval = key['keyval']
          keydict[keyid] = tuf.keys.create_in_metadata_format(keytype, keyval)
        # This is not a recognized key.  Raise an exception.
        else:
          raise tuf.Error('Unsupported keytype: '+keyid)
      # Do we have a duplicate?  Raise an exception if so.
      if keyid in keyids:
        raise tuf.Error('Same keyid listed twice: '+keyid)
      # Add the loaded keyid for the role being processed.
      keyids.append(keyid)
    # Generate and store the role data belonging to the processed role.
    role_metadata = tuf.formats.make_role_metadata(keyids, config[rolename]['threshold'])
    roledict[rolename] = role_metadata

  # Extract the expiration information from the config.  The root metadata
  # object stores this expiration information in total seconds.
  expiration = config['expiration']
  expiration_seconds = (expiration['seconds'] + 60 * expiration['minutes'] +
                        3600 * expiration['hours'] +
                        3600 * 24 * expiration['days'])

  # Generate the root metadata object.
  root_metadata = tuf.formats.RootFile.make_metadata(version, expiration_seconds,
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
      determine if the downloaded version is newer than the one currently trusted.

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

  repository_directory = check_directory(repository_directory)

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
      determine if the downloaded version is newer than the one currently trusted.

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

  metadata_directory = check_directory(metadata_directory)

  # Retrieve the full filepath of the root and targets metadata file.
  root_filename = os.path.join(metadata_directory, 'root.txt')
  targets_filename = os.path.join(metadata_directory, 'targets.txt')

  # Retrieve the file info of 'root.txt' and 'targets.txt'.  This file
  # information includes data such as file length, hashes of the file, etc.
  filedict = {}
  filedict['root.txt'] = get_metadata_file_info(root_filename)
  filedict['targets.txt'] = get_metadata_file_info(targets_filename)

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
      determine if the downloaded version is newer than the one currently trusted.

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
  fileinfo['release.txt'] = get_metadata_file_info(release_filename)

  # Save the file info of the compressed versions of 'timestamp.txt'.
  for file_extension in compressions:
    compressed_filename = release_filename + '.' + file_extension
    try:
      compressed_fileinfo = get_metadata_file_info(compressed_filename)
    except:
      logger.warn('Could not get fileinfo about '+str(compressed_filename))
    else:
      logger.info('Including fileinfo about '+str(compressed_filename))
      fileinfo['release.txt.' + file_extension] = compressed_fileinfo

  # Generate the timestamp metadata object.
  timestamp_metadata = tuf.formats.TimestampFile.make_metadata(version,
                                                               expiration_date,
                                                               fileinfo)

  return tuf.formats.make_signable(timestamp_metadata)





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
  check_directory(os.path.dirname(filename))

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





def generate_and_save_rsa_key(keystore_directory, password,
                              bits=DEFAULT_RSA_KEY_BITS):
  """
  <Purpose>
    Generate a new RSA key and save it as an encrypted key file
    to 'keystore_directory'.  The encrypted key file is named:
    <keyid>.key.  'password' is used as the encryption key.

  <Arguments>
    keystore_directory:
      The directory to save the generated encrypted key file.

    password:
      The password used to encrypt the RSA key file.

    bits:
      The key size, or key length, of the RSA key.
      If 'bits' is unspecified, a 3072-bit RSA key is generated, which is the
      key size recommended by TUF, although 2048-bit keys are accepted
      (minimum key size).

  <Exceptions>
    tuf.FormatError, if 'bits' or 'password' does not have the
    correct format.

    tuf.CryptoError, if there was an error while generating the key.

  <Side Effects>
    An encrypted key file is created in 'keystore_directory'.

  <Returns>
    The generated RSA key.
    The object returned conforms to 'tuf.formats.RSAKEY_SCHEMA' of the form:
    {'keytype': 'rsa',
     'keyid': keyid,
     'keyval': {'public': '-----BEGIN RSA PUBLIC KEY----- ...',
                'private': '-----BEGIN RSA PRIVATE KEY----- ...'}}
  """

  # Are the arguments correctly formatted?
  # Raise 'tuf.FormatError' if there is a mismatch.
  tuf.formats.PATH_SCHEMA.check_match(keystore_directory)
  tuf.formats.PASSWORD_SCHEMA.check_match(password)

  keystore_directory = check_directory(keystore_directory)

  # tuf.FormatError or tuf.CryptoError raised.
  rsakey = tuf.keys.generate_rsa_key(bits)

  logger.info('Generated a new key: '+rsakey['keyid'])

  # Store the generated RSA key in the keystore and save the
  # key file '<keyid>.key' in 'keystore_directory'.
  try:
    tuf.repo.keystore.add_rsakey(rsakey, password)
    tuf.repo.keystore.save_keystore_to_keyfiles(keystore_directory)
  except tuf.FormatError:
    raise
  except tuf.KeyAlreadyExistsError:
    logger.warn('The generated RSA key already exists.')

  return rsakey





def check_directory(directory):
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
  targets_directory = check_directory(delegated_targets_directory)
  metadata_directory = check_directory(metadata_directory)

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






def accept_any_file(full_target_path):
  """
  <Purpose>
    Simply accept any given file.

  <Arguments>
    full_target_path:
      The absolute path to a target file.

  <Exceptions>
    None.

  <Side Effects>
    None.

  <Returns>
    True.
  """

  return True





def get_targets(files_directory, recursive_walk=False, followlinks=True,
                file_predicate=accept_any_file):
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

    file_predicate:
      To filter a file based on a predicate, set file_predicate to a function
      which accepts a full path to a file and returns a Boolean.

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
      if file_predicate(full_target_path):
        targets.append(full_target_path)

    # Prune the subdirectories to walk right now if we do not wish to
    # recursively walk files_directory.
    if recursive_walk is False:
      del dirnames[:]

  return targets




if __name__ == '__main__':
  # The interactive sessions of the documentation strings can
  # be tested by running libtuftools.py as a standalone module.
  # python libtuftools.py.
  import doctest
  doctest.testmod()
