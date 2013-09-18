"""
<Program Name>
  signerlib.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  April 5, 2012.  Based on a previous version of this module by Geremy Condra.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Provide helper functions to the 'signercli.py' and 'quickstart.py' scripts.
  These functions contain code that can extract or create needed repository
  data, such as the extraction of role and keyid information from a config file,
  and the generation of actual metadata content.

"""

import gzip
import os
import ConfigParser
import logging

import tuf
import tuf.formats
import tuf.hash
import tuf.rsa_key
import tuf.repo.keystore
import tuf.sig
import tuf.util

# See 'log.py' to learn how logging is handled in TUF.
logger = logging.getLogger('tuf.signerlib')

json = tuf.util.import_json()

# Recommended RSA key sizes:
# http://www.emc.com/emc-plus/rsa-labs/historical/twirl-and-rsa-key-size.htm#table1 
# According to the document above, revised May 6, 2003, RSA keys of
# size 3072 provide security through 2031 and beyond.  2048-bit keys
# are the recommended minimum and are good from the present through 2030.
DEFAULT_RSA_KEY_BITS = 3072

# The metadata filenames for the top-level roles.
ROOT_FILENAME = 'root.txt'
TARGETS_FILENAME = 'targets.txt'
RELEASE_FILENAME = 'release.txt'
TIMESTAMP_FILENAME = 'timestamp.txt'

# The filename for the repository configuration file.
# This file holds the keyids and threshold values for
# the top-level roles and their expiration date.
CONFIG_FILENAME = 'config.cfg'


def read_config_file(filename):
  """
  <Purpose>
    Read the TUF configuration file at filepath 'filename'.  Return a
    dictionary where the keys are section names and the values dictionaries
    of the keys/values in that section.
    For example:
    config_dict = {'expiration': {'days': 290, 'years': 8, ...},
                   'root': {'keyids': [1234bc33dfba, 13213123dbfdd]},
                   ...}

  <Arguments>
    filename:
      The absolute path of the configuration file.

  <Exceptions>
    tuf.FormatError, if 'filename' is improperly formatted.

    tuf.Error, if 'filename' could not be read.

  <Side Effects>
    The contents of 'filename' are read and stored.

  <Returns>
    A dictionary containing the data loaded from the configuration file.

  """

  # Does 'filename' have the correct format?
  # Raise 'tuf.FormatError' if there is a mismatch.
  tuf.formats.PATH_SCHEMA.check_match(filename)

  # Ensure 'filename' is an absolutized path and is a valid file.
  if not os.path.isabs(filename):
    raise tuf.Error(repr(filename)+' is not an absolute path.')
  if not os.path.isfile(filename):
    raise tuf.Error(repr(filename)+' is not a valid file.')

  # Check if 'filename' is an appropriately named config file.  If it is not,
  # we want to indicate this and prevent the reading of an invalid file.
  if not filename.endswith(CONFIG_FILENAME):
    raise tuf.Error(repr(filename)+' is not a config file.')

  # RawConfigParser is used because unlike ConfigParser,
  # it does not provide magical interpolation/expansion
  # of variables (e.g., '%(option)s' would be ignored).
  config = ConfigParser.RawConfigParser()
  config.read(filename)
  config_dict = {}

  # Extract the relevant information from the config and build the
  # 'config_dict' dictionary.
  for section in config.sections():
    config_dict[section] = {}
    for key, value in config.items(section):
      if key in ['threshold', 'years', 'seconds', 'minutes', 'days', 'hours']:
        value = int(value)
      elif key in ['keyids']:
        value = value.split(',')
      config_dict[section][key] = value

  return config_dict





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
  filenames['root'] = os.path.join(metadata_directory, ROOT_FILENAME)
  filenames['targets'] = os.path.join(metadata_directory, TARGETS_FILENAME)
  filenames['release'] = os.path.join(metadata_directory, RELEASE_FILENAME)
  filenames['timestamp'] = os.path.join(metadata_directory, TIMESTAMP_FILENAME)

  return filenames





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
        if key['keytype'] == 'rsa':
          keydict[keyid] = tuf.rsa_key.create_in_metadata_format(key['keyval'])
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





def read_metadata_file(filename):
  """
  <Purpose>
    Extract the metadata object from 'filename'.

  <Arguments>
    filename:
      The filename of the file containing the metadata object.

  <Exceptions>
    tuf.FormatError, if 'filename' is improperly formatted.

    tuf.Error, if 'filename' cannot be opened.

  <Side Effects>
    The contents of 'filename' are extracted.

  <Returns>
   The metadata object.

  """

  return tuf.util.load_json_file(filename)





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
  rsakey = tuf.rsa_key.generate(bits)

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





def get_target_keyids(metadata_directory):
  """
  <Purpose>
    Retrieve the role keyids for all the target roles located
    in 'metadata_directory'.  The target's '.txt' metadata
    file is inspected and the keyids extracted.  The 'targets.txt'
    role, including delegated roles (e.g., 'targets/role1.txt'),
    are all read.

  <Arguments>
    metadata_directory:
      The directory containing the 'targets.txt' metadata file and
      the metadata for optional delegated roles.  The delegated role
      'role1' whose parent is 'targets', would be located in the
      '{metadata_directory}/targets/role1' directory.

  <Exceptions>
    tuf.FormatError, if any of the arguments are improperly formatted.

    tuf.RepositoryError, if there was an error reading a target file.

  <Side Effects>
    Reads all of the target metadata found in 'metadata_directory'
    and stores the information extracted.

  <Returns>
    A dictionary containing the role information extracted from the
    metadata.
    Ex: {'targets':[keyid1, ...], 'targets/role1':[keyid], ...}

  """

  # Does 'metadata_directory' have the correct format?
  # Raise 'tuf.FormatError, if there is a mismatch.
  tuf.formats.PATH_SCHEMA.check_match(metadata_directory)

  metadata_directory = check_directory(metadata_directory)

  # The dict holding the keyids for all the target roles.
  # This dict will be returned to the caller. 
  role_keyids = {}

  # Read the 'targets.txt' file.  This file must exist.
  targets_filepath = os.path.join(metadata_directory, 'targets.txt')
  if not os.path.exists(targets_filepath):
    raise tuf.RepositoryError('"targets.txt" not found')

  # Read the contents of 'targets.txt' and save the signable.
  targets_signable = tuf.util.load_json_file(targets_filepath)

  # Ensure the signable is properly formatted.
  try:
    tuf.formats.check_signable_object_format(targets_signable)
  except tuf.FormatError, e:
    raise tuf.RepositoryError('"targets.txt" is improperly formatted')

  # Store the keyids of the 'targets' role.  This target role is
  # required.
  role_keyids['targets'] = []
  for signature in targets_signable['signatures']:
    role_keyids['targets'].append(signature['keyid'])

  # Walk the 'targets/' directory and generate the file info for all
  # the targets.  This information is stored in the 'meta' field of
  # the release metadata object.  The keyids for the optional
  # delegated roles will now be extracted.
  targets_metadata = os.path.join(metadata_directory, 'targets')
  if os.path.exists(targets_metadata) and os.path.isdir(targets_metadata):
    for directory_path, junk, files in os.walk(targets_metadata):
      for basename in files:
        # Store the metadata's file path and the role's full name (without
        # the '.txt').   The target role is identified by its full name.
        # The metadata's file path is needed so it can be loaded.
        metadata_path = os.path.join(directory_path, basename)
        metadata_name = metadata_path[len(metadata_directory):].lstrip(os.path.sep)
        metadata_name = metadata_name[:-len('.txt')]

        # Read the contents of 'metadata_path' and save the signable.
        targets_signable = tuf.util.load_json_file(metadata_path)

        # Ensure the signable is properly formatted.
        try:
          tuf.formats.check_signable_object_format(targets_signable)
        except tuf.FormatError, e:
          continue

        # Store the signature keyids of the 'metadata_name' role.
        role_keyids[metadata_name] = []
        for signature in targets_signable['signatures']:
          role_keyids[metadata_name].append(signature['keyid'])

  return role_keyids





def build_config_file(config_file_directory, timeout, role_info):
  """
  <Purpose>
    Build the configuration file containing the keyids, threshold,
    and expiration time for the top-level metadata files.

  <Arguments>
    config_file_directory:
      The absolute path of the directory to save the configuration file.

    timeout:
      The the number of days left before the top-level metadata files expire.

    role_info:
      A dictionary containing the keyids and threshold values for the
      top-level roles.  Must conform to 'tuf.formats.ROLEDICT_SCHEMA':
      {'rolename': {'keyids': ['34345df32093bd12...'],
                    'threshold': 1
                    'paths': ['path/to/role.txt']}}

  <Exceptions>
    tuf.FormatError, if any of the arguments are improperly formatted.

  <Side Effects>
    The configuration file is written to 'config_filepath'.

  <Returns>
    The normalized absolutized path of the saved configuration file.

  """

  # Do the arguments have the correct format?
  # Raise 'tuf.FormatError' if any of them is a mismatch.
  tuf.formats.PATH_SCHEMA.check_match(config_file_directory)
  tuf.formats.LENGTH_SCHEMA.check_match(timeout)
  tuf.formats.ROLEDICT_SCHEMA.check_match(role_info)

  config_file_directory = check_directory(config_file_directory) 
  
  # Construct the configuration file parser (hint: .ini).
  config_parser = ConfigParser.ConfigParser()

  # Verify that only the top-level roles are presented.
  for role in role_info.keys():
    if role not in ['root', 'targets', 'release', 'timestamp']:
      msg = ('\nCannot build configuration file: role '+repr(role)+
             ' is not a top-level role.')
      raise tuf.Error(msg)

  # Handle the expiration data.
  config_parser.add_section('expiration')
  config_parser.set('expiration', 'days', timeout)
  config_parser.set('expiration', 'years', 0)
  config_parser.set('expiration', 'minutes', 0)
  config_parser.set('expiration', 'hours', 0)
  config_parser.set('expiration', 'seconds', 0)

  # Build the role data.
  for role in role_info:
    config_parser.add_section(role)

    # Each role has an associated list of keyids and a threshold.
    keyids = role_info[role]['keyids']
    threshold = role_info[role]['threshold']

    # Convert 'keyids' into a string list it can read.
    # This is done because in ConfigParser.set(section, option, value)
    # the 'value' parameter should always be a string.
    # keyid_list has the form: 'keyid1, keyid2, keyid3'
    keyid_list = ','.join(keyids)

    # And add that data to the appropriate section.
    config_parser.set(role, 'keyids', keyid_list)
    config_parser.set(role, 'threshold', threshold)

  # We want to write this to '{config_file_directory}/CONFIG_FILENAME'.
  file_path = os.path.join(config_file_directory, CONFIG_FILENAME)
  file_object = open(file_path, 'w')
  config_parser.write(file_object)
  file_object.close()

  return file_path





def build_root_file(config_filepath, root_keyids, metadata_directory, version):
  """
  <Purpose>
    Build the root metadata file using the information available in the
    configuration file and sign the root file with 'root_keyids'.
    The generated metadata file is saved to 'metadata_directory'.

  <Arguments>
    config_filepath:
      The absolute path of the configuration file.

    root_keyids:
      The list of keyids to be used as the signing keys for the root file.

    metadata_directory:
      The directory to save the root metadata file.
    
    version:
      The metadata version number.  Clients use the version number to
      determine if the downloaded version is newer than the one currently trusted.

  <Exceptions>
    tuf.FormatError, if any of the arguments are improperly formatted.

    tuf.Error, if there was an error building the root file.

  <Side Effects>
    The root metadata file is written to a file.

  <Returns>
    The path for the written root metadata file.

  """

  # Do the arguments have the correct format?
  # Raise 'tuf.FormatError' if there is a mismatch.
  tuf.formats.PATH_SCHEMA.check_match(config_filepath)
  tuf.formats.KEYIDS_SCHEMA.check_match(root_keyids)
  tuf.formats.PATH_SCHEMA.check_match(metadata_directory)
  tuf.formats.METADATAVERSION_SCHEMA.check_match(version)

  metadata_directory = check_directory(metadata_directory)
  
  root_filepath = os.path.join(metadata_directory, ROOT_FILENAME)

  root_metadata = generate_root_metadata(config_filepath, version)
  signable = sign_metadata(root_metadata, root_keyids, root_filepath)

  return write_metadata_file(signable, root_filepath)





def build_targets_file(target_paths, targets_keyids, metadata_directory,
                       version, expiration_date):
  """
  <Purpose>
    Build the targets metadata file using the signing keys in 'targets_keyids'.
    The generated metadata file is saved to 'metadata_directory'.  The target
    files listed in 'target_paths' will be tracked by the built targets
    metadata.

  <Arguments>
    target_paths:
      The list of directories and/or filepaths specifying
      the target files of the targets metadata.  For example:
      ['targets/2.5/', 'targets/3.0/file.txt', 'targes/3.2/']

    targets_keyids:
      The list of keyids to be used as the signing keys for the targets file.

    metadata_directory:
      The metadata directory (absolute path) containing all the metadata files.

    version:
      The metadata version number.  Clients use the version number to
      determine if the downloaded version is newer than the one currently trusted.

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
  tuf.formats.PATHS_SCHEMA.check_match(target_paths)
  tuf.formats.KEYIDS_SCHEMA.check_match(targets_keyids)
  tuf.formats.PATH_SCHEMA.check_match(metadata_directory)
  tuf.formats.METADATAVERSION_SCHEMA.check_match(version)
  tuf.formats.TIME_SCHEMA.check_match(expiration_date)
  
  # Check if 'metadata_directory' is valid.
  metadata_directory = check_directory(metadata_directory)

  # The metadata directory is expected to live directly under
  # the repository directory.  
  repository_directory, junk = os.path.split(metadata_directory)
  repository_directory_length = len(repository_directory)

  # Retrieve the list of targets.  generate_targets_metadata() expects individual
  # target paths relative to the targets directory on the repository.
  targets = []
  
  # Extract the filepaths and/or directories from the 'target_paths' list
  # and append the individual target files to 'targets'.
  for path in target_paths:
    path = os.path.abspath(path)
    if os.path.isfile(path):
      # '+1' in the line below removes the leading '/'.
      filename = path[repository_directory_length+1:]
      targets.append(filename)
    elif os.path.isdir(path):
      for root, directories, files in os.walk(path):
        for target_file in files:
          # '+1' in the line below removes the leading '/'.
          filename = os.path.join(root, target_file)[repository_directory_length+1:]
          targets.append(filename)
    else:
      # Invalid directory or file, so log a warning.
      logger.warn('Skipping: '+repr(path))

  # Create the targets metadata object.
  targets_metadata = generate_targets_metadata(repository_directory, targets,
                                               version, expiration_date)

  # Sign it.
  targets_filepath = os.path.join(metadata_directory, TARGETS_FILENAME)
  signable = sign_metadata(targets_metadata, targets_keyids, targets_filepath)

  return write_metadata_file(signable, targets_filepath)





def build_release_file(release_keyids, metadata_directory,
                       version, expiration_date, compress=False):
  """
  <Purpose>
    Build the release metadata file using the signing keys in 'release_keyids'.
    The generated metadata file is saved in 'metadata_directory'.

  <Arguments>
    release_keyids:
      The list of keyids to be used as the signing keys for the release file.

    metadata_directory:
      The directory (absolute path) to save the release metadata file.
    
    version:
      The metadata version number.  Clients use the version number to
      determine if the downloaded version is newer than the one currently trusted.

    expiration_date:
      The expiration date, in UTC, of the metadata file.
      Conformant to 'tuf.formats.TIME_SCHEMA'.

    compress:
      Should we *include* a compressed version of the release file? By default,
      the answer is no.

  <Exceptions>
    tuf.FormatError, if any of the arguments are improperly formatted.

    tuf.Error, if there was an error while building the release file.

  <Side Effects>
    The release metadata file is written to a file.

  <Returns>
    The path for the written release metadata file.

  """

  # Do the arguments have the correct format?
  # Raise 'tuf.FormatError' if there is a mismatch.
  tuf.formats.KEYIDS_SCHEMA.check_match(release_keyids)
  tuf.formats.PATH_SCHEMA.check_match(metadata_directory)
  tuf.formats.METADATAVERSION_SCHEMA.check_match(version)
  tuf.formats.TIME_SCHEMA.check_match(expiration_date)

  metadata_directory = check_directory(metadata_directory)

  # Generate the file path of the release metadata.
  release_filepath = os.path.join(metadata_directory, RELEASE_FILENAME)

  # Generate and sign the release metadata.
  release_metadata = generate_release_metadata(metadata_directory,
                                               version, expiration_date)
  signable = sign_metadata(release_metadata, release_keyids, release_filepath)

  # Should we also include a compressed version of release.txt?
  if compress:
    # If so, write a gzip version of release.txt.
    compressed_written_filepath = \
        write_metadata_file(signable, release_filepath, compression='gz')
    logger.info('Wrote '+str(compressed_written_filepath))
  else:
    logger.debug('No compressed version of release metadata will be included.')

  written_filepath = write_metadata_file(signable, release_filepath)
  logger.info('Wrote '+str(written_filepath))

  return written_filepath





def build_timestamp_file(timestamp_keyids, metadata_directory,
                         version, expiration_date,
                         include_compressed_release=True):
  """
  <Purpose>
    Build the timestamp metadata file using the signing keys in 'timestamp_keyids'.
    The generated metadata file is saved in 'metadata_directory'.

  <Arguments>
    timestamp_keyids:
      The list of keyids to be used as the signing keys for the timestamp file.

    metadata_directory:
      The directory (absolute path) to save the timestamp metadata file.

    version:
      The metadata version number.  Clients use the version number to
      determine if the downloaded version is newer than the one currently trusted.

    expiration_date:
      The expiration date, in UTC, of the metadata file.
      Conformant to 'tuf.formats.TIME_SCHEMA'.

    include_compressed_release:
      Should the timestamp role *include* compression versions of the release
      metadata, if any? We do this by default.
  
  <Exceptions>
    tuf.FormatError, if any of the arguments are improperly formatted.

    tuf.Error, if there was an error while building the timestamp file.

  <Side Effects>
    The timestamp metadata file is written to a file.

  <Returns>
    The path for the written timestamp metadata file.

  """

  # Do the arguments have the correct format?
  # Raise 'tuf.FormatError' if there is a mismatch.
  tuf.formats.KEYIDS_SCHEMA.check_match(timestamp_keyids)
  tuf.formats.PATH_SCHEMA.check_match(metadata_directory)
  tuf.formats.METADATAVERSION_SCHEMA.check_match(version)
  tuf.formats.TIME_SCHEMA.check_match(expiration_date)

  metadata_directory = check_directory(metadata_directory)

  # Generate the file path of the release and timestamp metadata.
  release_filepath = os.path.join(metadata_directory, RELEASE_FILENAME)
  timestamp_filepath = os.path.join(metadata_directory, TIMESTAMP_FILENAME)

  # Should we include compressed versions of release in timestamp?
  compressions = ()
  if include_compressed_release:
    # Presently, we include only gzip versions by default.
    compressions = ('gz',)
    logger.info('Including '+str(compressions)+' versions of release in '\
                'timestamp.')
  else:
    logger.warn('No compressed versions of release will be included in '\
                'timestamp.')

  # Generate and sign the timestamp metadata.
  timestamp_metadata = generate_timestamp_metadata(release_filepath,
                                                   version,
                                                   expiration_date,
                                                   compressions=compressions)
  signable = sign_metadata(timestamp_metadata, timestamp_keyids,
                           timestamp_filepath)

  return write_metadata_file(signable, timestamp_filepath)





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





def find_delegated_role(roles, delegated_role):
  """
  <Purpose>
    Find the index, if any, of a role with a given name in a list of roles.

  <Arguments>
    roles:
      The list of roles, each of which must have a name.

    delegated_role:
      The name of the role to be found in the list of roles.

  <Exceptions>
    tuf.RepositoryError, if the list of roles has invalid data.

  <Side Effects>
    No known side effects.

  <Returns>
    None, if the role with the given name does not exist, or its unique index
    in the list of roles.

  """

  # Check argument types.
  tuf.formats.ROLELIST_SCHEMA.check_match(roles)
  tuf.formats.ROLENAME_SCHEMA.check_match(delegated_role)

  # The index of a role, if any, with the same name.
  role_index = None

  for index in xrange(len(roles)):
    role = roles[index]
    name = role.get('name')
    # This role has no name.
    if name is None:
      no_name_message = 'Role with no name!'
      raise tuf.RepositoryError(no_name_message)
    # Does this role have the same name?
    else:
      # This role has the same name, and...
      if name == delegated_role:
        # ...it is the only known role with the same name.
        if role_index is None:
          role_index = index
        # ...there are at least two roles with the same name!
        else:
          duplicate_role_message = 'Duplicate role ('+str(delegated_role)+')!'
          raise tuf.RepositoryError(duplicate_role_message)
      # This role has a different name.
      else:
        continue

  return role_index





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





