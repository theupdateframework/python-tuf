#!/usr/bin/env python

"""
<Program Name>
  repository_lib.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  June 1, 2014 

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Provide a library for the repository tool that can create a TUF repository.
  The repository tool can be used with the Python interpreter in interactive
  mode, or imported directly into a Python module.  See 'tuf/README' for the
  complete guide to using 'tuf.repository_tool.py'.
"""

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import os
import errno
import sys
import time
import datetime
import getpass
import logging
import tempfile
import shutil
import json
import gzip
import random

import tuf
import tuf.formats
import tuf.util
import tuf.keydb
import tuf.roledb
import tuf.keys
import tuf.sig
import tuf.log
import tuf.conf

import iso8601
import six


# See 'log.py' to learn how logging is handled in TUF.
logger = logging.getLogger('tuf.repository_lib')

# Disable 'iso8601' logger messages to prevent 'iso8601' from clogging the
# log file.
iso8601_logger = logging.getLogger('iso8601')
iso8601_logger.disabled = True

# Recommended RSA key sizes:
# http://www.emc.com/emc-plus/rsa-labs/historical/twirl-and-rsa-key-size.htm#table1
# According to the document above, revised May 6, 2003, RSA keys of
# size 3072 provide security through 2031 and beyond. 2048-bit keys
# are the recommended minimum and are good from the present through 2030.
DEFAULT_RSA_KEY_BITS = 3072

# The extension of TUF metadata.
METADATA_EXTENSION = '.json'

# The targets and metadata directory names.  Metadata files are written
# to the staged metadata directory instead of the "live" one.
METADATA_STAGED_DIRECTORY_NAME = 'metadata.staged'
METADATA_DIRECTORY_NAME = 'metadata'
TARGETS_DIRECTORY_NAME = 'targets' 

# The metadata filenames of the top-level roles.
ROOT_FILENAME = 'root' + METADATA_EXTENSION
TARGETS_FILENAME = 'targets' + METADATA_EXTENSION
SNAPSHOT_FILENAME = 'snapshot' + METADATA_EXTENSION
TIMESTAMP_FILENAME = 'timestamp' + METADATA_EXTENSION

# Log warning when metadata expires in n days, or less.
# root = 1 month, snapshot = 1 day, targets = 10 days, timestamp = 1 day.
ROOT_EXPIRES_WARN_SECONDS = 2630000
SNAPSHOT_EXPIRES_WARN_SECONDS = 86400
TARGETS_EXPIRES_WARN_SECONDS = 864000
TIMESTAMP_EXPIRES_WARN_SECONDS = 86400

# Supported key types.
SUPPORTED_KEY_TYPES = ['rsa', 'ed25519']

# The recognized compression extensions. 
SUPPORTED_COMPRESSION_EXTENSIONS = ['.gz']

# The full list of supported TUF metadata extensions.
METADATA_EXTENSIONS = ['.json']


def _generate_and_write_metadata(rolename, metadata_filename, write_partial,
                                 targets_directory, metadata_directory,
                                 consistent_snapshot=False, filenames=None,
                                 compression_algorithms=['gz']):
  """
  Non-public function that can generate and write the metadata of the specified
  top-level 'rolename'.  It also increments version numbers if:
  
  1.  write_partial==True and the metadata is the first to be written.
  
  2.  write_partial=False (i.e., write()), the metadata was not loaded as
      partially written, and a write_partial is not needed.
  """

  metadata = None 

  # Retrieve the roleinfo of 'rolename' to extract the needed metadata
  # attributes, such as version number, expiration, etc.
  roleinfo = tuf.roledb.get_roleinfo(rolename) 

  # Generate the appropriate role metadata for 'rolename'. 
  if rolename == 'root':
    metadata = generate_root_metadata(roleinfo['version'],
                                      roleinfo['expires'], consistent_snapshot,
                                      compression_algorithms)
    
    _log_warning_if_expires_soon(ROOT_FILENAME, roleinfo['expires'],
                                 ROOT_EXPIRES_WARN_SECONDS)
 
  # Check for the Targets role, including delegated roles.
  elif rolename.startswith('targets'):
    metadata = generate_targets_metadata(targets_directory,
                                         roleinfo['paths'],
                                         roleinfo['version'],
                                         roleinfo['expires'],
                                         roleinfo['delegations'],
                                         consistent_snapshot)

    if rolename == 'targets':    
      _log_warning_if_expires_soon(TARGETS_FILENAME, roleinfo['expires'],
                                   TARGETS_EXPIRES_WARN_SECONDS)
  
  elif rolename == 'snapshot':
    root_filename = ROOT_FILENAME[:-len(METADATA_EXTENSION)]
    targets_filename = TARGETS_FILENAME[:-len(METADATA_EXTENSION)]
    metadata = generate_snapshot_metadata(metadata_directory,
                                          roleinfo['version'],
                                          roleinfo['expires'], root_filename,
                                          targets_filename,
                                          consistent_snapshot)
           
      
    _log_warning_if_expires_soon(SNAPSHOT_FILENAME, roleinfo['expires'],
                                 SNAPSHOT_EXPIRES_WARN_SECONDS)
  
  elif rolename == 'timestamp':
    snapshot_filename = filenames['snapshot'] 
    metadata = generate_timestamp_metadata(snapshot_filename,
                                           roleinfo['version'],
                                           roleinfo['expires'])
    
    _log_warning_if_expires_soon(TIMESTAMP_FILENAME, roleinfo['expires'],
                                 TIMESTAMP_EXPIRES_WARN_SECONDS)
  else:
    raise tuf.Error('Invalid rolename') 

  signable = sign_metadata(metadata, roleinfo['signing_keyids'],
                           metadata_filename)
 
  # Check if the version number of 'rolename' may be automatically incremented,
  # depending on whether if partial metadata is loaded or if the metadata is
  # written with write() / write_partial(). 
  # Increment the version number if this is the first partial write.
  if write_partial:
    temp_signable = sign_metadata(metadata, [], metadata_filename)
    temp_signable['signatures'].extend(roleinfo['signatures'])
    status = tuf.sig.get_signature_status(temp_signable, rolename)
    if len(status['good_sigs']) == 0:
      metadata['version'] = metadata['version'] + 1
      roleinfo = tuf.roledb.get_roleinfo(rolename)
      roleinfo['version'] = roleinfo['version'] + 1
      tuf.roledb.update_roleinfo(rolename, roleinfo)
      signable = sign_metadata(metadata, roleinfo['signing_keyids'],
                               metadata_filename)
  # non-partial write()
  else:
    # If writing a new version of 'rolename,' increment its version number in
    # both the metadata file and roledb (required so that snapshot references
    # the latest version).
    if tuf.sig.verify(signable, rolename) and not roleinfo['partial_loaded']:
      metadata['version'] = metadata['version'] + 1
      roleinfo = tuf.roledb.get_roleinfo(rolename)
      roleinfo['version'] = roleinfo['version'] + 1
      tuf.roledb.update_roleinfo(rolename, roleinfo) 
      signable = sign_metadata(metadata, roleinfo['signing_keyids'],
                               metadata_filename)
  
  # Write the metadata to file if contains a threshold of signatures. 
  signable['signatures'].extend(roleinfo['signatures']) 
  
  if tuf.sig.verify(signable, rolename) or write_partial:
    _remove_invalid_and_duplicate_signatures(signable)
    filename = write_metadata_file(signable, metadata_filename,
                                   metadata['version'], compression_algorithms,
                                   consistent_snapshot)
    
    # The root and timestamp files should also be written without a version
    # number prepended if 'consistent_snaptshot' is True.  Clients may request
    # a timestamp and root file without knowing their version numbers.
    if rolename == 'root' or rolename == 'timestamp':
      write_metadata_file(signable, metadata_filename, metadata['version'],
                          compression_algorithms, consistent_snapshot=False)
    
  
  # 'signable' contains an invalid threshold of signatures. 
  else:
    message = 'Not enough signatures for ' + repr(metadata_filename)
    raise tuf.UnsignedMetadataError(message, signable)
  
  return signable, filename





def _prompt(message, result_type=str):
  """
    Non-public function that prompts the user for input by loging 'message',
    converting the input to 'result_type', and returning the value to the
    caller.
  """

  return result_type(six.moves.input(message))





def _get_password(prompt='Password: ', confirm=False):
  """
    Non-public function that returns the password entered by the user.  If
    'confirm' is True, the user is asked to enter the previously entered
    password once again.  If they match, the password is returned to the caller.
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
      print('Mismatch; try again.')





def _metadata_is_partially_loaded(rolename, signable, roleinfo):
  """
  Non-public function that determines whether 'rolename' is loaded with
  at least zero good signatures, but an insufficient threshold (which means
  'rolename' was written to disk with repository.write_partial()).  A repository
  maintainer may write partial metadata without including a valid signature.
  Howerver, the final repository.write() must include a threshold number of
  signatures.
  
  If 'rolename' is found to be partially loaded, mark it as partially loaded in
  its 'tuf.roledb' roleinfo.  This function exists to assist in deciding whether
  a role's version number should be incremented when write() or write_parital()
  is called.  Return True if 'rolename' was partially loaded, False otherwise. 
  """

  # The signature status lists the number of good signatures, including
  # bad, untrusted, unknown, etc.
  status = tuf.sig.get_signature_status(signable, rolename)
  
  if len(status['good_sigs']) < status['threshold'] and \
                                                  len(status['good_sigs']) >= 0:
    return True
  
  else:
    return False





def _check_directory(directory):
  """
  <Purpose>
    Non-public function that ensures 'directory' is valid and it exists.  This
    is not a security check, but a way for the caller to determine the cause of
    an invalid directory provided by the user.  If the directory argument is
    valid, it is returned normalized and as an absolute path.

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
    raise tuf.Error(repr(directory) + ' directory does not exist.')

  directory = os.path.abspath(directory)
  
  return directory





def _check_role_keys(rolename):
  """
  Non-public function that verifies the public and signing keys of 'rolename'.
  If either contain an invalid threshold of keys, raise an exception.
  'rolename' is the full rolename (e.g., 'targets/unclaimed/django'). 
  """

  # Extract the total number of public and private keys of 'rolename' from its
  # roleinfo in 'tuf.roledb'.
  roleinfo = tuf.roledb.get_roleinfo(rolename)
  total_keyids = len(roleinfo['keyids'])
  threshold = roleinfo['threshold']
  total_signatures = len(roleinfo['signatures'])
  total_signing_keys = len(roleinfo['signing_keyids'])
 
  # Raise an exception for an invalid threshold of public keys.
  if total_keyids < threshold: 
    message = repr(rolename) + ' role contains ' + \
      repr(total_keyids) + ' / ' + repr(threshold) + ' public keys.'
    raise tuf.InsufficientKeysError(message)

  # Raise an exception for an invalid threshold of signing keys.
  if total_signatures == 0 and total_signing_keys < threshold: 
    message = repr(rolename) + ' role contains ' + \
      repr(total_signing_keys) + ' / ' + repr(threshold) + ' signing keys.'
    raise tuf.InsufficientKeysError(message)





def _remove_invalid_and_duplicate_signatures(signable):
  """
    Non-public function that removes invalid signatures from 'signable'.
    'signable' may contain signatures (invalid) from previous versions
    of the metadata that were loaded with load_repository().  Invalid, or
    duplicate signatures are removed from 'signable'.
  """
  
  # Store the keyids of valid signatures.  'signature_keyids' is checked
  # for duplicates rather than comparing signature objects because PSS may
  # generate duplicate valid signatures of the same data, yet contain different
  # signatures.
  signature_keyids = []

  for signature in signable['signatures']:
    signed = signable['signed']
    keyid = signature['keyid']
    key = None

    # Remove 'signature' from 'signable' if the listed keyid does not exist
    # in 'tuf.keydb'.
    try:
      key = tuf.keydb.get_key(keyid)
    
    except tuf.UnknownKeyError as e:
      signable['signatures'].remove(signature)
      continue
    
    # Remove 'signature' from 'signable' if it is an invalid signature.
    if not tuf.keys.verify_signature(key, signature, signed):
      signable['signatures'].remove(signature)
    
    # Although valid, it may still need removal if it is a duplicate.  Check
    # the keyid, rather than the signature, to remove duplicate PSS signatures.
    # PSS may generate multiple different signatures for the same keyid.
    else:
      if keyid in signature_keyids:
        signable['signatures'].remove(signature)
      
      # 'keyid' is valid and not a duplicate, so add it to 'signature_keyids'.
      else:
        signature_keyids.append(keyid)





def _delete_obsolete_metadata(metadata_directory, snapshot_metadata,
                              consistent_snapshot):
  """
  Non-public function that deletes metadata files marked as removed by
  'repository_tool.py'.  Revoked metadata files are not actually deleted until
  this function is called.  Obsolete metadata should *not* be retained in
  "metadata.staged", otherwise they may be re-loaded by 'load_repository()'. 
  Note: Obsolete metadata may not always be easily detected (by inspecting
  top-level metadata during loading) due to partial metadata and top-level
  metadata that have not been written yet.
  """
 
  # Walk the repository's metadata 'targets' sub-directory, where all the
  # metadata of delegated roles is stored.
  targets_metadata = os.path.join(metadata_directory, 'targets')

  # The 'targets.json' metadata is not visited, only its child delegations.
  # The 'targets/unclaimed/django.json' role would be located in the
  # '{repository_directory}/metadata/targets/unclaimed/' directory.
  if os.path.exists(targets_metadata) and os.path.isdir(targets_metadata):
    for directory_path, junk_directories, files in os.walk(targets_metadata):
      
      # 'files' here is a list of target file names.
      for basename in files:
        metadata_path = os.path.join(directory_path, basename)
        # Strip the metadata dirname and the leading path separator.
        # '{repository_directory}/metadata/targets/unclaimed/django.json' -->
        # 'targets/unclaimed/django.json'
        metadata_name = \
          metadata_path[len(metadata_directory):].lstrip(os.path.sep)
      
        # Strip the version number if 'consistent_snapshot' is True.  Example:
        # 'targets/unclaimed/10.django.json'  -->
        # 'targets/unclaimed/django.json'.  Consistent and non-consistent
        # metadata might co-exist if write() and
        # write(consistent_snapshot=True) are mixed, so ensure only
        # '<version_number>.filename' metadata is stripped.
        embedded_version_number = None
        if metadata_name not in snapshot_metadata['meta']: 
          metadata_name, embedded_version_number = \
            _strip_consistent_snapshot_version_number(metadata_name, consistent_snapshot)
        
        # Strip filename extensions.  The role database does not include the
        # metadata extension.
        metadata_name_extension = metadata_name
        for metadata_extension in METADATA_EXTENSIONS: 
          if metadata_name.endswith(metadata_extension):
            metadata_name = metadata_name[:-len(metadata_extension)]
        
        # Delete the metadata file if it does not exist in 'tuf.roledb'.
        # 'repository_tool.py' might have removed 'metadata_name,'
        # but its metadata file is not actually deleted yet.  Do it now.
        if not tuf.roledb.role_exists(metadata_name):
          logger.info('Removing outdated metadata: ' + repr(metadata_path))
          os.remove(metadata_path)

        # Delete outdated consistent snapshots.  Snapshot metadata includes the
        # file extension of roles.  TODO: Should we leave it up to integrators
        # to remove outdated consistent snapshots?
        """ 
        if consistent_snapshot and embedded_version_number is not None:
          file_hashes = list(snapshot_metadata['meta'][metadata_name_extension] \
                                        ['hashes'].values())
          if embedded_digest not in file_hashes:
            logger.info('Removing outdated metadata: ' + repr(metadata_path))
            os.remove(metadata_path)
        """





def _get_written_metadata(metadata_signable):
  """
  Non-public function that returns the actual content of written metadata.
  """

  # Explicitly specify the JSON separators for Python 2 + 3 consistency.
  written_metadata_content = \
    json.dumps(metadata_signable, indent=1, separators=(',', ': '),
               sort_keys=True).encode('utf-8')
  
  return written_metadata_content





def _strip_consistent_snapshot_version_number(metadata_filename,
                                              consistent_snapshot):
  """
  Strip from 'metadata_filename' any version data (in the expected
  '{dirname}/version_number.filename' format) that it may contain, and return
  the stripped filename and its version number as a tuple.
  'consistent_snapshot' is a boolean indicating if 'metadata_filename' contains
  prepended version number.
  """
 
  embedded_version_number = ''

  # Strip the version number if 'consistent_snapshot' is True.
  # Example:  'targets/unclaimed/10.django.json'  -->
  # 'targets/unclaimed/django.json'
  if consistent_snapshot:
    dirname, basename = os.path.split(metadata_filename)
    embedded_version_number, basename = basename.split('.', 1)
    stripped_metadata_filename = os.path.join(dirname, basename)
    
    return stripped_metadata_filename, embedded_version_number
  
  else:
    return metadata_filename, ''





def _load_top_level_metadata(repository, top_level_filenames):
  """
  Load the metadata of the Root, Timestamp, Targets, and Snapshot roles.  At a
  minimum, the Root role must exist and successfully load.
  """

  root_filename = top_level_filenames[ROOT_FILENAME] 
  targets_filename = top_level_filenames[TARGETS_FILENAME] 
  snapshot_filename = top_level_filenames[SNAPSHOT_FILENAME] 
  timestamp_filename = top_level_filenames[TIMESTAMP_FILENAME]

  root_metadata = None
  targets_metadata = None
  snapshot_metadata = None
  timestamp_metadata = None
  
  # Load 'root.json'.  A Root role file without a version number is always
  # written. 
  if os.path.exists(root_filename):
    # Initialize the key and role metadata of the top-level roles.
    signable = tuf.util.load_json_file(root_filename)
    tuf.formats.check_signable_object_format(signable)
    root_metadata = signable['signed']  
    tuf.keydb.create_keydb_from_root_metadata(root_metadata)
    tuf.roledb.create_roledb_from_root_metadata(root_metadata)

    # Load Root's roleinfo and update 'tuf.roledb'.
    roleinfo = tuf.roledb.get_roleinfo('root')
    roleinfo['signatures'] = []
    for signature in signable['signatures']:
      if signature not in roleinfo['signatures']: 
        roleinfo['signatures'].append(signature)

    if os.path.exists(root_filename + '.gz'):
      roleinfo['compressions'].append('gz')
   
    # By default, roleinfo['partial_loaded'] of top-level roles should be set
    # to False in 'create_roledb_from_root_metadata()'.  Update this field, if
    # necessary, now that we have its signable object.
    if _metadata_is_partially_loaded('root', signable, roleinfo):
      roleinfo['partial_loaded'] = True
    
    _log_warning_if_expires_soon(ROOT_FILENAME, roleinfo['expires'],
                                 ROOT_EXPIRES_WARN_SECONDS)
    
    tuf.roledb.update_roleinfo('root', roleinfo)

    # Ensure the 'consistent_snapshot' field is extracted.
    consistent_snapshot = root_metadata['consistent_snapshot']
  
  else:
    message = 'Cannot load the required root file: ' + repr(root_filename)
    raise tuf.RepositoryError(message)
  
  # Load 'timestamp.json'.  A Timestamp role file without a version number is
  # always written. 
  if os.path.exists(timestamp_filename):
    signable = tuf.util.load_json_file(timestamp_filename)
    timestamp_metadata = signable['signed']  
    for signature in signable['signatures']:
      repository.timestamp.add_signature(signature)

    # Load Timestamp's roleinfo and update 'tuf.roledb'.
    roleinfo = tuf.roledb.get_roleinfo('timestamp')
    roleinfo['expires'] = timestamp_metadata['expires']
    roleinfo['version'] = timestamp_metadata['version']
    if os.path.exists(timestamp_filename+'.gz'):
      roleinfo['compressions'].append('gz')
    
    if _metadata_is_partially_loaded('timestamp', signable, roleinfo):
      roleinfo['partial_loaded'] = True
    
    _log_warning_if_expires_soon(TIMESTAMP_FILENAME, roleinfo['expires'],
                                 TIMESTAMP_EXPIRES_WARN_SECONDS)
    
    tuf.roledb.update_roleinfo('timestamp', roleinfo)
  
  else:
    pass
  
  # Load 'snapshot.json'.  A consistent snapshot of Snapshot must be calculated
  # if 'consistent_snapshot' is True.
  if consistent_snapshot:
    snapshot_version = timestamp_metadata['meta'][SNAPSHOT_FILENAME]['version']
    dirname, basename = os.path.split(snapshot_filename)
    snapshot_filename = os.path.join(dirname, str(snapshot_version) + '.' + basename)
  
  if os.path.exists(snapshot_filename):
    signable = tuf.util.load_json_file(snapshot_filename)
    tuf.formats.check_signable_object_format(signable)
    snapshot_metadata = signable['signed']  
    for signature in signable['signatures']:
      repository.snapshot.add_signature(signature)

    # Load Snapshot's roleinfo and update 'tuf.roledb'.
    roleinfo = tuf.roledb.get_roleinfo('snapshot')
    roleinfo['expires'] = snapshot_metadata['expires']
    roleinfo['version'] = snapshot_metadata['version']
    if os.path.exists(snapshot_filename + '.gz'):
      roleinfo['compressions'].append('gz')
    
    if _metadata_is_partially_loaded('snapshot', signable, roleinfo):
      roleinfo['partial_loaded'] = True
    
    _log_warning_if_expires_soon(SNAPSHOT_FILENAME, roleinfo['expires'],
                                 SNAPSHOT_EXPIRES_WARN_SECONDS)
    
    tuf.roledb.update_roleinfo('snapshot', roleinfo)
  
  else:
    pass 

  # Load 'targets.json'.  A consistent snapshot of the Targets role must be
  # calculated if 'consistent_snapshot' is True.
  if consistent_snapshot:
    targets_version = snapshot_metadata['meta'][TARGETS_FILENAME]['version']
    dirname, basename = os.path.split(targets_filename)
    targets_filename = os.path.join(dirname, str(targets_version) + '.' + basename)
  
  if os.path.exists(targets_filename):
    signable = tuf.util.load_json_file(targets_filename)
    tuf.formats.check_signable_object_format(signable)
    targets_metadata = signable['signed']

    for signature in signable['signatures']:
      repository.targets.add_signature(signature)
   
    # Update 'targets.json' in 'tuf.roledb.py' 
    roleinfo = tuf.roledb.get_roleinfo('targets')
    for filepath, fileinfo in six.iteritems(targets_metadata['targets']):
      roleinfo['paths'].update({filepath: fileinfo.get('custom', {})})
    roleinfo['version'] = targets_metadata['version']
    roleinfo['expires'] = targets_metadata['expires']
    roleinfo['delegations'] = targets_metadata['delegations']
    if os.path.exists(targets_filename + '.gz'):
      roleinfo['compressions'].append('gz')
   
    if _metadata_is_partially_loaded('targets', signable, roleinfo):
      roleinfo['partial_loaded'] = True
   
    _log_warning_if_expires_soon(TARGETS_FILENAME, roleinfo['expires'],
                                 TARGETS_EXPIRES_WARN_SECONDS)
   
    tuf.roledb.update_roleinfo('targets', roleinfo)

    # Add the keys specified in the delegations field of the Targets role.
    for key_metadata in six.itervalues(targets_metadata['delegations']['keys']):
      key_object = tuf.keys.format_metadata_to_key(key_metadata)
     
      # Add 'key_object' to the list of recognized keys.  Keys may be shared,
      # so do not raise an exception if 'key_object' has already been loaded.
      # In contrast to the methods that may add duplicate keys, do not log
      # a warning as there may be many such duplicate key warnings.  The
      # repository maintainer should have also been made aware of the duplicate
      # key when it was added.
      try: 
        tuf.keydb.add_key(key_object)
      
      except tuf.KeyAlreadyExistsError as e:
        pass

    for role in targets_metadata['delegations']['roles']:
      rolename = role['name'] 
      roleinfo = {'name': role['name'], 'keyids': role['keyids'],
                  'threshold': role['threshold'], 'compressions': [''],
                  'signing_keyids': [], 'partial_loaded': False, 'paths': {},
                  'signatures': [], 'delegations': {'keys': {},
                                                    'roles': []}}
      tuf.roledb.add_role(rolename, roleinfo)
  
  else:
    pass 
  
  return repository, consistent_snapshot




def _log_warning_if_expires_soon(rolename, expires_iso8601_timestamp,
                                 seconds_remaining_to_warn):
  """
  Non-public function that logs a warning if 'rolename' expires in
  'seconds_remaining_to_warn' seconds, or less.
  """
 
  # Metadata stores expiration datetimes in ISO8601 format.  Convert to
  # unix timestamp, subtract from from current time.time() (also in POSIX time)
  # and compare against 'seconds_remaining_to_warn'.  Log a warning message
  # to console if 'rolename' expires soon.
  datetime_object = iso8601.parse_date(expires_iso8601_timestamp)
  expires_unix_timestamp = \
    tuf.formats.datetime_to_unix_timestamp(datetime_object) 
  seconds_until_expires = expires_unix_timestamp - int(time.time())
  
  if seconds_until_expires <= seconds_remaining_to_warn:
    days_until_expires = seconds_until_expires / 86400
    
    message = repr(rolename) + ' expires ' + datetime_object.ctime() + \
      ' (UTC).\n' + repr(days_until_expires) + ' day(s) until it expires.'
    
    logger.warning(message)





def generate_and_write_rsa_keypair(filepath, bits=DEFAULT_RSA_KEY_BITS,
                                   password=None):
  """
  <Purpose>
    Generate an RSA key file, create an encrypted PEM string (using 'password'
    as the pass phrase), and store it in 'filepath'.  The public key portion of
    the generated RSA key is stored in <'filepath'>.pub.  Which cryptography
    library performs the cryptographic decryption is determined by the string
    set in 'tuf.conf.RSA_CRYPTO_LIBRARY'.  PyCrypto currently supported.  The
    PEM private key is encrypted with 3DES and CBC the mode of operation.  The
    password is strengthened with PBKDF1-MD5.

  <Arguments>
    filepath:
      The public and private key files are saved to <filepath>.pub, <filepath>,
      respectively.
    
    bits:
      The number of bits of the generated RSA key. 

    password:
      The password used to encrypt 'filepath'.

  <Exceptions>
    tuf.FormatError, if the arguments are improperly formatted.

  <Side Effects>
    Writes key files to '<filepath>' and '<filepath>.pub'.

  <Returns>
    None.
  """

  # Do the arguments have the correct format?
  # This check ensures arguments have the appropriate number of
  # objects and object types, and that all dict keys are properly named.
  # Raise 'tuf.FormatError' if there is a mismatch.
  tuf.formats.PATH_SCHEMA.check_match(filepath)

  # Does 'bits' have the correct format?
  tuf.formats.RSAKEYBITS_SCHEMA.check_match(bits)

  # If the caller does not provide a password argument, prompt for one.
  if password is None: # pragma: no cover
    message = 'Enter a password for the RSA key file: '
    password = _get_password(message, confirm=True)

  # Does 'password' have the correct format?
  tuf.formats.PASSWORD_SCHEMA.check_match(password)
 
  #  Generate public and private RSA keys, encrypted the private portion
  # and store them in PEM format.
  rsa_key = tuf.keys.generate_rsa_key(bits)
  public = rsa_key['keyval']['public']
  private = rsa_key['keyval']['private']
  encrypted_pem = tuf.keys.create_rsa_encrypted_pem(private, password) 
 
  # Write public key (i.e., 'public', which is in PEM format) to
  # '<filepath>.pub'.  If the parent directory of filepath does not exist,
  # create it (and all its parent directories, if necessary).
  tuf.util.ensure_parent_dir(filepath)

  # Create a tempororary file, write the contents of the public key, and move
  # to final destination.
  file_object = tuf.util.TempFile()
  file_object.write(public.encode('utf-8'))
  
  # The temporary file is closed after the final move.
  file_object.move(filepath + '.pub')

  # Write the private key in encrypted PEM format to '<filepath>'.
  # Unlike the public key file, the private key does not have a file
  # extension.
  file_object = tuf.util.TempFile()
  file_object.write(encrypted_pem.encode('utf-8'))
  file_object.move(filepath)





def import_rsa_privatekey_from_file(filepath, password=None):
  """
  <Purpose>
    Import the encrypted PEM file in 'filepath', decrypt it, and return the key
    object in 'tuf.formats.RSAKEY_SCHEMA' format.

    Which cryptography library performs the cryptographic decryption is
    determined by the string set in 'tuf.conf.RSA_CRYPTO_LIBRARY'.  PyCrypto
    currently supported.

    The PEM private key is encrypted with 3DES and CBC the mode of operation.
    The password is strengthened with PBKDF1-MD5.

  <Arguments>
    filepath:
      <filepath> file, an RSA encrypted PEM file.  Unlike the public RSA PEM
      key file, 'filepath' does not have an extension.
    
    password:
      The passphrase to decrypt 'filepath'.

  <Exceptions>
    tuf.FormatError, if the arguments are improperly formatted.

    tuf.CryptoError, if 'filepath' is not a valid encrypted key file.

  <Side Effects>
    The contents of 'filepath' is read, decrypted, and the key stored.

  <Returns>
    An RSA key object, conformant to 'tuf.formats.RSAKEY_SCHEMA'.
  """

  # Does 'filepath' have the correct format?
  # Ensure the arguments have the appropriate number of objects and object
  # types, and that all dict keys are properly named.
  # Raise 'tuf.FormatError' if there is a mismatch.
  tuf.formats.PATH_SCHEMA.check_match(filepath)

  # If the caller does not provide a password argument, prompt for one.
  # Password confirmation disabled here, which should ideally happen only
  # when creating encrypted key files (i.e., improve usability).
  if password is None: # pragma: no cover
    message = 'Enter a password for the encrypted RSA file: '
    password = _get_password(message, confirm=False)

  # Does 'password' have the correct format?
  tuf.formats.PASSWORD_SCHEMA.check_match(password)

  encrypted_pem = None

  # Read the contents of 'filepath' that should be an encrypted PEM.
  with open(filepath, 'rb') as file_object:
    encrypted_pem = file_object.read().decode('utf-8')

  # Convert 'encrypted_pem' to 'tuf.formats.RSAKEY_SCHEMA' format.  Raise
  # 'tuf.CryptoError' if 'encrypted_pem' is invalid.
  rsa_key = tuf.keys.import_rsakey_from_encrypted_pem(encrypted_pem, password)
  
  return rsa_key





def import_rsa_publickey_from_file(filepath):
  """
  <Purpose>
    Import the RSA key stored in 'filepath'.  The key object returned is a TUF
    key, specifically 'tuf.formats.RSAKEY_SCHEMA'.  If the RSA PEM in 'filepath'
    contains a private key, it is discarded.

    Which cryptography library performs the cryptographic decryption is
    determined by the string set in 'tuf.conf.RSA_CRYPTO_LIBRARY'.  PyCrypto
    currently supported.  If the RSA PEM in 'filepath' contains a private key,
    it is discarded.

  <Arguments>
    filepath:
      <filepath>.pub file, an RSA PEM file.
    
  <Exceptions>
    tuf.FormatError, if 'filepath' is improperly formatted.

    tuf.Error, if a valid RSA key object cannot be generated.  This may be
    caused by an improperly formatted PEM file.

  <Side Effects>
    'filepath' is read and its contents extracted.

  <Returns>
    An RSA key object conformant to 'tuf.formats.RSAKEY_SCHEMA'.
  """

  # Does 'filepath' have the correct format?
  # Ensure the arguments have the appropriate number of objects and object
  # types, and that all dict keys are properly named.
  # Raise 'tuf.FormatError' if there is a mismatch.
  tuf.formats.PATH_SCHEMA.check_match(filepath)

  # Read the contents of the key file that should be in PEM format and contains
  # the public portion of the RSA key.
  with open(filepath, 'rb') as file_object:
    rsa_pubkey_pem = file_object.read().decode('utf-8')

  # Convert 'rsa_pubkey_pem' to 'tuf.formats.RSAKEY_SCHEMA' format.
  try:
    rsakey_dict = tuf.keys.format_rsakey_from_pem(rsa_pubkey_pem)
  
  except tuf.FormatError as e:
    raise tuf.Error('Cannot import improperly formatted PEM file.')
  
  return rsakey_dict





def generate_and_write_ed25519_keypair(filepath, password=None):
  """
  <Purpose>
    Generate an ED25519 key file, create an encrypted TUF key (using 'password'
    as the pass phrase), and store it in 'filepath'.  The public key portion of
    the generated ED25519 key is stored in <'filepath'>.pub.  Which cryptography
    library performs the cryptographic decryption is determined by the string
    set in 'tuf.conf.ED25519_CRYPTO_LIBRARY'.
    
    PyCrypto currently supported.  The ED25519 private key is encrypted with
    AES-256 and CTR the mode of operation.  The password is strengthened with
    PBKDF2-HMAC-SHA256.

  <Arguments>
    filepath:
      The public and private key files are saved to <filepath>.pub and
      <filepath>, respectively.
    
    password:
      The password, or passphrase, to encrypt the private portion of the
      generated ed25519 key.  A symmetric encryption key is derived from
      'password', so it is not directly used.

  <Exceptions>
    tuf.FormatError, if the arguments are improperly formatted.
    
    tuf.CryptoError, if 'filepath' cannot be encrypted.

    tuf.UnsupportedLibraryError, if 'filepath' cannot be encrypted due to an
    invalid configuration setting (i.e., invalid 'tuf.conf.py' setting).

  <Side Effects>
    Writes key files to '<filepath>' and '<filepath>.pub'.

  <Returns>
    None.
  """
  
  # Does 'filepath' have the correct format?
  # Ensure the arguments have the appropriate number of objects and object
  # types, and that all dict keys are properly named.
  # Raise 'tuf.FormatError' if there is a mismatch.
  tuf.formats.PATH_SCHEMA.check_match(filepath)

  # If the caller does not provide a password argument, prompt for one.
  if password is None: # pragma: no cover
    message = 'Enter a password for the ED25519 key: '
    password = _get_password(message, confirm=True)

  # Does 'password' have the correct format?
  tuf.formats.PASSWORD_SCHEMA.check_match(password)

  # Generate a new ED25519 key object and encrypt it.  The cryptography library
  # used is determined by the user, or by default (set in
  # 'tuf.conf.ED25519_CRYPTO_LIBRARY').  Raise 'tuf.CryptoError' or
  # 'tuf.UnsupportedLibraryError', if 'ed25519_key' cannot be encrypted.
  ed25519_key = tuf.keys.generate_ed25519_key()
  encrypted_key = tuf.keys.encrypt_key(ed25519_key, password) 

  # ed25519 public key file contents in metadata format (i.e., does not include
  # the keyid portion).
  keytype = ed25519_key['keytype']
  keyval = ed25519_key['keyval']
  ed25519key_metadata_format = \
    tuf.keys.format_keyval_to_metadata(keytype, keyval, private=False)
  
  # Write the public key, conformant to 'tuf.formats.KEY_SCHEMA', to
  # '<filepath>.pub'.
  tuf.util.ensure_parent_dir(filepath)

  # Create a tempororary file, write the contents of the public key, and move
  # to final destination.
  file_object = tuf.util.TempFile()
  file_object.write(json.dumps(ed25519key_metadata_format).encode('utf-8'))
  
  # The temporary file is closed after the final move.
  file_object.move(filepath + '.pub')

  # Write the encrypted key string, conformant to
  # 'tuf.formats.ENCRYPTEDKEY_SCHEMA', to '<filepath>'.
  file_object = tuf.util.TempFile()
  file_object.write(encrypted_key.encode('utf-8'))
  file_object.move(filepath)
  




def import_ed25519_publickey_from_file(filepath):
  """
  <Purpose>
    Load the ED25519 public key object (conformant to 'tuf.formats.KEY_SCHEMA')
    stored in 'filepath'.  Return 'filepath' in tuf.formats.ED25519KEY_SCHEMA
    format.
    
    If the TUF key object in 'filepath' contains a private key, it is discarded.

  <Arguments>
    filepath:
      <filepath>.pub file, a TUF public key file.
    
  <Exceptions>
    tuf.FormatError, if 'filepath' is improperly formatted or is an unexpected
    key type.

  <Side Effects>
    The contents of 'filepath' is read and saved.

  <Returns>
    An ED25519 key object conformant to 'tuf.formats.ED25519KEY_SCHEMA'.
  """

  # Does 'filepath' have the correct format?
  # Ensure the arguments have the appropriate number of objects and object
  # types, and that all dict keys are properly named.
  # Raise 'tuf.FormatError' if there is a mismatch.
  tuf.formats.PATH_SCHEMA.check_match(filepath)

  # ED25519 key objects are saved in json and metadata format.  Return the
  # loaded key object in tuf.formats.ED25519KEY_SCHEMA' format that also
  # includes the keyid.
  ed25519_key_metadata = tuf.util.load_json_file(filepath)
  ed25519_key = tuf.keys.format_metadata_to_key(ed25519_key_metadata)
  
  # Raise an exception if an unexpected key type is imported.
  # Redundant validation of 'keytype'.  'tuf.keys.format_metadata_to_key()'
  # should have fully validated 'ed25519_key_metadata'.
  if ed25519_key['keytype'] != 'ed25519': # pragma: no cover
    message = 'Invalid key type loaded: ' + repr(ed25519_key['keytype'])
    raise tuf.FormatError(message)

  return ed25519_key





def import_ed25519_privatekey_from_file(filepath, password=None):
  """
  <Purpose>
    Import the encrypted ed25519 TUF key file in 'filepath', decrypt it, and
    return the key object in 'tuf.formats.ED25519KEY_SCHEMA' format.

    Which cryptography library performs the cryptographic decryption is
    determined by the string set in 'tuf.conf.ED25519_CRYPTO_LIBRARY'.  PyCrypto
    currently supported.

    The TUF private key (may also contain the public part) is encrypted with AES
    256 and CTR the mode of operation.  The password is strengthened with
    PBKDF2-HMAC-SHA256.

  <Arguments>
    filepath:
      <filepath> file, an RSA encrypted TUF key file.
    
    password:
      The password, or passphrase, to import the private key (i.e., the
      encrypted key file 'filepath' must be decrypted before the ed25519 key
      object can be returned.

  <Exceptions>
    tuf.FormatError, if the arguments are improperly formatted or the imported
    key object contains an invalid key type (i.e., not 'ed25519').

    tuf.CryptoError, if 'filepath' cannot be decrypted.

    tuf.UnsupportedLibraryError, if 'filepath' cannot be decrypted due to an
    invalid configuration setting (i.e., invalid 'tuf.conf.py' setting).

  <Side Effects>
    'password' is used to decrypt the 'filepath' key file.

  <Returns>
    An ed25519 key object of the form: 'tuf.formats.ED25519KEY_SCHEMA'.
  """

  # Does 'filepath' have the correct format?
  # Ensure the arguments have the appropriate number of objects and object
  # types, and that all dict keys are properly named.
  # Raise 'tuf.FormatError' if there is a mismatch.
  tuf.formats.PATH_SCHEMA.check_match(filepath)

  # If the caller does not provide a password argument, prompt for one.
  # Password confirmation disabled here, which should ideally happen only
  # when creating encrypted key files (i.e., improve usability).
  if password is None: # pragma: no cover
    message = 'Enter a password for the encrypted ED25519 key: '
    password = _get_password(message, confirm=False)

  # Does 'password' have the correct format?
  tuf.formats.PASSWORD_SCHEMA.check_match(password)

  # Store the encrypted contents of 'filepath' prior to calling the decryption
  # routine.
  encrypted_key = None

  with open(filepath, 'rb') as file_object:
    encrypted_key = file_object.read()

  # Decrypt the loaded key file, calling the appropriate cryptography library
  # (i.e., set by the user) and generating the derived encryption key from
  # 'password'.  Raise 'tuf.CryptoError' or 'tuf.UnsupportedLibraryError' if the
  # decryption fails.
  key_object = tuf.keys.decrypt_key(encrypted_key, password)

  # Raise an exception if an unexpected key type is imported. 
  if key_object['keytype'] != 'ed25519':
    message = 'Invalid key type loaded: ' + repr(key_object['keytype'])
    raise tuf.FormatError(message)

  return key_object





def get_metadata_filenames(metadata_directory=None):
  """
  <Purpose>
    Return a dictionary containing the filenames of the top-level roles.
    If 'metadata_directory' is set to 'metadata', the dictionary
    returned would contain:

    filenames = {'root.json': 'metadata/root.json',
                 'targets.json': 'metadata/targets.json',
                 'snapshot.json': 'metadata/snapshot.json',
                 'timestamp.json': 'metadata/timestamp.json'}

    If 'metadata_directory' is not set by the caller, the current directory is
    used.

  <Arguments>
    metadata_directory:
      The directory containing the metadata files.

  <Exceptions>
    tuf.FormatError, if 'metadata_directory' is improperly formatted.

  <Side Effects>
    None.

  <Returns>
    A dictionary containing the expected filenames of the top-level
    metadata files, such as 'root.json' and 'snapshot.json'.
  """
  
  if metadata_directory is None:
    metadata_directory = os.getcwd()
  
  # Does 'metadata_directory' have the correct format?
  # Ensure the arguments have the appropriate number of objects and object
  # types, and that all dict keys are properly named.
  # Raise 'tuf.FormatError' if there is a mismatch.
  tuf.formats.PATH_SCHEMA.check_match(metadata_directory)

  # Store the filepaths of the top-level roles, including the
  # 'metadata_directory' for each one.
  filenames = {}

  filenames[ROOT_FILENAME] = \
    os.path.join(metadata_directory, ROOT_FILENAME)
  
  filenames[TARGETS_FILENAME] = \
    os.path.join(metadata_directory, TARGETS_FILENAME)
  
  filenames[SNAPSHOT_FILENAME] = \
    os.path.join(metadata_directory, SNAPSHOT_FILENAME)
  
  filenames[TIMESTAMP_FILENAME] = \
    os.path.join(metadata_directory, TIMESTAMP_FILENAME)

  return filenames





def get_metadata_fileinfo(filename, custom=None):
  """
  <Purpose>
    Retrieve the file information of 'filename'.  The object returned
    conforms to 'tuf.formats.FILEINFO_SCHEMA'.  The information
    generated for 'filename' is stored in metadata files like 'targets.json'.
    The fileinfo object returned has the form:
    
    fileinfo = {'length': 1024,
                'hashes': {'sha256': 1233dfba312, ...},
                'custom': {...}}

  <Arguments>
    filename:
      The metadata file whose file information is needed.  It must exist.

    custom:
      An optional object providing additional information about the file. 

  <Exceptions>
    tuf.FormatError, if 'filename' is improperly formatted.

    tuf.Error, if 'filename' doesn't exist.

  <Side Effects>
    The file is opened and information about the file is generated,
    such as file size and its hash.

  <Returns>
    A dictionary conformant to 'tuf.formats.FILEINFO_SCHEMA'.  This
    dictionary contains the length, hashes, and custom data about the
    'filename' metadata file.  SHA256 hashes are generated by default.
  """

  # Does 'filename' and 'custom' have the correct format?
  # Ensure the arguments have the appropriate number of objects and object
  # types, and that all dict keys are properly named.
  # Raise 'tuf.FormatError' if there is a mismatch.
  tuf.formats.PATH_SCHEMA.check_match(filename)
  if custom is not None:
    tuf.formats.CUSTOM_SCHEMA.check_match(custom)

  if not os.path.isfile(filename):
    message = repr(filename) + ' is not a file.'
    raise tuf.Error(message)
  
  # Note: 'filehashes' is a dictionary of the form
  # {'sha256': 1233dfba312, ...}.  'custom' is an optional
  # dictionary that a client might define to include additional
  # file information, such as the file's author, version/revision
  # numbers, etc.
  filesize, filehashes = \
    tuf.util.get_file_details(filename, tuf.conf.REPOSITORY_HASH_ALGORITHMS)

  return tuf.formats.make_fileinfo(filesize, filehashes, custom)





def get_metadata_versioninfo(rolename):
  """
  <Purpose>
    Retrieve the version information of 'rolename'.  The object returned
    conforms to 'tuf.formats.VERSIONINFO_SCHEMA'.  The information
    generated for 'rolename' is stored in 'snapshot.json'.
    The versioninfo object returned has the form:
    
    versioninfo = {'version': 14}

  <Arguments>
    rolename:
      The metadata role whose versioninfo is needed.  It must exist, otherwise
      a 'tuf.UnknownRoleError' exception is raised.

  <Exceptions>
    tuf.FormatError, if 'rolename' is improperly formatted.

    tuf.UnknownRoleError, if 'rolename' does not exist.

  <Side Effects>
    None.
  
  <Returns>
    A dictionary conformant to 'tuf.formats.VERSIONINFO_SCHEMA'.  This
    dictionary contains the version  number of 'rolename'.
  """
  
  # Does 'rolename' have the correct format?
  # Ensure the arguments have the appropriate number of objects and object
  # types, and that all dict keys are properly named.
  tuf.formats.ROLENAME_SCHEMA.check_match(rolename)
  
  roleinfo = tuf.roledb.get_roleinfo(rolename) 
  versioninfo = {'version': roleinfo['version']}
  
  return versioninfo 





def get_target_hash(target_filepath):
  """
  <Purpose>
    Compute the hash of 'target_filepath'. This is useful in conjunction with
    the "path_hash_prefixes" attribute in a delegated targets role, which
    tells us which paths it is implicitly responsible for.
    
    The repository may optionally organize targets into hashed bins to ease
    target delegations and role metadata management.  The use of consistent
    hashing allows for a uniform distribution of targets into bins. 

  <Arguments>
    target_filepath:
      The path to the target file on the repository. This will be relative to
      the 'targets' (or equivalent) directory on a given mirror.

  <Exceptions>
    None.
 
  <Side Effects>
    None.
  
  <Returns>
    The hash of 'target_filepath'.
  """
  
  return tuf.util.get_target_hash(target_filepath)





def generate_root_metadata(version, expiration_date, consistent_snapshot,
                           compression_algorithms=['gz']):
  """
  <Purpose>
    Create the root metadata.  'tuf.roledb.py' and 'tuf.keydb.py' are read and
    the information returned by these modules is used to generate the root
    metadata object.

  <Arguments>
    version:
      The metadata version number.  Clients use the version number to
      determine if the downloaded version is newer than the one currently
      trusted.
    
    expiration_date:
      The expiration date of the metadata file.  Conformant to
      'tuf.formats.ISO8601_DATETIME_SCHEMA'.

    consistent_snapshot:
      Boolean.  If True, a file digest is expected to be prepended to the
      filename of any target file located in the targets directory.  Each digest
      is stripped from the target filename and listed in the snapshot metadata. 
    
    compression_algorithms:
      A list of compression algorithms to use when generating the compressed
      metadata files for the repository.  The root file specifies the
      algorithms used by the repository.

  <Exceptions>
    tuf.FormatError, if the generated root metadata object could not
    be generated with the correct format.

    tuf.Error, if an error is encountered while generating the root
    metadata object (e.g., a required top-level role not found in 'tuf.roledb'.)
  
  <Side Effects>
    The contents of 'tuf.keydb.py' and 'tuf.roledb.py' are read.

  <Returns>
    A root metadata object, conformant to 'tuf.formats.ROOT_SCHEMA'.
  """

  # Do the arguments have the correct format?
  # Ensure the arguments have the appropriate number of objects and object
  # types, and that all dict keys are properly named.
  # Raise 'tuf.FormatError' if any of the arguments are improperly formatted.
  tuf.formats.METADATAVERSION_SCHEMA.check_match(version)
  tuf.formats.ISO8601_DATETIME_SCHEMA.check_match(expiration_date)
  tuf.formats.BOOLEAN_SCHEMA.check_match(consistent_snapshot)
  tuf.formats.COMPRESSIONS_SCHEMA.check_match(compression_algorithms)

  # The role and key dictionaries to be saved in the root metadata object.
  # Conformant to 'ROLEDICT_SCHEMA' and 'KEYDICT_SCHEMA', respectively. 
  roledict = {}
  keydict = {}

  # Extract the role, threshold, and keyid information of the top-level roles,
  # which Root stores in its metadata.  The necessary role metadata is generated
  # from this information.
  for rolename in ['root', 'targets', 'snapshot', 'timestamp']:
    
    # If a top-level role is missing from 'tuf.roledb.py', raise an exception.
    if not tuf.roledb.role_exists(rolename):
      raise tuf.Error(repr(rolename) + ' not in "tuf.roledb".')
   
    # Keep track of the keys loaded to avoid duplicates.
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
        
        # This appears to be a new keyid.  Generate the key for it.
        if key['keytype'] in ['rsa', 'ed25519']:
          keytype = key['keytype']
          keyval = key['keyval']
          keydict[keyid] = \
            tuf.keys.format_keyval_to_metadata(keytype, keyval, private=False)
        
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
                                                     keydict, roledict,
                                                     consistent_snapshot,
                                                     compression_algorithms)

  return root_metadata 





def generate_targets_metadata(targets_directory, target_files, version,
                              expiration_date, delegations=None,
                              write_consistent_targets=False):
  """
  <Purpose>
    Generate the targets metadata object. The targets in 'target_files' must
    exist at the same path they should on the repo.  'target_files' is a list of
    targets.  The 'custom' field of the targets metadata is not currently
    supported.

  <Arguments>
    targets_directory:
      The directory containing the target files and directories of the 
      repository.

    target_files:
      The target files tracked by 'targets.json'.  'target_files' is a
      dictionary of target paths that are relative to the targets directory and
      an optional custom value (e.g., {'file1.txt': {'custom_data: 0755},
      'Django/module.py': {}}).

    version:
      The metadata version number.  Clients use the version number to
      determine if the downloaded version is newer than the one currently
      trusted.

    expiration_date:
      The expiration date of the metadata file.  Conformant to
      'tuf.formats.ISO8601_DATETIME_SCHEMA'.

    delegations:
      The delegations made by the targets role to be generated.  'delegations'
      must match 'tuf.formats.DELEGATIONS_SCHEMA'.

    write_consistent_targets:
      Boolean that indicates whether file digests should be prepended to the
      target files.
  
  <Exceptions>
    tuf.FormatError, if an error occurred trying to generate the targets
    metadata object.

    tuf.Error, if any of the target files cannot be read. 

  <Side Effects>
    The target files are read and file information generated about them.

  <Returns>
    A targets metadata object, conformant to 'tuf.formats.TARGETS_SCHEMA'.
  """

  # Do the arguments have the correct format?
  # Ensure the arguments have the appropriate number of objects and object
  # types, and that all dict keys are properly named.
  # Raise 'tuf.FormatError' if there is a mismatch.
  tuf.formats.PATH_SCHEMA.check_match(targets_directory)
  tuf.formats.PATH_FILEINFO_SCHEMA.check_match(target_files)
  tuf.formats.METADATAVERSION_SCHEMA.check_match(version)
  tuf.formats.ISO8601_DATETIME_SCHEMA.check_match(expiration_date)
  tuf.formats.BOOLEAN_SCHEMA.check_match(write_consistent_targets)

  if delegations is not None:
    tuf.formats.DELEGATIONS_SCHEMA.check_match(delegations)
  
  # Store the file attributes of targets in 'target_files'.  'filedict',
  # conformant to 'tuf.formats.FILEDICT_SCHEMA', is added to the targets
  # metadata object returned.
  filedict = {}

  # Ensure the user is aware of a non-existent 'target_directory', and convert
  # it to its abosolute path, if it exists.
  targets_directory = _check_directory(targets_directory)

  # Generate the fileinfo of all the target files listed in 'target_files'.
  for target, custom in six.iteritems(target_files):
   
    # The root-most folder of the targets directory should not be included in
    # target paths listed in targets metadata.
    # (e.g., 'targets/more_targets/somefile.txt' -> 'more_targets/somefile.txt')
    relative_targetpath = target

    # Note: join() discards 'targets_directory' if 'target' contains a leading
    # path separator (i.e., is treated as an absolute path).
    target_path = os.path.join(targets_directory, target.lstrip(os.sep))

    # Ensure all target files listed in 'target_files' exist.  If just one of
    # these files does not exist, raise an exception.
    if not os.path.exists(target_path):
      message = repr(target_path) + ' cannot be read.  Unable to generate ' +\
        'targets metadata.'
      raise tuf.Error(message)

    # Add 'custom' if it has been provided.  Custom data about the target is
    # optional and will only be included in metadata (i.e., a 'custom' field in
    # the target's fileinfo dictionary) if specified here.
    custom_data = None
    if len(custom):
      custom_data = custom
      
    filedict[relative_targetpath] = \
      get_metadata_fileinfo(target_path, custom_data)
   
    # Create hard links for 'target_path' if consistent hashing is enabled.
    if write_consistent_targets:
      for target_digest in six.itervalues(filedict[relative_targetpath]['hashes']):
        dirname, basename = os.path.split(target_path)
        digest_filename = target_digest + '.' + basename
        digest_target = os.path.join(dirname, digest_filename)

        if not os.path.exists(digest_target):
          logger.warning('Hard linking target file to ' + repr(digest_target))
          os.link(target_path, digest_target)
  
  # Generate the targets metadata object.
  targets_metadata = tuf.formats.TargetsFile.make_metadata(version,
                                                           expiration_date,
                                                           filedict,
                                                           delegations)

  return targets_metadata





def generate_snapshot_metadata(metadata_directory, version, expiration_date,
                               root_filename, targets_filename,
                               consistent_snapshot=False):
  """
  <Purpose>
    Create the snapshot metadata.  The minimum metadata must exist
    (i.e., 'root.json' and 'targets.json'). This will also look through
    the 'targets/' directory in 'metadata_directory' and the resulting
    snapshot file will list all the delegated roles.

  <Arguments>
    metadata_directory:
      The directory containing the 'root.json' and 'targets.json' metadata
      files.
    
    version:
      The metadata version number.  Clients use the version number to
      determine if the downloaded version is newer than the one currently
      trusted.

    expiration_date:
      The expiration date of the metadata file.
      Conformant to 'tuf.formats.ISO8601_DATETIME_SCHEMA'.

    root_filename:
      The filename of the top-level root role.  The hash and file size of this
      file is listed in the snapshot role.

    targets_filename:
      The filename of the top-level targets role.  The hash and file size of
      this file is listed in the snapshot role.

    consistent_snapshot:
      Boolean.  If True, a file digest is expected to be prepended to the
      filename of any target file located in the targets directory.  Each digest
      is stripped from the target filename and listed in the snapshot metadata. 

  <Exceptions>
    tuf.FormatError, if the arguments are improperly formatted.

    tuf.Error, if an error occurred trying to generate the snapshot metadata
    object.

  <Side Effects>
    The 'root.json' and 'targets.json' files are read.

  <Returns>
    The snapshot metadata object, conformant to 'tuf.formats.SNAPSHOT_SCHEMA'.
  """

  # Do the arguments have the correct format?
  # This check ensures arguments have the appropriate number of objects and 
  # object types, and that all dict keys are properly named.
  # Raise 'tuf.FormatError' if the check fails.
  tuf.formats.PATH_SCHEMA.check_match(metadata_directory)
  tuf.formats.METADATAVERSION_SCHEMA.check_match(version)
  tuf.formats.ISO8601_DATETIME_SCHEMA.check_match(expiration_date)
  tuf.formats.PATH_SCHEMA.check_match(root_filename)
  tuf.formats.PATH_SCHEMA.check_match(targets_filename)
  tuf.formats.BOOLEAN_SCHEMA.check_match(consistent_snapshot)

  metadata_directory = _check_directory(metadata_directory)

  # Retrieve the versioninfo of 'root.json' and 'targets.json'.  The
  # versioninfo contains the version number of these roles.
  versiondict = {}
  versiondict[ROOT_FILENAME] = get_metadata_versioninfo(root_filename)
  versiondict[TARGETS_FILENAME] = get_metadata_versioninfo(targets_filename)

  # We previously also stored the compressed versions of roles in
  # snapshot.json, however, this is no longer needed as their hashes and
  # lengths are no longer used and their version numbers match the uncompressed
  # role files. 

  # Walk the 'targets/' directory and generate the versioninfo of all the role
  # files found.  This information is stored in the 'meta' field of the
  # snapshot metadata object.
  targets_metadata = os.path.join(metadata_directory, 'targets')
  if os.path.exists(targets_metadata) and os.path.isdir(targets_metadata):
    for directory_path, junk_directories, files in os.walk(targets_metadata):
      
      # 'files' here is a list of file names.
      for basename in files:
        metadata_path = os.path.join(directory_path, basename)
        metadata_name = \
          metadata_path[len(metadata_directory):].lstrip(os.path.sep)
        
        # Strip the version number if 'consistent_snapshot' is True.
        # Example:  'targets/unclaimed/10.django.json'  -->
        # 'targets/unclaimed/django.json'
        metadata_name, version_number_junk = \
          _strip_consistent_snapshot_version_number(metadata_name, consistent_snapshot)
        
        # All delegated roles are added to the snapshot file.
        for metadata_extension in METADATA_EXTENSIONS: 
          if metadata_name.endswith(metadata_extension):
            rolename = metadata_name[:-len(metadata_extension)]
            
            # Obsolete role files may still be found.  Ensure only roles loaded
            # in the roledb are included in the Snapshot metadata.
            if tuf.roledb.role_exists(rolename):
              versiondict[metadata_name] = get_metadata_versioninfo(rolename)

  # Generate the Snapshot metadata object.
  snapshot_metadata = tuf.formats.SnapshotFile.make_metadata(version,
                                                             expiration_date,
                                                             versiondict)

  return snapshot_metadata





def generate_timestamp_metadata(snapshot_filename, version, expiration_date):
  """
  <Purpose>
    Generate the timestamp metadata object.  The 'snapshot.json' file must
    exist.

  <Arguments>
    snapshot_filename:
      The required filename of the snapshot metadata file.  The timestamp role
      needs to the calculate the file size and hash of this file.
    
    version:
      The timestamp's version number.  Clients use the version number to
      determine if the downloaded version is newer than the one currently
      trusted.

    expiration_date:
      The expiration date of the metadata file, conformant to
      'tuf.formats.ISO8601_DATETIME_SCHEMA'.

  <Exceptions>
    tuf.FormatError, if the generated timestamp metadata object cannot be
    formatted correctly, or one of the arguments is improperly formatted.

  <Side Effects>
    None.

  <Returns>
    A timestamp metadata object, conformant to 'tuf.formats.TIMESTAMP_SCHEMA'.
  """
  
  # Do the arguments have the correct format?
  # This check ensures arguments have the appropriate number of objects and 
  # object types, and that all dict keys are properly named.
  # Raise 'tuf.FormatError' if the check fails.
  tuf.formats.PATH_SCHEMA.check_match(snapshot_filename)
  tuf.formats.METADATAVERSION_SCHEMA.check_match(version)
  tuf.formats.ISO8601_DATETIME_SCHEMA.check_match(expiration_date)

  # Retrieve the versioninfo of the Snapshot metadata file.
  versioninfo = {}
  versioninfo[SNAPSHOT_FILENAME] = get_metadata_versioninfo('snapshot')

  # We previously saved the versioninfo of the compressed versions of
  # 'snapshot.json' in 'versioninfo'.  Since version numbers are now stored,
  # the version numbers of compressed roles do not change and can thus be
  # excluded.

  # Generate the timestamp metadata object.
  timestamp_metadata = tuf.formats.TimestampFile.make_metadata(version,
                                                               expiration_date,
                                                               versioninfo)

  return timestamp_metadata





def sign_metadata(metadata_object, keyids, filename):
  """
  <Purpose>
    Sign a metadata object. If any of the keyids have already signed the file,
    the old signature is replaced.  The keys in 'keyids' must already be
    loaded in 'tuf.keydb'.

  <Arguments>
    metadata_object:
      The metadata object to sign.  For example, 'metadata' might correspond to
      'tuf.formats.ROOT_SCHEMA' or 'tuf.formats.TARGETS_SCHEMA'.

    keyids:
      The keyids list of the signing keys.

    filename:
      The intended filename of the signed metadata object.
      For example, 'root.json' or 'targets.json'.  This function
      does NOT save the signed metadata to this filename.

  <Exceptions>
    tuf.FormatError, if a valid 'signable' object could not be generated or
    the arguments are improperly formatted.

    tuf.Error, if an invalid keytype was found in the keystore. 
  
  <Side Effects>
    None.

  <Returns>
    A signable object conformant to 'tuf.formats.SIGNABLE_SCHEMA'.
  """

  # Do the arguments have the correct format?
  # This check ensures arguments have the appropriate number of objects and 
  # object types, and that all dict keys are properly named.
  # Raise 'tuf.FormatError' if the check fails.
  tuf.formats.ANYROLE_SCHEMA.check_match(metadata_object)  
  tuf.formats.KEYIDS_SCHEMA.check_match(keyids)
  tuf.formats.PATH_SCHEMA.check_match(filename)

  # Make sure the metadata is in 'signable' format.  That is,
  # it contains a 'signatures' field containing the result
  # of signing the 'signed' field of 'metadata' with each
  # keyid of 'keyids'.
  signable = tuf.formats.make_signable(metadata_object)

  # Sign the metadata with each keyid in 'keyids'.
  for keyid in keyids:
    
    # Load the signing key.
    key = tuf.keydb.get_key(keyid)
    logger.info('Signing ' + repr(filename) + ' with ' + key['keyid'])

    # Create a new signature list.  If 'keyid' is encountered, do not add it
    # to the new list.
    signatures = []
    for signature in signable['signatures']:
      if not keyid == signature['keyid']:
        signatures.append(signature)
      
      else:
        continue
    signable['signatures'] = signatures

    # Generate the signature using the appropriate signing method.
    if key['keytype'] in SUPPORTED_KEY_TYPES:
      if 'private' in key['keyval']:
        signed = signable['signed']
        signature = tuf.keys.create_signature(key, signed)
        signable['signatures'].append(signature)
      
      else:
        logger.warning('Private key unset.  Skipping: ' + repr(keyid))
    
    else:
      raise tuf.Error('The keydb contains a key with an invalid key type.')

  # Raise 'tuf.FormatError' if the resulting 'signable' is not formatted
  # correctly.
  tuf.formats.check_signable_object_format(signable)

  return signable





def write_metadata_file(metadata, filename, version_number,
                        compression_algorithms, consistent_snapshot):
  """
  <Purpose>
    If necessary, write the 'metadata' signable object to 'filename', and the
    compressed version of the metadata file if 'compression' is set.
    Note:  Compression algorithms like gzip attach a timestamp to compressed
    files, so a metadata file compressed multiple times may generate different
    digests even though the uncompressed content has not changed.

  <Arguments>
    metadata:
      The object that will be saved to 'filename', conformant to
      'tuf.formats.SIGNABLE_SCHEMA'.

    filename:
      The filename of the metadata to be written (e.g., 'root.json').
      If a compression algorithm is specified in 'compression_algorithms', the
      compression extention is appended to 'filename'.

    version_number:
      The version number of the metadata file to be written.  The version
      number is needed for consistent snapshots, which prepend the version
      number to 'filename'.

    compression_algorithms:
      Specify the algorithms, as a list of strings, used to compress the
      'metadata'; The only currently available compression option is 'gz'
      (gzip).

    consistent_snapshot:
      Boolean that determines whether the metadata file's digest should be
      prepended to the filename.

  <Exceptions>
    tuf.FormatError, if the arguments are improperly formatted.

    tuf.Error, if the directory of 'filename' does not exist.

    Any other runtime (e.g., IO) exception.

  <Side Effects>
    The 'filename' (or the compressed filename) file is created, or overwritten
    if it exists.

  <Returns>
    None. 
  """

  # Do the arguments have the correct format?
  # This check ensures arguments have the appropriate number of objects and 
  # object types, and that all dict keys are properly named.
  # Raise 'tuf.FormatError' if the check fails.
  tuf.formats.SIGNABLE_SCHEMA.check_match(metadata)
  tuf.formats.PATH_SCHEMA.check_match(filename)
  tuf.formats.METADATAVERSION_SCHEMA.check_match(version_number)
  tuf.formats.COMPRESSIONS_SCHEMA.check_match(compression_algorithms)
  tuf.formats.BOOLEAN_SCHEMA.check_match(consistent_snapshot)

  # Verify the directory of 'filename', and convert 'filename' to its absolute
  # path so that temporary files are moved to their expected destinations.
  filename = os.path.abspath(filename)
  written_filename = filename
  written_consistent_filename = None
  _check_directory(os.path.dirname(filename))

  # Generate the actual metadata file content of 'metadata'.  Metadata is
  # saved as JSON and includes formatting, such as indentation and sorted
  # objects.  The new digest of 'metadata' is also calculated to help determine
  # if re-saving is required.
  file_content = _get_written_metadata(metadata)
 
  if consistent_snapshot:
    dirname, basename = os.path.split(filename)
    version_and_filename = str(version_number) + '.' + basename
    written_consistent_filename = os.path.join(dirname, version_and_filename)
 
  # Verify whether new metadata needs to be written (i.e., has not been
  # previously written or has changed.
  write_new_metadata = False

  # Has the uncompressed metadata changed?  Does it exist?  If so, set
  # 'write_compressed_version' to 'True' so that it is written.
  # Compressed metadata should only be written if it does not exist or the
  # uncompressed version has changed).
  new_digests = {}
  hash_algorithms = tuf.conf.REPOSITORY_HASH_ALGORITHMS
  for hash_algorithm in hash_algorithms: 
    digest_object = tuf.hash.digest(hash_algorithm)
    digest_object.update(file_content)
    new_digests.update({hash_algorithm: digest_object.hexdigest()})

  try:
    file_length_junk, old_digests = tuf.util.get_file_details(written_filename)
    if old_digests != new_digests:
      write_new_metadata = True
  
  # 'tuf.Error' raised if 'filename' does not exist.
  except tuf.Error as e:
    write_new_metadata = True

  if write_new_metadata:
    # The 'metadata' object is written to 'file_object', including compressed
    # versions.  To avoid partial metadata from being written, 'metadata' is
    # first written to a temporary location (i.e., 'file_object') and then moved
    # to 'filename'.
    file_object = tuf.util.TempFile()
    
    # Serialize 'metadata' to the file-like object and then write
    # 'file_object' to disk.  The dictionary keys of 'metadata' are sorted
    # and indentation is used.  The 'tuf.util.TempFile' file-like object is
    # automically closed after the final move.
    file_object.write(file_content)
    logger.debug('Saving ' + repr(written_filename))
    file_object.move(written_filename)
   
    if consistent_snapshot: 
      logger.info('Linking ' + repr(written_consistent_filename))
      os.link(written_filename, written_consistent_filename)
   
  # Generate the compressed versions of 'metadata', if necessary.  A compressed
  # file may be written (without needing to write the uncompressed version) if
  # the repository maintainer adds compression after writing the uncompressed
  # version.
  for compression_algorithm in compression_algorithms:
    file_object = None 
   
    # Ignore the empty string that signifies non-compression.  The uncompressed
    # file was previously written above, if necessary.
    if not len(compression_algorithm):
      continue

    elif compression_algorithm == 'gz':
      file_object = tuf.util.TempFile()
      compressed_filename = filename + '.gz'

      # Instantiate a gzip object, but save compressed content to
      # 'file_object' (i.e., GzipFile instance is based on its 'fileobj'
      # argument).
      gzip_object = gzip.GzipFile(fileobj=file_object, mode='wb') 
      try: 
        gzip_object.write(file_content)
      
      finally:
        gzip_object.close()

    else:
      raise tuf.FormatError('Unknown compression algorithm: ' + repr(compressio_algorithm))
   
    # Save the compressed version, ensuring an unchanged file is not re-saved.
    # Re-saving the same compressed version may cause its digest to unexpectedly
    # change (gzip includes a timestamp) even though content has not changed.
    _write_compressed_metadata(file_object, compressed_filename,
                               write_new_metadata, consistent_snapshot)
  return written_filename





def _write_compressed_metadata(file_object, compressed_filename,
                               write_new_metadata, consistent_snapshot):
  """
  Write compressed versions of metadata, ensuring compressed file that have
  not changed are not re-written, the digest of the compressed file is properly
  added to the compressed filename, and consistent snapshots are also saved.
  Ensure compressed files are written to a temporary location, and then
  moved to their destinations.
  """
 
  # If a consistent snapshot is unneeded, 'file_object' may be simply moved
  # 'compressed_filename' if not already written. 
  if not consistent_snapshot:
    if not os.path.exists(compressed_filename) or write_new_metadata:
      file_object.move(compressed_filename)
    
    # The temporary file must be closed if 'file_object.move()' is not used.
    # tuf.util.TempFile() automatically closes the temp file when move() is
    # called
    else:
      file_object.close_temp_file()
 
  # Consistent snapshots = True.  Ensure the file's digest is included in the
  # compressed filename written, provided it does not already exist.
  else:
    compressed_content = file_object.read()
    new_digests = []
    consistent_filenames = []
   
    # Multiple snapshots may be written if the repository uses multiple
    # hash algorithms.  Generate the digest of the compressed content.
    for hash_algorithm in tuf.conf.REPOSITORY_HASH_ALGORITHMS:
      digest_object = tuf.hash.digest(hash_algorithm)
      digest_object.update(compressed_content)
      new_digests.append(digest_object.hexdigest())
   
    # Attach each digest to the compressed consistent snapshot filename.
    for new_digest in new_digests:
      dirname, basename = os.path.split(compressed_filename)
      digest_and_filename = new_digest + '.' + basename
      consistent_filenames.append(os.path.join(dirname, digest_and_filename))
   
    # Move the 'tuf.util.TempFile' object to one of the filenames so that it is
    # saved and the temporary file closed.  Any remaining consistent snapshots
    # may still need to be copied or linked. 
    compressed_filename = consistent_filenames.pop()
    if not os.path.exists(compressed_filename):
      logger.info('Saving ' + repr(compressed_filename))
      file_object.move(compressed_filename)

    # Save any remaining compressed consistent snapshots.
    for consistent_filename in consistent_filenames:
      if not os.path.exists(consistent_filename):
        logger.info('Linking ' + repr(consistent_filename))
        os.link(compressed_filename, consistent_filename)





def _log_status_of_top_level_roles(targets_directory, metadata_directory):
  """
  Non-public function that logs whether any of the top-level roles contain an
  invalid number of public and private keys, or an insufficient threshold of
  signatures.  Considering that the top-level metadata have to be verified in
  the expected root -> targets -> snapshot -> timestamp order, this function
  logs the error message and returns as soon as a required metadata file is
  found to be invalid.  It is assumed here that the delegated roles have been
  written and verified.  Example output:
  
  'root' role contains 1 / 1 signatures.
  'targets' role contains 1 / 1 signatures.
  'snapshot' role contains 1 / 1 signatures.
  'timestamp' role contains 1 / 1 signatures.

  Note:  Temporary metadata is generated so that file hashes & sizes may be
  computed and verified against the attached signatures.  'metadata_directory'
  should be a directory in a temporary repository directory.
  """

  # The expected full filenames of the top-level roles needed to write them to
  # disk.
  filenames = get_metadata_filenames(metadata_directory)
  root_filename = filenames[ROOT_FILENAME]
  targets_filename = filenames[TARGETS_FILENAME]
  snapshot_filename = filenames[SNAPSHOT_FILENAME]
  timestamp_filename = filenames[TIMESTAMP_FILENAME]

  # Verify that the top-level roles contain a valid number of public keys and
  # that their corresponding private keys have been loaded.
  for rolename in ['root', 'targets', 'snapshot', 'timestamp']:
    try:
      _check_role_keys(rolename)
    
    except tuf.InsufficientKeysError as e:
      logger.info(str(e))
      return

  # Do the top-level roles contain a valid threshold of signatures?  Top-level
  # metadata is verified in Root -> Targets -> Snapshot -> Timestamp order.
  # Verify the metadata of the Root role.
  try:
    signable, root_filename = \
      _generate_and_write_metadata('root', root_filename, False,
                                   targets_directory, metadata_directory)
    _log_status('root', signable)
 
  # 'tuf.UnsignedMetadataError' raised if metadata contains an invalid threshold
  # of signatures.  log the valid/threshold message, where valid < threshold.
  except tuf.UnsignedMetadataError as e:
    _log_status('root', e.signable)
    return

  # Verify the metadata of the Targets role.
  try:
    signable, targets_filename = \
      _generate_and_write_metadata('targets', targets_filename, False,
                                   targets_directory, metadata_directory)
    _log_status('targets', signable)
  
  except tuf.UnsignedMetadataError as e:
    _log_status('targets', e.signable)
    return

  # Verify the metadata of the snapshot role.
  filenames = {'root': root_filename, 'targets': targets_filename} 
  try:
    signable, snapshot_filename = \
      _generate_and_write_metadata('snapshot', snapshot_filename, False,
                                   targets_directory, metadata_directory,
                                   False, filenames)
    _log_status('snapshot', signable)
  
  except tuf.UnsignedMetadataError as e:
    _log_status('snapshot', e.signable)
    return
  
  # Verify the metadata of the Timestamp role.
  filenames = {'snapshot': snapshot_filename}
  try:
    signable, snapshot_filename = \
      _generate_and_write_metadata('timestamp', snapshot_filename, False,
                                   targets_directory, metadata_directory,
                                   False, filenames)
    _log_status('timestamp', signable)
  
  except tuf.UnsignedMetadataError as e:
    _log_status('timestamp', e.signable)
    return




def _log_status(rolename, signable):
  """
  Non-public function logs the number of (good/threshold) signatures of
  'rolename'.
  """
  
  status = tuf.sig.get_signature_status(signable, rolename)

  message = repr(rolename) + ' role contains ' + repr(len(status['good_sigs']))+\
    ' / ' + repr(status['threshold']) + ' signatures.'
  logger.info(message)





def create_tuf_client_directory(repository_directory, client_directory):
  """
  <Purpose>
    Create a client directory structure that the 'tuf.interposition' package
    and 'tuf.client.updater' module expect of clients.  Metadata files
    downloaded from a remote TUF repository are saved to 'client_directory'.
    The Root file must initially exist before an update request can be
    satisfied.  create_tuf_client_directory() ensures the minimum metadata
    is copied and that required directories ('previous' and 'current') are
    created in 'client_directory'.  Software updaters integrating TUF may
    use the client directory created as an initial copy of the repository's
    metadadata.

  <Arguments>
    repository_directory:
      The path of the root repository directory.  The 'metadata' and 'targets'
      sub-directories should be available in 'repository_directory'.  The
      metadata files of 'repository_directory' are copied to 'client_directory'.

    client_directory:
      The path of the root client directory.  The 'current' and 'previous'
      sub-directies are created and will store the metadata files copied
      from 'repository_directory'.  'client_directory' will store metadata
      and target files downloaded from a TUF repository.
  
  <Exceptions>
    tuf.FormatError, if the arguments are improperly formatted.

    tuf.RepositoryError, if the metadata directory in 'client_directory'
    already exists.

  <Side Effects>
    Copies metadata files and directories from 'repository_directory' to
    'client_directory'.  Parent directories are created if they do not exist.

  <Returns>
    None.
  """
  
  # Do the arguments have the correct format?
  # This check ensures arguments have the appropriate number of objects and 
  # object types, and that all dict keys are properly named.
  # Raise 'tuf.FormatError' if the check fails.
  tuf.formats.PATH_SCHEMA.check_match(repository_directory)
  tuf.formats.PATH_SCHEMA.check_match(client_directory)

  # Set the absolute path of the Repository's metadata directory.  The metadata
  # directory should be the one served by the Live repository.  At a minimum,
  # the repository's root file must be copied.
  repository_directory = os.path.abspath(repository_directory)
  metadata_directory = os.path.join(repository_directory,
                                    METADATA_DIRECTORY_NAME)

  # Set the client's metadata directory, which will store the metadata copied
  # from the repository directory set above.
  client_directory = os.path.abspath(client_directory)
  client_metadata_directory = os.path.join(client_directory,
                                           METADATA_DIRECTORY_NAME)
 
  # If the client's metadata directory does not already exist, create it and
  # any of its parent directories, otherwise raise an exception.  An exception
  # is raised to avoid accidently overwritting previous metadata.
  try:
    os.makedirs(client_metadata_directory)
  
  except OSError as e:
    if e.errno == errno.EEXIST:
      message = 'Cannot create a fresh client metadata directory: ' +\
        repr(client_metadata_directory) + '.  Already exists.'
      raise tuf.RepositoryError(message)
    
    else:
      raise

  # Move all  metadata to the client's 'current' and 'previous' directories.
  # The root metadata file MUST exist in '{client_metadata_directory}/current'.
  # 'tuf.interposition' and 'tuf.client.updater.py' expect the 'current' and
  # 'previous' directories to exist under 'metadata'.
  client_current = os.path.join(client_metadata_directory, 'current')
  client_previous = os.path.join(client_metadata_directory, 'previous')
  shutil.copytree(metadata_directory, client_current)
  shutil.copytree(metadata_directory, client_previous)



def disable_console_log_messages():
  """
  <Purpose>
    Disable logger messages printed to the console.  For example, repository
    maintainers may want to call this function if many roles will be sharing
    keys, otherwise detected duplicate keys will continually log a warning
    message.

  <Arguments>
    None.

  <Exceptions>
    None.

  <Side Effects>
    Removes the 'tuf.log' console handler, added by default when
    'tuf.repository_tool.py' is imported.
  
  <Returns>
    None.
  """
  
  tuf.log.remove_console_handler()



if __name__ == '__main__':
  # The interactive sessions of the documentation strings can
  # be tested by running repository_tool.py as a standalone module:
  # $ python repository_lib.py.
  import doctest
  doctest.testmod()
