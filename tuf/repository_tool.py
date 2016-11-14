#!/usr/bin/env python

"""
<Program Name>
  repository_tool.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  October 19, 2013 

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Provide a tool that can create a TUF repository.  It can be used with the
  Python interpreter in interactive mode, or imported directly into a Python
  module.  See 'tuf/README' for the complete guide to using
  'tuf.repository_tool.py'.
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
import time
import datetime
import logging
import tempfile
import shutil
import json
import random

import tuf
import tuf.formats
import tuf.ssl_crypto.util
import tuf.ssl_crypto.keydb
import tuf.roledb
import tuf.ssl_crypto.keys
import tuf.sig
import tuf.log
import tuf.repository_lib as repo_lib
from simple_settings import settings
from tuf.repository_lib import generate_and_write_rsa_keypair
from tuf.repository_lib import generate_and_write_ed25519_keypair
from tuf.repository_lib import import_rsa_publickey_from_file
from tuf.repository_lib import import_ed25519_publickey_from_file
from tuf.repository_lib import import_rsa_privatekey_from_file
from tuf.repository_lib import import_ed25519_privatekey_from_file
from tuf.repository_lib import create_tuf_client_directory
from tuf.repository_lib import disable_console_log_messages 

import iso8601
import six


# See 'log.py' to learn how logging is handled in TUF.
logger = logging.getLogger('tuf.repository_tool')

# Add a console handler so that users are aware of potentially unintended
# states, such as multiple roles that share keys.
tuf.log.add_console_handler()
tuf.log.set_console_log_level(logging.INFO)

# The algorithm used by the repository to generate the digests of the
# target filepaths, which are included in metadata files and may be prepended
# to the filenames of consistent snapshots.
HASH_FUNCTION = 'sha256'

# The targets and metadata directory names.  Metadata files are written
# to the staged metadata directory instead of the "live" one.
METADATA_STAGED_DIRECTORY_NAME = 'metadata.staged'
METADATA_DIRECTORY_NAME = 'metadata'
TARGETS_DIRECTORY_NAME = 'targets' 

# The extension of TUF metadata.
METADATA_EXTENSION = '.json'

# Expiration date delta, in seconds, of the top-level roles.  A metadata
# expiration date is set by taking the current time and adding the expiration
# seconds listed below.

# Initial 'root.json' expiration time of 1 year. 
ROOT_EXPIRATION = 31556900

# Initial 'targets.json' expiration time of 3 months. 
TARGETS_EXPIRATION = 7889230 

# Initial 'snapshot.json' expiration time of 1 week. 
SNAPSHOT_EXPIRATION = 604800 

# Initial 'timestamp.json' expiration time of 1 day.
TIMESTAMP_EXPIRATION = 86400

try:
  tuf.ssl_crypto.keys.check_crypto_libraries(['rsa', 'ed25519', 'general'])

except tuf.ssl_commons.exceptions.UnsupportedLibraryError: #pragma: no cover
  logger.warn('Warning: The repository and developer tools require'
    ' additional libraries, which can be installed as follows:'
    '\n $ pip install tuf[tools]') 


class Repository(object):
  """
  <Purpose>
    Represent a TUF repository that contains the metadata of the top-level
    roles, including all those delegated from the 'targets.json' role.  The
    repository object returned provides access to the top-level roles, and any
    delegated targets that are added as the repository is modified.  For
    example, a Repository object named 'repository' provides the following
    access by default:

    repository.root.version = 2
    repository.timestamp.expiration = datetime.datetime(2015, 8, 8, 12, 0)
    repository.snapshot.add_verification_key(...)
    repository.targets.delegate('unclaimed', ...)

    Delegating a role from 'targets' updates the attributes of the parent
    delegation, which then provides:

    repository.targets('unclaimed').add_verification_key(...)

      
  <Arguments>
    repository_directory:
      The root folder of the repository that contains the metadata and targets
      sub-directories.

    metadata_directory:
      The metadata sub-directory contains the files of the top-level
      roles, including all roles delegated from 'targets.json'. 

    targets_directory:
      The targets sub-directory contains all the target files that are
      downloaded by clients and are referenced in TUF Metadata.  The hashes and
      file lengths are listed in Metadata files so that they are securely
      downloaded.  Metadata files are similarly referenced in the top-level
      metadata.

  <Exceptions>
    tuf.ssl_commons.exceptions.FormatError, if the arguments are improperly
    formatted.

  <Side Effects>
    Creates top-level role objects and assigns them as attributes.

  <Returns>
    A Repository object that contains default Metadata objects for the top-level
    roles.
  """
 
  def __init__(self, repository_directory, metadata_directory, targets_directory):
  
    # Do the arguments have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.  Raise
    # 'tuf.ssl_commons.exceptions.FormatError' if any are improperly formatted.
    tuf.ssl_crypto.formats.PATH_SCHEMA.check_match(repository_directory)
    tuf.ssl_crypto.formats.PATH_SCHEMA.check_match(metadata_directory)
    tuf.ssl_crypto.formats.PATH_SCHEMA.check_match(targets_directory)
    
    self._repository_directory = repository_directory
    self._metadata_directory = metadata_directory
    self._targets_directory = targets_directory
   
    # Set the top-level role objects.
    self.root = Root() 
    self.snapshot = Snapshot()
    self.timestamp = Timestamp()
    self.targets = Targets(self._targets_directory, 'targets')



  def writeall(self, consistent_snapshot=False, compression_algorithms=['gz']):
    """
    <Purpose>
      Write all the JSON Metadata objects to their corresponding files.
      writeall() raises an exception if any of the role metadata to be written
      to disk is invalid, such as an insufficient threshold of signatures,
      missing private keys, etc.
    
    <Arguments>
      consistent_snapshot:
        A boolean indicating whether written metadata and target files should
        include a version number in the filename (i.e.,
        <version_number>.root.json, <version_number>.targets.json.gz,
        <version_number>.README.json
        Example: 13.root.json'
      
      compression_algorithms:
        A list of compression algorithms.  Each of these algorithms will be
        used to compress all of the metadata available on the repository.
        By default, all metadata is compressed with gzip.
        
    <Exceptions>
      tuf.ssl_commons.exceptions.UnsignedMetadataError, if any of the top-level
      and delegated roles do not have the minimum threshold of signatures.

    <Side Effects>
      Creates metadata files in the repository's metadata directory.

    <Returns>
      None.
    """
    
    # Do the arguments have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.
    # Raise 'tuf.ssl_commons.exceptions.FormatError' if any are improperly formatted.
    tuf.ssl_crypto.formats.BOOLEAN_SCHEMA.check_match(consistent_snapshot)
    tuf.ssl_crypto.formats.COMPRESSIONS_SCHEMA.check_match(compression_algorithms)
    
    # At this point, tuf.ssl_crypto.keydb and tuf.roledb must be fully
    # populated, otherwise writeall() throws a
    # 'tuf.ssl_commons.exceptions.UnsignedMetadataError' for the top-level
    # roles.  exception if any of the top-level roles are missing signatures,
    # keys, etc.

    # Write the metadata files of all the Targets roles that are dirty (i.e.,
    # have been modified via roledb.update_roleinfo()).
    filenames = {'root': os.path.join(self._metadata_directory, repo_lib.ROOT_FILENAME),
                 'targets': os.path.join(self._metadata_directory, repo_lib.TARGETS_FILENAME),
                 'snapshot': os.path.join(self._metadata_directory, repo_lib.SNAPSHOT_FILENAME),
                 'timestamp': os.path.join(self._metadata_directory, repo_lib.TIMESTAMP_FILENAME)}

    snapshot_signable = None
    dirty_rolenames = tuf.roledb.get_dirty_roles()

    for dirty_rolename in dirty_rolenames:
     
      # Ignore top-level roles, they will be generated later in this method. 
      if dirty_rolename in ['root', 'targets', 'snapshot', 'timestamp']:
        continue
    
      dirty_filename = os.path.join(self._metadata_directory,
                                    dirty_rolename + METADATA_EXTENSION)
      repo_lib._generate_and_write_metadata(dirty_rolename,
                                            dirty_filename,
                                            self._targets_directory,
                                            self._metadata_directory,
                                            consistent_snapshot,
                                            filenames)
    
    # Metadata should be written in (delegated targets -> root -> targets ->
    # snapshot -> timestamp) order.  Begin by generating the 'root.json'
    # metadata file.  _generate_and_write_metadata() raises a
    # 'tuf.ssl_commons.exceptions.Error' exception if the metadata cannot be
    # written.
    if 'root' in dirty_rolenames or consistent_snapshot:
      repo_lib._generate_and_write_metadata('root', filenames['root'],
                                            self._targets_directory,
                                            self._metadata_directory,
                                            consistent_snapshot,
                                            filenames)

    # Generate the 'targets.json' metadata file.
    if 'targets' in dirty_rolenames:
      repo_lib._generate_and_write_metadata('targets', filenames['targets'],
                                            self._targets_directory,
                                            self._metadata_directory,
                                            consistent_snapshot)
    
    # Generate the 'snapshot.json' metadata file.
    if 'snapshot' in dirty_rolenames:
      snapshot_signable, junk = \
        repo_lib._generate_and_write_metadata('snapshot', filenames['snapshot'],
                                              self._targets_directory,
                                              self._metadata_directory,
                                              consistent_snapshot, filenames)

    # Generate the 'timestamp.json' metadata file.
    if 'timestamp' in dirty_rolenames:
      repo_lib._generate_and_write_metadata('timestamp', filenames['timestamp'],
                                            self._targets_directory,
                                            self._metadata_directory,
                                            consistent_snapshot, filenames)
    
    tuf.roledb.unmark_dirty(dirty_rolenames)

    # Delete the metadata of roles no longer in 'tuf.roledb'.  Obsolete roles
    # may have been revoked and should no longer have their metadata files
    # available on disk, otherwise loading a repository may unintentionally
    # load them.
    if snapshot_signable is not None:
      repo_lib._delete_obsolete_metadata(self._metadata_directory,
                                         snapshot_signable['signed'],
                                         consistent_snapshot)


  
  def write(self, rolename, consistent_snapshot=False, increment_version_number=True):
    """
    <Purpose>
      Write the JSON metadata for 'rolename' to its corresponding file on disk.
      Unlike writeall(), write() allows the metadata file to contain an invalid
      threshold of signatures.  
    
    <Arguments>
      rolename:
        The name of the role to be written to disk.

      consistent_snapshot:
        A boolean indicating whether written metadata and target files should
        include a version number in the filename (i.e.,
        <version_number>.root.json, <version_number>.targets.json.gz,
        <version_number>.README.json
        Example: 13.root.json'

      increment_version_number:
        Boolean indicating whether the version number of 'rolename' should be
        automatically incremented.

    <Exceptions>
      None.

    <Side Effects>
      Creates metadata files in the repository's metadata directory.

    <Returns>
      None.
    """

    rolename_filename = os.path.join(self._metadata_directory,
                                     rolename + METADATA_EXTENSION)
    
    filenames = {'root': os.path.join(self._metadata_directory, repo_lib.ROOT_FILENAME),
                 'targets': os.path.join(self._metadata_directory, repo_lib.TARGETS_FILENAME),
                 'snapshot': os.path.join(self._metadata_directory, repo_lib.SNAPSHOT_FILENAME),
                 'timestamp': os.path.join(self._metadata_directory, repo_lib.TIMESTAMP_FILENAME)}
    
    repo_lib._generate_and_write_metadata(rolename,
                                          rolename_filename,
                                          self._targets_directory,
                                          self._metadata_directory,
                                          consistent_snapshot,
                                          filenames=filenames,
                                          allow_partially_signed=True,
                                          increment_version_number=increment_version_number)

    # Ensure 'rolename' is no longer marked as dirty after the successful write().
    tuf.roledb.unmark_dirty([rolename])
  
  
  


  def status(self):
    """
    <Purpose>
      Determine the status of the top-level roles.  status() checks if each
      role provides sufficient public and private keys, signatures, and that a
      valid metadata file is generated if writeall() or write() were to be
      called.  Metadata files are temporarily written so that file hashes and
      lengths may be verified, determine if delegated role trust is fully
      obeyed, and target paths valid according to parent roles.  status() does
      not do a simple check for number of threshold keys and signatures.

    <Arguments>
      None.

    <Exceptions>
      None.

    <Side Effects>
      Generates and writes temporary metadata files.

    <Returns>
      None.
    """
   
    temp_repository_directory = None

    # Generate and write temporary metadata so that full verification of
    # metadata is possible, such as verifying signatures, digests, and file
    # content.  Ensure temporary files are removed after verification results
    # are completed.
    try:
      temp_repository_directory = tempfile.mkdtemp()
      targets_directory = self._targets_directory
      metadata_directory = os.path.join(temp_repository_directory,
                                        METADATA_STAGED_DIRECTORY_NAME)
      os.mkdir(metadata_directory)

      # Verify the top-level roles and log the results.
      repo_lib._log_status_of_top_level_roles(targets_directory,
                                              metadata_directory)
    
    finally:
      shutil.rmtree(temp_repository_directory, ignore_errors=True)



  def dirty_roles(self):
    """
    <Purpose>
      Print/log the roles that have been modified.  For example, if some role's
      version number is changed (repository.timestamp.version = 2), it is
      considered dirty and will be included in the list of dirty roles
      printed/logged here.  Unlike status(), signatures, public keys, targets,
      etc. are not verified.  status() should be called instead if the caller
      would like to verify if a valid role file is generated if writeall() were
      to be called.
      
    <Arguments>
      None.

    <Exceptions>
      None.
    
    <Side Effects>
      None.

    <Returns>
      None.
    """

    logger.info('Dirty roles: ' + str(tuf.roledb.get_dirty_roles()))



  def mark_dirty(self, roles):
    """
    <Purpose>
      Mark the list of 'roles' as dirty.

    <Arguments>
      roles:
        A list of roles to mark as dirty.  on the next write, these roles
        will be written to disk.

    <Exceptions>
      None.
    
    <Side Effects>
      None.

    <Returns>
      None.
    """
  
    tuf.roledb.mark_dirty(roles)
  
  
  
  def unmark_dirty(self, roles):
    """
    <Purpose>
      No longer mark the list of 'roles' as dirty.

    <Arguments>
      roles:
        A list of roles to mark as dirty.  on the next write, these roles
        will be written to disk.

    <Exceptions>
      None.
    
    <Side Effects>
      None.

    <Returns>
      None.
    """
  
    tuf.roledb.unmark_dirty(roles)



  @staticmethod
  def get_filepaths_in_directory(files_directory, recursive_walk=False,
                                 followlinks=True):
    """
    <Purpose>
      Walk the given 'files_directory' and build a list of target files found.

    <Arguments>
      files_directory:
        The path to a directory of target files.

      recursive_walk:
        To recursively walk the directory, set recursive_walk=True.

      followlinks:
        To follow symbolic links, set followlinks=True.

    <Exceptions>
      tuf.ssl_commons.exceptions.FormatError, if the arguments are improperly
      formatted.

      tuf.ssl_commons.exceptions.Error, if 'file_directory' is not a valid
      directory.

      Python IO exceptions.

    <Side Effects>
      None.

    <Returns>
      A list of absolute paths to target files in the given 'files_directory'.
    """

    # Do the arguments have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.  Raise
    # 'tuf.ssl_commons.exceptions.FormatError' if any are improperly formatted.
    tuf.ssl_crypto.formats.PATH_SCHEMA.check_match(files_directory)
    tuf.ssl_crypto.formats.BOOLEAN_SCHEMA.check_match(recursive_walk)
    tuf.ssl_crypto.formats.BOOLEAN_SCHEMA.check_match(followlinks)

    # Ensure a valid directory is given.
    if not os.path.isdir(files_directory):
      raise tuf.ssl_commons.exceptions.Error(repr(files_directory) + ' is not'
        ' a directory.')
   
    # A list of the target filepaths found in 'files_directory'.
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
      # recursively walk 'files_directory'.
      if recursive_walk is False:
        del dirnames[:]

      else:
        logger.debug('Not pruning subdirectories ' + repr(dirnames))

    return targets





class Metadata(object):
  """
  <Purpose>
    Provide a base class to represent a TUF Metadata role.  There are four
    top-level roles: Root, Targets, Snapshot, and Timestamp.  The Metadata
    class provides methods that are needed by all top-level roles, such as
    adding and removing public keys, private keys, and signatures.  Metadata
    attributes, such as rolename, version, threshold, expiration, key list, and
    compressions, is also provided by the Metadata base class.

  <Arguments>
    None.

  <Exceptions>
    None.

  <Side Effects>
    None.

  <Returns>
    None.
  """

  def __init__(self):
    self._rolename = None    
    


  def add_verification_key(self, key, expires=None):
    """
    <Purpose>
      Add 'key' to the role.  Adding a key, which should contain only the
      public portion, signifies the corresponding private key and signatures
      the role is expected to provide.  A threshold of signatures is required
      for a role to be considered properly signed.  If a metadata file contains
      an insufficient threshold of signatures, it must not be accepted.

      >>> 
      >>> 
      >>> 

    <Arguments>
      key:
        The role key to be added, conformant to
        'tuf.ssl_crypto.formats.ANYKEY_SCHEMA'.  Adding a public key to a role
        means that its corresponding private key must generate and add its
        signature to the role.  A threshold number of signatures is required
        for a role to be fully signed.

      expires:
        The date in which 'key' expires.  'expires' is a datetime.datetime()
        object.

    <Exceptions>
      tuf.ssl_commons.exceptions.FormatError, if any of the arguments are
      improperly formatted.

      tuf.ssl_commons.exceptions.Error, if the 'expires' datetime has already
      expired.

    <Side Effects>
      The role's entries in 'tuf.ssl_crypto.keydb.py' and 'tuf.roledb.py' are
      updated.

    <Returns>
      None.
    """
   
    # Does 'key' have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.  Raise
    # 'tuf.ssl_commons.exceptions.FormatError' if any are improperly formatted.
    tuf.ssl_crypto.formats.ANYKEY_SCHEMA.check_match(key)

    # If 'expires' is unset, choose a default expiration for 'key'.  By
    # default, Root, Targets, Snapshot, and Timestamp keys are set to expire
    # 1 year, 3 months, 1 week, and 1 day from the current time, respectively.
    if expires is None:
      if self.rolename == 'root':
        expires = \
          tuf.formats.unix_timestamp_to_datetime(int(time.time() + ROOT_EXPIRATION))
      
      elif self.rolename == 'Targets':
        expires = \
          tuf.formats.unix_timestamp_to_datetime(int(time.time() + TARGETS_EXPIRATION))
      
      elif self.rolename == 'Snapshot':
        expires = \
          tuf.formats.unix_timestamp_to_datetime(int(time.time() + SNAPSHOT_EXPIRATION))
  
      elif self.rolename == 'Timestamp':
        expires = \
          tuf.formats.unix_timestamp_to_datetime(int(time.time() + TIMESTAMP_EXPIRATION))

      else:
        expires = \
          tuf.formats.unix_timestamp_to_datetime(int(time.time() + TIMESTAMP_EXPIRATION))
    
    # Is 'expires' a datetime.datetime() object?
    # Raise 'tuf.ssl_commons.exceptions.FormatError' if not.
    if not isinstance(expires, datetime.datetime):
      raise tuf.ssl_commons.exceptions.FormatError(repr(expires) + ' is not a'
        ' datetime.datetime() object.') 

    # Truncate the microseconds value to produce a correct schema string 
    # of the form 'yyyy-mm-ddThh:mm:ssZ'.
    expires = expires.replace(microsecond = 0)
    
    # Ensure the expiration has not already passed.
    current_datetime = \
      tuf.formats.unix_timestamp_to_datetime(int(time.time()))
    
    if expires < current_datetime:
      raise tuf.ssl_commons.exceptions.Error(repr(key) + ' has already'
        ' expired.')
   
    # Update the key's 'expires' entry.
    expires = expires.isoformat() + 'Z'
    key['expires'] = expires 

    # Ensure 'key', which should contain the public portion, is added to
    # 'tuf.ssl_crypto.keydb.py'.  Add 'key' to the list of recognized keys.
    # Keys may be shared, so do not raise an exception if 'key' has already
    # been loaded.
    try:
      tuf.ssl_crypto.keydb.add_key(key)
    
    except tuf.ssl_commons.exceptions.KeyAlreadyExistsError:
      logger.warning('Adding a verification key that has already been used.')

    keyid = key['keyid']
    roleinfo = tuf.roledb.get_roleinfo(self.rolename)
    
    previous_keyids = roleinfo['keyids']
   
    # Add 'key' to the role's entry in 'tuf.roledb.py' and avoid duplicates.
    if keyid not in previous_keyids: 
      roleinfo['keyids'].append(keyid)
      roleinfo['previous_keyids'] = previous_keyids
      
      tuf.roledb.update_roleinfo(self._rolename, roleinfo)



  def remove_verification_key(self, key):
    """
    <Purpose>
      Remove 'key' from the role's currently recognized list of role keys.
      The role expects a threshold number of signatures. 

      >>> 
      >>> 
      >>> 

    <Arguments>
      key:
        The role's key, conformant to 'tuf.ssl_crypto.formats.ANYKEY_SCHEMA'.
        'key' should contain only the public portion, as only the public key is
        needed.  The 'add_verification_key()' method should have previously
        added 'key'. 

    <Exceptions>
      tuf.ssl_commons.exceptions.FormatError, if the 'key' argument is
      improperly formatted.
      
      tuf.ssl_commons.exceptions.Error, if the 'key' argument has not been
      previously added.
    
    <Side Effects>
      Updates the role's 'tuf.roledb.py' entry.

    <Returns>
      None.
    """
    
    # Does 'key' have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.  Raise
    # 'tuf.ssl_commons.exceptions.FormatError' if any are improperly formatted.
    tuf.ssl_crypto.formats.ANYKEY_SCHEMA.check_match(key)
    
    keyid = key['keyid']
    roleinfo = tuf.roledb.get_roleinfo(self.rolename)
    
    if keyid in roleinfo['keyids']: 
      roleinfo['keyids'].remove(keyid)
      
      tuf.roledb.update_roleinfo(self._rolename, roleinfo)
    
    else:
      raise tuf.ssl_commons.exceptions.Error('Verification key not found.')
   


  def load_signing_key(self, key):
    """
    <Purpose>
      Load the role key, which must contain the private portion, so that role
      signatures may be generated when the role's metadata file is eventually
      written to disk.

      >>> 
      >>> 
      >>> 

    <Arguments>
      key:
        The role's key, conformant to 'tuf.ssl_crypto.formats.ANYKEY_SCHEMA'.
        It must contain the private key, so that role signatures may be
        generated when writeall() or write() is eventually called to generate
        valid metadata files.

    <Exceptions>
      tuf.ssl_commons.exceptions.FormatError, if 'key' is improperly formatted.

      tuf.ssl_commons.exceptions.Error, if the private key is not found in 'key'.

    <Side Effects>
      Updates the role's 'tuf.ssl_crypto.keydb.py' and 'tuf.roledb.py' entries.

    <Returns>
      None.
    """
    
    # Does 'key' have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.  Raise
    # 'tuf.ssl_commons.exceptions.FormatError' if any are improperly formatted.
    tuf.ssl_crypto.formats.ANYKEY_SCHEMA.check_match(key)
  
    # Ensure the private portion of the key is available, otherwise signatures
    # cannot be generated when the metadata file is written to disk.
    if 'private' not in key['keyval'] or not len(key['keyval']['private']):
      raise tuf.ssl_commons.exceptions.Error('This is not a private key.')

    # Has the key, with the private portion included, been added to the keydb?
    # The public version of the key may have been previously added.
    try:
      tuf.ssl_crypto.keydb.add_key(key)
    
    except tuf.ssl_commons.exceptions.KeyAlreadyExistsError:
      tuf.ssl_crypto.keydb.remove_key(key['keyid'])
      tuf.ssl_crypto.keydb.add_key(key)

    # Update the role's 'signing_keys' field in 'tuf.roledb.py'.
    roleinfo = tuf.roledb.get_roleinfo(self.rolename)
    if key['keyid'] not in roleinfo['signing_keyids']:
      roleinfo['signing_keyids'].append(key['keyid'])
      
      tuf.roledb.update_roleinfo(self.rolename, roleinfo)



  def unload_signing_key(self, key):
    """
    <Purpose>
      Remove a previously loaded role private key (i.e., load_signing_key()).
      The keyid of the 'key' is removed from the list of recognized signing
      keys.

      >>> 
      >>> 
      >>> 

    <Arguments>
      key:
        The role key to be unloaded, conformant to
        'tuf.ssl_crypto.formats.ANYKEY_SCHEMA'.

    <Exceptions>
      tuf.ssl_commons.exceptions.FormatError, if the 'key' argument is
      improperly formatted.

      tuf.ssl_commons.exceptions.Error, if the 'key' argument has not been
      previously loaded.

    <Side Effects>
      Updates the signing keys of the role in 'tuf.roledb.py'.

    <Returns>
      None.
    """
    
    # Does 'key' have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.  Raise
    # 'tuf.ssl_commons.exceptions.FormatError' if any are improperly formatted.
    tuf.ssl_crypto.formats.ANYKEY_SCHEMA.check_match(key)
    
    # Update the role's 'signing_keys' field in 'tuf.roledb.py'.
    roleinfo = tuf.roledb.get_roleinfo(self.rolename)

    # TODO: Should we consider removing keys from keydb that are no longer
    # associated with any roles?  There could be many no-longer-used keys
    # stored in the keydb if not.  For now, just unload the key.
    if key['keyid'] in roleinfo['signing_keyids']:
      roleinfo['signing_keyids'].remove(key['keyid'])
      
      tuf.roledb.update_roleinfo(self.rolename, roleinfo)
    
    else:
      raise tuf.ssl_commons.exceptions.Error('Signing key not found.')
      


  def add_signature(self, signature, mark_role_as_dirty=True):
    """
    <Purpose>
      Add a signature to the role.  A role is considered fully signed if it
      contains a threshold of signatures.  The 'signature' should have been
      generated by the private key corresponding to one of the role's expected
      keys.

      >>> 
      >>> 
      >>> 

    <Arguments>
      signature:
        The signature to be added to the role, conformant to
        'tuf.ssl_crypto.formats.SIGNATURE_SCHEMA'.

      mark_role_as_dirty:
        A boolean indicating whether the updated 'roleinfo' for 'rolename'
        should be marked as dirty.  The caller might not want to mark
        'rolename' as dirty if it is loading metadata from disk and only wants
        to populate roledb.py.  Likewise, add_role() would support a similar
        boolean to allow the repository tools to successfully load roles via
        load_repository() without needing to mark these roles as dirty (default
        behavior).


    <Exceptions>
      tuf.ssl_commons.exceptions.FormatError, if the 'signature' argument is
      improperly formatted.

    <Side Effects>
      Adds 'signature', if not already added, to the role's 'signatures' field
      in 'tuf.roledb.py'.

    <Returns>
      None.
    """
    
    # Does 'signature' have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.  Raise
    # 'tuf.ssl_commons.exceptions.FormatError' if any are improperly formatted.
    tuf.ssl_crypto.formats.SIGNATURE_SCHEMA.check_match(signature)
    tuf.ssl_crypto.formats.BOOLEAN_SCHEMA.check_match(mark_role_as_dirty) 

    roleinfo = tuf.roledb.get_roleinfo(self.rolename)
    
    # Ensure the roleinfo contains a 'signatures' field.
    if 'signatures' not in roleinfo:
      roleinfo['signatures'] = []
   
    # Update the role's roleinfo by adding 'signature', if it has not been
    # added.
    if signature not in roleinfo['signatures']:
      roleinfo['signatures'].append(signature)
      tuf.roledb.update_roleinfo(self.rolename, roleinfo, mark_role_as_dirty)

    else:
      logger.debug('Signature already exists for role: ' + repr(self.rolename))



  def remove_signature(self, signature):
    """
    <Purpose>
      Remove a previously loaded, or added, role 'signature'.  A role must
      contain a threshold number of signatures to be considered fully signed.

      >>> 
      >>> 
      >>> 

    <Arguments>
      signature:
        The role signature to remove, conformant to
        'tuf.ssl_crypto.formats.SIGNATURE_SCHEMA'.

    <Exceptions>
      tuf.ssl_commons.exceptions.FormatError, if the 'signature' argument is
      improperly formatted.

      tuf.ssl_commons.exceptions.Error, if 'signature' has not been previously
      added to this role.

    <Side Effects>
      Updates the 'signatures' field of the role in 'tuf.roledb.py'.

    <Returns>
      None.
    """
    
    # Does 'signature' have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.  Raise
    # 'tuf.ssl_commons.exceptions.FormatError' if any are improperly formatted.
    tuf.ssl_crypto.formats.SIGNATURE_SCHEMA.check_match(signature)
  
    roleinfo = tuf.roledb.get_roleinfo(self.rolename)
    
    if signature in roleinfo['signatures']:
      roleinfo['signatures'].remove(signature)
      
      tuf.roledb.update_roleinfo(self.rolename, roleinfo)

    else:
      raise tuf.ssl_commons.exceptions.Error('Signature not found.')



  @property
  def signatures(self):
    """
    <Purpose>
      A getter method that returns the role's signatures.  A role is considered
      fully signed if it contains a threshold number of signatures, where each
      signature must be provided by the generated by the private key.  Keys
      are added to a role with the add_verification_key() method.

    <Arguments>
      None.

    <Exceptions>
      None.

    <Side Effects>
      None.

    <Returns>
      A list of signatures, conformant to
      'tuf.ssl_crypto.formats.SIGNATURES_SCHEMA'.
    """

    roleinfo = tuf.roledb.get_roleinfo(self.rolename)
    signatures = roleinfo['signatures']
  
    return signatures



  @property
  def keys(self):
    """
    <Purpose>
      A getter method that returns the role's keyids of the keys.  The role
      is expected to eventually contain a threshold of signatures generated
      by the private keys of each of the role's keys (returned here as a keyid.)

    <Arguments>
      None.

    <Exceptions>
      None.

    <Side Effects>
      None.

    <Returns>
      A list of the role's keyids (i.e., keyids of the keys). 
    """

    roleinfo = tuf.roledb.get_roleinfo(self.rolename)
    keyids = roleinfo['keyids']

    return keyids



  @property
  def rolename(self):
    """
    <Purpose>
      Return the role's name.
      Examples: 'root', 'timestamp', 'targets/unclaimed/django'.

    <Arguments>
      None.

    <Exceptions>
      None.

    <Side Effects>
      None.

    <Returns>
      The role's name, conformant to 'tuf.ssl_crypto.formats.ROLENAME_SCHEMA'.
      Examples: 'root', 'timestamp', 'targets/unclaimed/django'.
    """

    return self._rolename
  
  
  
  @property
  def version(self):
    """
    <Purpose>
      A getter method that returns the role's version number, conformant to
      'tuf.ssl_crypto.formats.VERSION_SCHEMA'.

    <Arguments>
      None.

    <Exceptions>
      None.

    <Side Effects>
      None.

    <Returns>
      The role's version number, conformant to
      'tuf.ssl_crypto.formats.VERSION_SCHEMA'.
    """
    
    roleinfo = tuf.roledb.get_roleinfo(self.rolename)
    version = roleinfo['version'] 

    return version
  
  
  
  @version.setter
  def version(self, version):
    """
    <Purpose>
      A setter method that updates the role's version number.  TUF clients
      download new metadata with version number greater than the version
      currently trusted.  New metadata start at version 1 when either write()
      or write_partial() is called.  Version numbers are automatically
      incremented, when the write methods are called, as follows: 
      
      1.  write_partial==True and the metadata is the first to be written.
      
      2.  write_partial=False (i.e., write()), the metadata was not loaded as
          partially written, and a write_partial is not needed.

      >>> 
      >>> 
      >>> 

    <Arguments>
      version:
        The role's version number, conformant to
        'tuf.ssl_crypto.formats.VERSION_SCHEMA'.

    <Exceptions>
      tuf.ssl_commons.exceptions.FormatError, if the 'version' argument is
      improperly formatted.

    <Side Effects>
      Modifies the 'version' attribute of the Repository object and updates the
      role's version in 'tuf.roledb.py'.

    <Returns>
      None.
    """
    
    # Does 'version' have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.  Raise
    # 'tuf.ssl_commons.exceptions.FormatError' if any are improperly formatted.
    tuf.ssl_crypto.formats.METADATAVERSION_SCHEMA.check_match(version)
    
    roleinfo = tuf.roledb.get_roleinfo(self.rolename)
    roleinfo['version'] = version 
    
    tuf.roledb.update_roleinfo(self._rolename, roleinfo)



  @property
  def threshold(self):
    """
    <Purpose>
      Return the role's threshold value.  A role is considered fully signed if
      a threshold number of signatures is available.

    <Arguments>
      None.

    <Exceptions>
      None.

    <Side Effects>
      None.

    <Returns>
      The role's threshold value, conformant to
      'tuf.ssl_crypto.formats.THRESHOLD_SCHEMA'.
    """
    
    roleinfo = tuf.roledb.get_roleinfo(self._rolename)
    threshold = roleinfo['threshold']

    return threshold



  @threshold.setter 
  def threshold(self, threshold):
    """
    <Purpose>
      A setter method that modified the threshold value of the role.  Metadata
      is considered fully signed if a 'threshold' number of signatures is
      available.

      >>> 
      >>> 
      >>> 

    <Arguments>
      threshold:
        An integer value that sets the role's threshold value, or the miminum
        number of signatures needed for metadata to be considered fully
        signed.  Conformant to 'tuf.ssl_crypto.formats.THRESHOLD_SCHEMA'.

    <Exceptions>
      tuf.ssl_commons.exceptions.FormatError, if the 'threshold' argument is
      improperly formatted.

    <Side Effects>
      Modifies the threshold attribute of the Repository object and updates
      the roles threshold in 'tuf.roledb.py'.

    <Returns>
      None.
    """
   
    # Does 'threshold' have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.  Raise
    # 'tuf.ssl_commons.exceptions.FormatError' if any are improperly formatted.
    tuf.ssl_crypto.formats.THRESHOLD_SCHEMA.check_match(threshold)
    
    roleinfo = tuf.roledb.get_roleinfo(self._rolename)
    roleinfo['previous_threshold'] = roleinfo['threshold']
    roleinfo['threshold'] = threshold
    
    tuf.roledb.update_roleinfo(self._rolename, roleinfo)
 

  @property
  def expiration(self):
    """
    <Purpose>
      A getter method that returns the role's expiration datetime.

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
      The role's expiration datetime, a datetime.datetime() object.
    """
    
    roleinfo = tuf.roledb.get_roleinfo(self.rolename)
    expires = roleinfo['expires']

    expires_datetime_object = iso8601.parse_date(expires)
    
    return expires_datetime_object 



  @expiration.setter
  def expiration(self, datetime_object):
    """
    <Purpose>
      A setter method for the role's expiration datetime.  The top-level
      roles have a default expiration (e.g., ROOT_EXPIRATION), but may later
      be modified by this setter method.
      
      >>>  
      >>> 
      >>> 

    <Arguments>
      datetime_object:
        The datetime expiration of the role, a datetime.datetime() object.

    <Exceptions>
      tuf.ssl_commons.exceptions.FormatError, if 'datetime_object' is not a
      datetime.datetime() object. 
   
      tuf.ssl_commons.exceptions.Error, if 'datetime_object' has already
      expired.

    <Side Effects>
      Modifies the expiration attribute of the Repository object. 
      The datetime given will be truncated to microseconds = 0

    <Returns>
      None.
    """
    
    # Is 'datetime_object' a datetime.datetime() object?
    # Raise 'tuf.ssl_commons.exceptions.FormatError' if not.
    if not isinstance(datetime_object, datetime.datetime):
      raise tuf.ssl_commons.exceptions.FormatError(repr(datetime_object) + ' is'
        ' not a datetime.datetime() object.') 

    # truncate the microseconds value to produce a correct schema string 
    # of the form yyyy-mm-ddThh:mm:ssZ
    datetime_object = datetime_object.replace(microsecond = 0)
    
    # Ensure the expiration has not already passed.
    current_datetime_object = \
      tuf.formats.unix_timestamp_to_datetime(int(time.time()))
    
    if datetime_object < current_datetime_object:
      raise tuf.ssl_commons.exceptions.Error(repr(self.rolename) + ' has'
        ' already expired.')
   
    # Update the role's 'expires' entry in 'tuf.roledb.py'.
    roleinfo = tuf.roledb.get_roleinfo(self.rolename)
    expires = datetime_object.isoformat() + 'Z'
    roleinfo['expires'] = expires 
    
    tuf.roledb.update_roleinfo(self.rolename, roleinfo)
  
  
  
  @property
  def signing_keys(self):
    """
    <Purpose>
      A getter method that returns a list of the role's signing keys.

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
      A list of keyids of the role's signing keys, conformant to
      'tuf.ssl_crypto.formats.KEYIDS_SCHEMA'.
    """

    roleinfo = tuf.roledb.get_roleinfo(self.rolename)
    signing_keyids = roleinfo['signing_keyids']

    return signing_keyids



  @property
  def compressions(self):
    """
    <Purpose>
      A getter method that returns a list of the file compression algorithms
      used when the metadata is written to disk.  If ['gz'] is set for the
      'targets.json' role, the metadata files 'targets.json' and
      'targets.json.gz' are written.

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
      A list of compression algorithms, conformant to
      'tuf.ssl_crypto.formats.COMPRESSIONS_SCHEMA'.
    """

    roleinfo = tuf.roledb.get_roleinfo(self.rolename)
    compressions = roleinfo['compressions']

    return compressions



  @compressions.setter
  def compressions(self, compression_list):
    """
    <Purpose>
      A setter method for the file compression algorithms used when the
      metadata is written to disk.  If ['gz'] is set for the 'targets.json' role
      the metadata files 'targets.json' and 'targets.json.gz' are written.

      >>>  
      >>> 
      >>> 

    <Arguments>
      compression_list:
        A list of file compression algorithms, conformant to
        'tuf.ssl_crypto.formats.COMPRESSIONS_SCHEMA'.

    <Exceptions>
      tuf.ssl_commons.exceptions.FormatError, if 'compression_list' is
      improperly formatted.

    <Side Effects>
      Updates the role's compression algorithms listed in 'tuf.roledb.py'.

    <Returns>
      None. 
    """
   
    # Does 'compression_name' have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.  Raise
    # 'tuf.ssl_commons.exceptions.FormatError' if any are improperly formatted.
    tuf.ssl_crypto.formats.COMPRESSIONS_SCHEMA.check_match(compression_list)

    roleinfo = tuf.roledb.get_roleinfo(self.rolename)
   
    # Add the compression algorithms of 'compression_list' to the role's
    # entry in 'tuf.roledb.py'.
    for compression in compression_list:
      if compression not in roleinfo['compressions']:
        roleinfo['compressions'].append(compression)
    
    tuf.roledb.update_roleinfo(self.rolename, roleinfo)





class Root(Metadata):
  """
  <Purpose>
    Represent a Root role object.  The root role is responsible for
    listing the public keys and threshold of all the top-level roles, including
    itself.  Top-level metadata is rejected if it does not comply with what is
    specified by the Root role.
    
    This Root object sub-classes Metadata, so the expected Metadata
    operations like adding/removing public keys, signatures, private keys, and
    updating metadata attributes (e.g., version and expiration) is supported.
    Since Root is a top-level role and must exist, a default Root object
    is instantiated when a new Repository object is created.

    >>> 
    >>> 
    >>> 

  <Arguments>
    None.
  
  <Exceptions>
    None.

  <Side Effects>
    A 'root' role is added to 'tuf.roledb.py'.

  <Returns>
    None.
  """

  def __init__(self):
    
    super(Root, self).__init__() 
    
    self._rolename = 'root'
   
    # By default, 'snapshot' metadata is set to expire 1 week from the current
    # time.  The expiration may be modified.
    expiration = \
      tuf.formats.unix_timestamp_to_datetime(int(time.time() + ROOT_EXPIRATION))
    expiration = expiration.isoformat() + 'Z'

    roleinfo = {'keyids': [], 'signing_keyids': [], 'threshold': 1, 
                'signatures': [], 'version': 0, 'consistent_snapshot': False,
                'compressions': [''], 'expires': expiration,
                'partial_loaded': False}
    try: 
      tuf.roledb.add_role(self._rolename, roleinfo)
    
    except tuf.ssl_commons.exceptions.RoleAlreadyExistsError:
      pass





class Timestamp(Metadata):
  """
  <Purpose>
    Represent a Timestamp role object.  The timestamp role is responsible for
    referencing the latest version of the Snapshot role.  Under normal
    conditions, it is the only role to be downloaded from a remote repository
    without a known file length and hash.  An upper length limit is set, though.
    Also, its signatures are also verified to be valid according to the Root
    role.  If invalid metadata can only be downloaded by the client, Root
    is the only other role that is downloaded without a known length and hash.
    This case may occur if a role's signing keys have been revoked and a newer
    Root file is needed to list the updated keys. 
    
    This Timestamp object sub-classes Metadata, so the expected Metadata
    operations like adding/removing public keys, signatures, private keys, and
    updating metadata attributes (e.g., version and expiration) is supported.
    Since Snapshot is a top-level role and must exist, a default Timestamp
    object is instantiated when a new Repository object is created.

    >>>
    >>>
    >>>

  <Arguments>
    None.

  <Exceptions>
    None.

  <Side Effects>
    A 'timestamp' role is added to 'tuf.roledb.py'.

  <Returns>
    None.
  """

  def __init__(self):
    
    super(Timestamp, self).__init__() 
    
    self._rolename = 'timestamp'

    # By default, 'root' metadata is set to expire 1 year from the current
    # time.  The expiration may be modified.
    expiration = \
      tuf.formats.unix_timestamp_to_datetime(int(time.time() + TIMESTAMP_EXPIRATION))
    expiration = expiration.isoformat() + 'Z'

    roleinfo = {'keyids': [], 'signing_keyids': [], 'threshold': 1,
                'signatures': [], 'version': 0, 'compressions': [''],
                'expires': expiration, 'partial_loaded': False}
    
    try: 
      tuf.roledb.add_role(self.rolename, roleinfo)
    
    except tuf.ssl_commons.exceptions.RoleAlreadyExistsError:
      pass





class Snapshot(Metadata):
  """
  <Purpose>
    Represent a Snapshot role object.  The snapshot role is responsible for
    referencing the other top-level roles (excluding Timestamp) and all
    delegated roles.
    
    This Snapshot object sub-classes Metadata, so the expected
    Metadata operations like adding/removing public keys, signatures, private
    keys, and updating metadata attributes (e.g., version and expiration) is
    supported.  Since Snapshot is a top-level role and must exist, a default
    Snapshot object is instantiated when a new Repository object is created.

    >>> 
    >>>
    >>>

  <Arguments>
    None.

  <Exceptions>
    None.

  <Side Effects>
    A 'snapshot' role is added to 'tuf.roledb.py'.

  <Returns>
    None.
  """

  def __init__(self):
    
    super(Snapshot, self).__init__() 
    
    self._rolename = 'snapshot' 
   
    # By default, 'snapshot' metadata is set to expire 1 week from the current
    # time.  The expiration may be modified.
    expiration = \
      tuf.formats.unix_timestamp_to_datetime(int(time.time() + SNAPSHOT_EXPIRATION))
    expiration = expiration.isoformat() + 'Z'

    roleinfo = {'keyids': [], 'signing_keyids': [], 'threshold': 1,
                'signatures': [], 'version': 0, 'compressions': [''],
                'expires': expiration, 'partial_loaded': False}
    
    try:
      tuf.roledb.add_role(self._rolename, roleinfo)
    
    except tuf.ssl_commons.exceptions.RoleAlreadyExistsError:
      pass





class Targets(Metadata):
  """
  <Purpose>
    Represent a Targets role object.  Targets roles include the top-level role 
    'targets.json' and all delegated roles (e.g., 'targets/unclaimed/django').
    The expected operations of Targets metadata is included, such as adding
    and removing repository target files, making and revoking delegations, and
    listing the target files provided by it.
    
    Adding or removing a delegation causes the attributes of the Targets object
    to be updated.  That is, if the 'django' Targets object is delegated by
    'targets/unclaimed', a new attribute is added so that the following
    code statement is supported:
    repository.targets('unclaimed')('django').version = 2

    Likewise, revoking a delegation causes removal of the delegation attribute.
    
    This Targets object sub-classes Metadata, so the expected Metadata
    operations like adding/removing public keys, signatures, private keys, and
    updating metadata attributes (e.g., version and expiration) is supported.
    Since Targets is a top-level role and must exist, a default Targets object
    (for 'targets.json', not delegated roles) is instantiated when a new
    Repository object is created.

    >>> 
    >>>
    >>>

  <Arguments>
    targets_directory:
      The targets directory of the Repository object.

    rolename:
      The rolename of this Targets object.

    roleinfo:
      An already populated roleinfo object of 'rolename'.  Conformant to
      'tuf.ssl_crypto.formats.ROLEDB_SCHEMA'.

  <Exceptions>
    tuf.ssl_commons.exceptions.FormatError, if the arguments are improperly
    formatted.

  <Side Effects>
    Modifies the roleinfo of the targets role in 'tuf.roledb', or creates
    a default one named 'targets'.
  
  <Returns>
    None.
  """
  
  def __init__(self, targets_directory, rolename='targets', roleinfo=None,
               parent_targets_object=None):
   
    # Do the arguments have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.  Raise
    # 'tuf.ssl_commons.exceptions.FormatError' if any are improperly formatted.
    tuf.ssl_crypto.formats.PATH_SCHEMA.check_match(targets_directory)
    tuf.ssl_crypto.formats.ROLENAME_SCHEMA.check_match(rolename)
    
    if roleinfo is not None:
      tuf.ssl_crypto.formats.ROLEDB_SCHEMA.check_match(roleinfo)

    super(Targets, self).__init__()
    self._targets_directory = targets_directory
    self._rolename = rolename 
    self._target_files = []
    self._delegated_roles = {}
    self._parent_targets_object = self 

    # Keep a reference to the top-level 'targets' object.  Any delegated roles
    # that may be created, can be added to and accessed via the top-level
    # 'targets' object.
    if parent_targets_object is not None:
      self._parent_targets_object = parent_targets_object
  
    # By default, Targets objects are set to expire 3 months from the current
    # time.  May be later modified.
    expiration = \
      tuf.formats.unix_timestamp_to_datetime(int(time.time() + TARGETS_EXPIRATION))
    expiration = expiration.isoformat() + 'Z'

    # If 'roleinfo' is not provided, set an initial default.
    if roleinfo is None:
      roleinfo = {'keyids': [], 'signing_keyids': [], 'threshold': 1,
                  'version': 0, 'compressions': [''], 'expires': expiration,
                  'signatures': [], 'paths': {}, 'path_hash_prefixes': [],
                  'partial_loaded': False, 'delegations': {'keys': {},
                                                           'roles': []}}
   
    # Add the new role to the 'tuf.roledb'.
    try:
      tuf.roledb.add_role(self.rolename, roleinfo)
    
    except tuf.ssl_commons.exceptions.RoleAlreadyExistsError:
      pass  



  def __call__(self, rolename):
    """
    <Purpose>
      Allow callable Targets object so that delegated roles may be referenced
      by their string rolenames.  Rolenames may include characters like '-' and
      are not restricted to Python identifiers.

    <Arguments>
      rolename:
        The rolename of the delegated role.  'rolename' must be a role
        previously delegated by this Targets role.

    <Exceptions>
      tuf.ssl_commons.exceptions.FormatError, if the arguments are improperly
      formatted.

      tuf.ssl_commons.exceptions.UnknownRoleError, if 'rolename' has not been
      delegated by this Targets object.

    <Side Effects>
      Modifies the roleinfo of the targets role in 'tuf.roledb'.
    
    <Returns>
      The Targets object of 'rolename'. 
    """
    
    # Do the arguments have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.  Raise
    # 'tuf.ssl_commons.exceptions.FormatError' if any are improperly formatted.
    tuf.ssl_crypto.formats.ROLENAME_SCHEMA.check_match(rolename)
   
    if rolename in self._delegated_roles:
      return self._delegated_roles[rolename]
    
    else:
      raise tuf.ssl_commons.exceptions.UnknownRoleError(repr(rolename) + ' has'
        ' not been delegated by ' + repr(self.rolename))



  def add_delegated_role(self, rolename, targets_object):
    """ 
    <Purpose>
      Add 'targets_object' to this Targets object's list of known delegated
      roles.  Specifically, delegated Targets roles should call 'super(Targets,
      self).add_delegated_role(...)' so that the top-level 'targets' role
      contains a dictionary of all the available roles on the repository.
    
    <Arguments>
      rolename:
        The rolename of the delegated role.  'rolename' must be a role
        previously delegated by this Targets role.

      targets_object:
        A Targets() object. 

    <Exceptions>
      tuf.ssl_commons.exceptions.FormatError, if the arguments are improperly
      formatted.

    <Side Effects>
      Updates the Target object's dictionary of delegated targets.
    
    <Returns>
      The Targets object of 'rolename'.
    """
    
    # Do the arguments have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.  Raise
    # 'tuf.ssl_commons.exceptions.FormatError' if any are improperly formatted.
    tuf.ssl_crypto.formats.ROLENAME_SCHEMA.check_match(rolename)
  
    if not isinstance(targets_object, Targets):
      raise tuf.ssl_commons.exceptions.FormatError(repr(targets_object) + ' is'
        ' not a Targets object.')
   

    if rolename in self._delegated_roles:
      logger.debug(repr(rolename) + ' already exists.')
    
    else:
      self._delegated_roles[rolename] = targets_object
  


  def remove_delegated_role(self, rolename):
    """
      Remove 'rolename' from this Targets object's list of delegated roles.
      This method does not update tuf.roledb and others.

    <Arguments>
      rolename:
        The rolename of the delegated role to remove.  'rolename' should be a
        role previously delegated by this Targets role.

    <Exceptions>
      tuf.ssl_commons.exceptions.FormatError, if the argument is improperly
      formatted.

    <Side Effects>
      Updates the Target object's dictionary of delegated targets.
    
    <Returns>
      None.
    """

    # Do the arguments have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.  Raise
    # 'tuf.ssl_commons.exceptions.FormatError' if any are improperly formatted.
    tuf.ssl_crypto.formats.ROLENAME_SCHEMA.check_match(rolename)
    
    if rolename not in self._delegated_roles:
      logger.debug(repr(rolename) + ' has not been delegated.') 
      return
    
    else:
      del self._delegated_roles[rolename]



  @property
  def target_files(self):
    """
    <Purpose>
      A getter method that returns the target files added thus far to this
      Targets object.

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
      None.
    """

    target_files = tuf.roledb.get_roleinfo(self._rolename)['paths']

    return target_files



  def add_restricted_paths(self, restricted_paths, child_rolename):
    """
    <Purpose>
      Add 'restricted_paths' to the restricted paths of 'child_rolename'.
      The updater client verifies the target paths specified by child roles, and
      searches for targets by visiting these restricted paths.  A child role may
      only provide targets specifically listed in the delegations field of the
      parent, or a target that matches a restricted path.

      >>> 
      >>>
      >>>

    <Arguments>
      restricted_paths:
        A list of paths that 'child_rolename' should be restricted to.

      child_rolename:
        The child delegation that requires an update to its restricted paths,
        as listed in the parent role's delegations (e.g., 'Django' in
        'unclaimed').

    <Exceptions>
      tuf.ssl_commons.exceptions.Error, if a restricted path in
      'restricted_paths' is not a string path, doesn't live under the
      repository's targets directory, or if 'child_rolename' has not been
      delegated yet. 

    <Side Effects>
      Modifies this Targets' delegations field.
    
    <Returns>
      None.
    """
    
    # Does 'filepath' have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.
    # Raise 'tuf.ssl_commons.exceptions.FormatError' if there is a mismatch.
    tuf.ssl_crypto.formats.PATHS_SCHEMA.check_match(restricted_paths)
    tuf.ssl_crypto.formats.ROLENAME_SCHEMA.check_match(child_rolename)

    # A list of relative and verified paths to be added to the child role's
    # entry in the parent's delegations.
    relative_paths = []
   
    # Ensure that 'child_rolename' exists, otherwise it will not have an entry
    # in the parent role's delegations field.
    if not tuf.roledb.role_exists(child_rolename):
      raise tuf.ssl_commons.exceptions.Error(repr(child_rolename) + ' does'
        ' not exist.')

    for restricted_path in restricted_paths:
      # Do the restricted paths fall under the repository's targets directory?
      # Append a trailing path separator with os.path.join(path, '').
      targets_directory = os.path.join(self._targets_directory, '')
      if not restricted_path.startswith(targets_directory):
        raise tuf.ssl_commons.exceptions.Error(repr(restricted_path) + ' does'
          ' not live under the repository\'s targets'
          ' directory: ' + repr(self._targets_directory))

      relative_paths.append(restricted_path[len(self._targets_directory):])

    # Get the current role's roleinfo, so that its delegations field can be
    # updated.
    roleinfo = tuf.roledb.get_roleinfo(self._rolename)
   
    # Update the restricted paths of 'child_rolename' to add relative paths. 
    for role in roleinfo['delegations']['roles']:
      if role['name'] == child_rolename:
        restricted_paths = role['paths'] 
    
    for relative_path in relative_paths:
      if relative_path not in restricted_paths:
        restricted_paths.append(relative_path)

      else:
        logger.debug(repr(relative_path) + ' is already a restricted path.')
   
    tuf.roledb.update_roleinfo(self._rolename, roleinfo)



  def add_target(self, filepath, custom=None):
    """
    <Purpose>
      Add a filepath (must be under the repository's targets directory) to the
      Targets object.
      
      This method does not actually create 'filepath' on the file system.
      'filepath' must already exist on the file system.  If 'filepath'
      has already been added, it will be replaced with any new file
      or 'custom' information. 

      >>> 
      >>>
      >>>

    <Arguments>
      filepath:
        The path of the target file.  It must exist in the repository's targets
        directory.

      custom:
        An optional object providing additional information about the file.

    <Exceptions>
      tuf.ssl_commons.exceptions.FormatError, if 'filepath' is improperly
      formatted.

      tuf.ssl_commons.exceptions.Error, if 'filepath' is not found under the
      repository's targets directory.

    <Side Effects>
      Adds 'filepath' to this role's list of targets.  This role's
      'tuf.roledb.py' entry is also updated.

    <Returns>
      None.
    """
    
    # Does 'filepath' have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.  Raise
    # 'tuf.ssl_commons.exceptions.FormatError' if there is a mismatch.
    tuf.ssl_crypto.formats.PATH_SCHEMA.check_match(filepath)
    if custom is None:
      custom = {}
    
    else:
      tuf.ssl_crypto.formats.CUSTOM_SCHEMA.check_match(custom)

    filepath = os.path.abspath(filepath)
   
    # Ensure 'filepath' is found under the repository's targets directory.
    if not filepath.startswith(self._targets_directory): 
      raise tuf.ssl_commons.exceptions.Error(repr(filepath) + ' does not exist'
        ' under the repository\'s targets directory:'
        ' ' + repr(self._targets_directory))

    # Add 'filepath' (i.e., relative to the targets directory) to the role's
    # list of targets.  'filepath' will not be verified as an allowed path
    # according to some delegating role.  Not verifying 'filepath' here allows
    # freedom to add targets and parent restrictions in any order, minimize the
    # number of times these checks are performed, and allow any role to
    # delegate trust of packages to this Targes role.
    if os.path.isfile(filepath):
      
      # Update the role's 'tuf.roledb.py' entry and avoid duplicates.
      targets_directory_length = len(self._targets_directory) 
      roleinfo = tuf.roledb.get_roleinfo(self._rolename)
      relative_path = filepath[targets_directory_length:]
      
      if relative_path not in roleinfo['paths']:
        logger.debug('Adding new target: ' + repr(relative_path))
        roleinfo['paths'].update({relative_path: custom})
      
      else:
        logger.debug('Replacing target: ' + repr(relative_path))
        roleinfo['paths'].update({relative_path: custom})
      
      tuf.roledb.update_roleinfo(self._rolename, roleinfo)
    
    else:
      raise tuf.ssl_commons.exceptions.Error(repr(filepath) + ' is not'
        ' a valid file.')
 

  
  def add_targets(self, list_of_targets):
    """
    <Purpose>
      Add a list of target filepaths (all relative to 'self.targets_directory').
      This method does not actually create files on the file system.  The
      list of targets must already exist on disk.
      
      >>> 
      >>>
      >>>

    <Arguments>
      list_of_targets:
        A list of target filepaths that are added to the paths of this Targets
        object.

    <Exceptions>
      tuf.ssl_commons.exceptions.FormatError, if the arguments are improperly
      formatted.
      
      tuf.ssl_commons.exceptions.Error, if any of the paths listed in
      'list_of_targets' is not found under the repository's targets directory
      or is invalid.

    <Side Effects>
      This Targets' roleinfo is updated with the paths in 'list_of_targets'.

    <Returns>
      None.
    """

    # Does 'list_of_targets' have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.
    # Raise 'tuf.ssl_commons.exceptions.FormatError' if there is a mismatch.
    tuf.ssl_crypto.formats.RELPATHS_SCHEMA.check_match(list_of_targets)

    # Update the tuf.roledb entry.
    targets_directory_length = len(self._targets_directory) 
    relative_list_of_targets = []
   
    # Ensure the paths in 'list_of_targets' are valid and fall under the
    # repository's targets directory.  The paths of 'list_of_targets' will be
    # verified as allowed paths according to this Targets parent role when
    # write() is called.  Not verifying filepaths here allows the freedom to add
    # targets and parent restrictions in any order, and minimize the number of
    # times these checks are performed.
    for target in list_of_targets:
      filepath = os.path.abspath(target)
    
      if not filepath.startswith(self._targets_directory+os.sep):
        raise tuf.ssl_commons.exceptions.Error(repr(filepath) + ' is not'
          ' under the Repository\'s targets'
          ' directory: ' + repr(self._targets_directory))
      
      if os.path.isfile(filepath):
        relative_list_of_targets.append(filepath[targets_directory_length:])
      
      else:
        raise tuf.ssl_commons.exceptions.Error(repr(filepath) + ' is not'
          ' a valid file.')

    # Update this Targets 'tuf.roledb.py' entry.
    roleinfo = tuf.roledb.get_roleinfo(self._rolename)
    for relative_target in relative_list_of_targets:
      if relative_target not in roleinfo['paths']:
        logger.debug('Adding new target: ' + repr(relative_target))
        roleinfo['paths'].update({relative_target: {}})
      
      else:
        logger.debug('Replacing target: ' + repr(relative_target))
    
    tuf.roledb.update_roleinfo(self.rolename, roleinfo)
  
  
  
  def remove_target(self, filepath):
    """
    <Purpose>
      Remove the target 'filepath' from this Targets' 'paths' field.  'filepath'
      is relative to the targets directory.

      >>> 
      >>>
      >>>

    <Arguments>
      filepath:
        The target to remove from this Targets object, relative to the
        repository's targets directory.

    <Exceptions>
      tuf.ssl_commons.exceptions.FormatError, if 'filepath' is improperly
      formatted.

      tuf.ssl_commons.exceptions.Error, if 'filepath' is not under the
      repository's targets directory, or not found.

    <Side Effects>
      Modifies this Targets 'tuf.roledb.py' entry.
    
    <Returns>
      None.
    """

    # Does 'filepath' have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.  Raise
    # 'tuf.ssl_commons.exceptions.FormatError' if there is a mismatch.
    tuf.ssl_crypto.formats.RELPATH_SCHEMA.check_match(filepath)
   
    filepath = os.path.abspath(filepath)
    targets_directory_length = len(self._targets_directory)
    
    # Ensure 'filepath' is under the repository targets directory.
    if not filepath.startswith(self._targets_directory+os.sep):
      raise tuf.ssl_commons.exceptions.Error(repr(filepath) + ' is not under'
        ' the Repository\'s targets directory: ' + repr(self._targets_directory))

    # The relative filepath is listed in 'paths'.
    relative_filepath = filepath[targets_directory_length:]
   
    # Remove 'relative_filepath', if found, and update this Targets roleinfo.  
    fileinfo = tuf.roledb.get_roleinfo(self.rolename)
    if relative_filepath in fileinfo['paths']:
      del fileinfo['paths'][relative_filepath]
      tuf.roledb.update_roleinfo(self.rolename, fileinfo)
    
    else:
      raise tuf.ssl_commons.exceptions.Error('Target file path not found.')



  def clear_targets(self):
    """
    <Purpose>
      Remove all the target filepaths in the "paths" field of this Targets.      

      >>> 
      >>>
      >>>

    <Arguments>
      None

    <Exceptions>
      None.

    <Side Effects>
      Modifies this Targets' 'tuf.roledb.py' entry.
    
    <Returns>
      None.
    """
    
    roleinfo = tuf.roledb.get_roleinfo(self.rolename)
    roleinfo['paths'] = {} 
    
    tuf.roledb.update_roleinfo(self.rolename, roleinfo) 





  def get_delegated_rolenames(self):
    """
    <Purpose>
      Return all delegations of a role.  If ['a/b/', 'a/b/c/', 'a/b/c/d'] have
      been delegated by the delegated role 'django',
      repository.targets('django').get_delegated_rolenames() returns: ['a/b',
      'a/b/c', 'a/b/c/d'].

    <Arguments>
      None.

    <Exceptions>
      None.

    <Side Effects>
      None.

    <Returns>
     A list of rolenames.
    """
  
    return tuf.roledb.get_delegated_rolenames(self.rolename)





  def delegate(self, rolename, public_keys, list_of_targets, threshold=1,
               terminating=False, restricted_paths=None, path_hash_prefixes=None):
    """
    <Purpose>
      Create a new delegation, where 'rolename' is a child delegation of this
      Targets object.  The keys and roles database is updated, including the
      delegations field of this Targets.  The delegation of 'rolename' is added
      and accessible (i.e., repository.targets(rolename)).
      
      Actual metadata files are not create, only when repository.write() or
      repository.write_partial() is called.

      >>> 
      >>>
      >>>

    <Arguments>
      rolename:
        The name of the delegated role, as in 'django' or 'unclaimed'.

      public_keys:
        A list of TUF key objects in 'ANYKEYLIST_SCHEMA' format.  The list
        may contain any of the supported key types: RSAKEY_SCHEMA,
        ED25519KEY_SCHEMA, etc.

      list_of_targets:
        A list of target filepaths that are added to the paths of 'rolename'.
        'list_of_targets' is a list of target filepaths, and can be empty.

      threshold:
        The threshold number of keys of 'rolename'. 
      
      terminating:
        Boolean that indicates whether this role allows the updater client to
        continue searching for targets (target files it is trusted to list but
        has not yet specified) in other delegations.  If 'terminating' is True
        and 'updater.target()' does not find 'example_target.tar.gz' in this
        role, a 'tuf.ssl_commons.exceptions.UnknownTargetError' exception
        should be raised.  If 'terminatin' is False (default), and
        'target/other_role' is also trusted with 'example_target.tar.gz' and
        has listed it, updater.target() should backtrack and return the target
        file specified by 'target/other_role'.

      restricted_paths:
        A list of restricted directory or file paths of 'rolename'.  Any target
        files added to 'rolename' must fall under one of the restricted paths.
      
      path_hash_prefixes:
        A list of hash prefixes in
        'tuf.ssl_crypto.formats.PATH_HASH_PREFIXES_SCHEMA' format, used in
        hashed bin delegations.  Targets may be located and stored in hashed
        bins by calculating the target path's hash prefix.

    <Exceptions>
      tuf.ssl_commons.exceptions.FormatError, if any of the arguments are
      improperly formatted.

      tuf.ssl_commons.exceptions.Error, if the delegated role already exists or
      if any of the arguments is an invalid path (i.e., not under the
      repository's targets directory).

    <Side Effects>
      A new Target object is created for 'rolename' that is accessible to the
      caller (i.e., targets.<rolename>).  The 'tuf.ssl_crypto.keydb.py' and
      'tuf.roledb.py' stores are updated with 'public_keys'.

    <Returns>
      None.
    """

    # Do the arguments have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.
    # Raise 'tuf.ssl_commons.exceptions.FormatError' if there is a mismatch.
    tuf.ssl_crypto.formats.ROLENAME_SCHEMA.check_match(rolename)
    tuf.ssl_crypto.formats.ANYKEYLIST_SCHEMA.check_match(public_keys)
    tuf.ssl_crypto.formats.RELPATHS_SCHEMA.check_match(list_of_targets)
    tuf.ssl_crypto.formats.THRESHOLD_SCHEMA.check_match(threshold)
    tuf.ssl_crypto.formats.BOOLEAN_SCHEMA.check_match(terminating)
    
    if restricted_paths is not None:
      tuf.ssl_crypto.formats.RELPATHS_SCHEMA.check_match(restricted_paths)
    
    if path_hash_prefixes is not None:
      tuf.ssl_crypto.formats.PATH_HASH_PREFIXES_SCHEMA.check_match(path_hash_prefixes)

    # Check if 'rolename' is not already a delegation.
    if tuf.roledb.role_exists(rolename):
      raise tuf.ssl_commons.exceptions.Error(repr(rolename) + ' already'
        ' delegated.')

    # Keep track of the valid keyids (added to the new Targets object) and
    # their keydicts (added to this Targets delegations). 
    keyids = [] 
    keydict = {}

    # Add all the keys in 'public_keys' to tuf.ssl_crypto.keydb.
    for key in public_keys:
      keyid = key['keyid']
      key_metadata_format = tuf.ssl_crypto.keys.format_keyval_to_metadata(key['keytype'],
                                                               key['keyval'])
      # Update 'keyids' and 'keydict'.
      new_keydict = {keyid: key_metadata_format}
      keydict.update(new_keydict)
      keyids.append(keyid)

    # Ensure the paths of 'list_of_targets' all fall under the repository's
    # targets.
    relative_targetpaths = {} 
    targets_directory_length = len(self._targets_directory)
    
    for target in list_of_targets:
      target = os.path.abspath(target)
      if not target.startswith(self._targets_directory + os.sep):
        raise tuf.ssl_commons.exceptions.Error(repr(target) + ' is not under'
          ' the repository\'s targets'
          ' directory: ' + repr(self._targets_directory))

      relative_targetpaths.update({target[targets_directory_length:]: {}})
    
    # Ensure the paths of 'restricted_paths' all fall under the repository's
    # targets.
    relative_restricted_paths = [] 
   
    if restricted_paths is not None: 
      for path in restricted_paths:
        if not path.startswith(self._targets_directory + os.sep):
          raise tuf.ssl_commons.exceptions.Error(repr(path) + ' is not under'
            ' the repository\'s targets'
            ' directory: ' +repr(self._targets_directory))
        
        # Append a trailing path separator with os.path.join(path, '').
        relative_restricted_paths.append(path[targets_directory_length:])
   
    # Create a new Targets object for the 'rolename' delegation.  An initial
    # expiration is set (3 months from the current time).
    expiration = \
      tuf.formats.unix_timestamp_to_datetime(int(time.time() + TARGETS_EXPIRATION))
    expiration = expiration.isoformat() + 'Z'
    
    roleinfo = {'name': rolename, 'keyids': keyids, 'signing_keyids': [],
                'threshold': threshold, 'version': 0, 'compressions': [''],
                'expires': expiration, 'signatures': [], 'partial_loaded': False,
                'paths': relative_targetpaths, 'delegations': {'keys': {},
                'roles': []}}

    # The new targets object is added as an attribute to this Targets object. 
    new_targets_object = Targets(self._targets_directory, rolename,
                                 roleinfo, parent_targets_object=self._parent_targets_object)
    
    # Update the 'delegations' field of the current role.
    current_roleinfo = tuf.roledb.get_roleinfo(self.rolename) 
    current_roleinfo['delegations']['keys'].update(keydict)

    # Update the roleinfo of this role.  A ROLE_SCHEMA object requires only
    # 'keyids', 'threshold', and 'paths'.
    roleinfo = {'name': rolename,
                'keyids': roleinfo['keyids'],
                'threshold': roleinfo['threshold'],
                'terminating': terminating,
                'paths': list(roleinfo['paths'].keys())}
    
    if restricted_paths is not None:
      roleinfo['paths'] = relative_restricted_paths
    
    if path_hash_prefixes is not None:
      roleinfo['path_hash_prefixes'] = path_hash_prefixes
      # A role in a delegations must list either 'path_hash_prefixes'
      # or 'paths'.  
      del roleinfo['paths']
    
    current_roleinfo['delegations']['roles'].append(roleinfo)
    tuf.roledb.update_roleinfo(self.rolename, current_roleinfo)  
    
    # Update the public keys of 'new_targets_object'.
    for key in public_keys:
      new_targets_object.add_verification_key(key)

    # Add the new delegation to the top-level 'targets' role object (i.e.,
    # 'repository.targets()').  For example, 'django', which was delegated by
    # repository.target('claimed'), is added to 'repository.targets('django')).
    
    # Add 'new_targets_object' to the 'targets' role object (this object).
    if self.rolename == 'targets':
      self.add_delegated_role(rolename, new_targets_object)
   
    else:
      self._parent_targets_object.add_delegated_role(rolename, new_targets_object)
      self.add_delegated_role(rolename, new_targets_object)
      
  



  def revoke(self, rolename):
    """
    <Purpose>
      Revoke this Targets' 'rolename' delegation.  Its 'rolename' attribute is
      deleted, including the entries in its 'delegations' field and in
      'tuf.roledb'.
      
      Actual metadata files are not updated, only when repository.write() or
      repository.write() is called.
      
      >>>
      >>>
      >>>

    <Arguments>
      rolename:
        The rolename (e.g., 'Django' in 'django') of the child delegation the
        parent role (this role) wants to revoke.

    <Exceptions>
      tuf.ssl_commons.exceptions.FormatError, if 'rolename' is improperly
      formatted.

    <Side Effects>
      The delegations dictionary of 'rolename' is modified, and its 'tuf.roledb'
      entry is updated.  This Targets' 'rolename' delegation attribute is also
      deleted.

    <Returns>
      None.
    """

    # Does 'rolename' have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.
    # Raise 'tuf.ssl_commons.exceptions.FormatError' if there is a mismatch.
    tuf.ssl_crypto.formats.ROLENAME_SCHEMA.check_match(rolename) 

    # Remove 'rolename' from this Target's delegations dict.  
    roleinfo = tuf.roledb.get_roleinfo(self.rolename)
    
    for role in roleinfo['delegations']['roles']:
      if role['name'] == rolename:
        roleinfo['delegations']['roles'].remove(role)

    tuf.roledb.update_roleinfo(self.rolename, roleinfo) 
    
    # Remove 'rolename' from 'tuf.roledb.py'.
    tuf.roledb.remove_role(rolename)
   
    # Remove the rolename delegation from the current role.  For example, the
    # 'django' role is removed from repository.targets('django').
    del self._delegated_roles[rolename]
    self._parent_targets_object.remove_delegated_role(rolename)





  def delegate_hashed_bins(self, list_of_targets, keys_of_hashed_bins,
                           number_of_bins=1024):
    """
    <Purpose>
      Distribute a large number of target files over multiple delegated roles
      (hashed bins).  The metadata files of delegated roles will be nearly
      equal in size (i.e., 'list_of_targets' is uniformly distributed by
      calculating the target filepath's hash and determing which bin it should
      reside in.  The updater client will use "lazy bin walk" to find a target
      file's hashed bin destination.  The parent role lists a range of path
      hash prefixes each hashed bin contains.  This method is intended for
      repositories with a large number of target files, a way of easily
      distributing and managing the metadata that lists the targets, and
      minimizing the number of metadata files (and their size) downloaded by
      the client.  See tuf-spec.txt and the following link for more
      information:
      http://www.python.org/dev/peps/pep-0458/#metadata-scalability
      
      >>>
      >>>
      >>>

    <Arguments>
      list_of_targets:
        The target filepaths of the targets that should be stored in hashed
        bins created (i.e., delegated roles).  A repository object's
        get_filepaths_in_directory() can generate a list of valid target
        paths.

      keys_of_hashed_bins:
        The initial public keys of the delegated roles.  Public keys may be
        later added or removed by calling the usual methods of the delegated
        Targets object.  For example:
        repository.targets('000-003').add_verification_key()
      
      number_of_bins:
        The number of delegated roles, or hashed bins, that should be generated
        and contain the target file attributes listed in 'list_of_targets'.
        'number_of_bins' must be a power of 2.  Each bin may contain a
        range of path hash prefixes (e.g., target filepath digests that range
        from [000]... - [003]..., where the series of digits in brackets is
        considered the hash prefix).

    <Exceptions>
      tuf.ssl_commons.exceptions.FormatError, if the arguments are improperly
      formatted.
      
      tuf.ssl_commons.exceptions.Error, if 'number_of_bins' is not a power of
      2, or one of the targets in 'list_of_targets' is not located under the
      repository's targets directory.

    <Side Effects>
      Delegates multiple target roles from the current parent role.

    <Returns>
      None.
    """      
    
    # Do the arguments have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.
    # Raise 'tuf.ssl_commons.exceptions.FormatError' if there is a mismatch.
    tuf.ssl_crypto.formats.PATHS_SCHEMA.check_match(list_of_targets)
    tuf.ssl_crypto.formats.ANYKEYLIST_SCHEMA.check_match(keys_of_hashed_bins)
    tuf.ssl_crypto.formats.NUMBINS_SCHEMA.check_match(number_of_bins)
   
    # Convert 'number_of_bins' to hexadecimal and determine the number of
    # hexadecimal digits needed by each hash prefix.  Calculate the total
    # number of hash prefixes (e.g., 000 - FFF total values) to be spread over
    # 'number_of_bins' and strip the first two characters ('0x') from Python's
    # representation of hexadecimal values (so that they are not used in the
    # calculation of the prefix length.) Example: number_of_bins = 32,
    # total_hash_prefixes = 256, and each hashed bin is responsible for 8 hash
    # prefixes.  Hashed bin roles created = 00-07.json, 08-0f.json, ...,
    # f8-ff.json.
    prefix_length =  len(hex(number_of_bins - 1)[2:])
    total_hash_prefixes = 16 ** prefix_length

    # For simplicity, ensure that 'total_hash_prefixes' (16 ^ n) can be evenly
    # distributed over 'number_of_bins' (must be 2 ^ n).  Each bin will contain
    # (total_hash_prefixes / number_of_bins) hash prefixes.
    if total_hash_prefixes % number_of_bins != 0:
      raise tuf.ssl_commons.exceptions.Error('The "number_of_bins" argument'
        ' must be a power of 2.')

    logger.info('Creating hashed bin delegations.')
    logger.info(repr(len(list_of_targets)) + ' total targets.')
    logger.info(repr(number_of_bins) + ' hashed bins.')
    logger.info(repr(total_hash_prefixes) + ' total hash prefixes.')

    # Store the target paths that fall into each bin.  The digest of the target
    # path, reduced to the first 'prefix_length' hex digits, is calculated to
    # determine which 'bin_index' it should go.  we use xrange() here because
    # there can be a large number of prefixes to process.
    target_paths_in_bin = {}
    for bin_index in six.moves.xrange(total_hash_prefixes):
      target_paths_in_bin[bin_index] = []
    
    # Assign every path to its bin.  Ensure every target is located under the
    # repository's targets directory.
    for target_path in list_of_targets:
      target_path = os.path.abspath(target_path)
      if not target_path.startswith(self._targets_directory + os.sep):
        raise tuf.ssl_commons.exceptions.Error('A path in "list of'
          ' targets" does not live under the repository\'s targets'
          ' directory: ' + repr(target_path))

      else:
        logger.debug(repr(target_path) + ' lives under the repository\'s'
          ' targets directory.')
      
      # Determine the hash prefix of 'target_path' by computing the digest of
      # its path relative to the targets directory.  Example:
      # '{repository_root}/targets/file1.txt' -> 'file1.txt'.
      relative_path = target_path[len(self._targets_directory):]
      digest_object = tuf.ssl_crypto.hash.digest(algorithm=HASH_FUNCTION)
      digest_object.update(relative_path.encode('utf-8'))
      relative_path_hash = digest_object.hexdigest()
      relative_path_hash_prefix = relative_path_hash[:prefix_length]

      # 'target_paths_in_bin' store bin indices in base-10, so convert the
      # 'relative_path_hash_prefix' base-16 (hex) number to a base-10 (dec)
      # number.
      bin_index = int(relative_path_hash_prefix, 16)

      # Add the 'target_path' (absolute) to the bin.  These target paths are
      # later added to the targets of the 'bin_index' role.
      target_paths_in_bin[bin_index].append(target_path)

    # Calculate the path hash prefixes of each 'bin_offset' stored in the parent
    # role.  For example: 'targets/unclaimed/000-003' may list the path hash
    # prefixes "000", "001", "002", "003" in the delegations dict of
    # 'targets/unclaimed'. 
    bin_offset = total_hash_prefixes // number_of_bins
    
    logger.info('Each bin ranges over ' + repr(bin_offset) + ' hash prefixes.')

    # The parent roles will list bin roles starting from "0" to
    # 'total_hash_prefixes' in 'bin_offset' increments.  The skipped bin roles
    # are listed in 'path_hash_prefixes' of 'outer_bin_index'.
    for outer_bin_index in six.moves.xrange(0, total_hash_prefixes, bin_offset):
      # The bin index is hex padded from the left with zeroes for up to the
      # 'prefix_length' (e.g., '000-003').  Ensure the correct hash bin name is
      # generated if a prefix range is unneeded.
      start_bin = hex(outer_bin_index)[2:].zfill(prefix_length)
      end_bin = hex(outer_bin_index+bin_offset-1)[2:].zfill(prefix_length)
      if start_bin == end_bin:
        bin_rolename = start_bin
      
      else:
        bin_rolename = start_bin + '-' + end_bin 
      
      # 'bin_rolename' may contain a range of target paths, from 'start_bin' to
      # 'end_bin'.  Determine the total target paths that should be included. 
      path_hash_prefixes = []
      bin_rolename_targets = []

      for inner_bin_index in six.moves.xrange(outer_bin_index, outer_bin_index+bin_offset):
        # 'inner_bin_rolename' needed in padded hex.  For example, "00b".
        inner_bin_rolename = hex(inner_bin_index)[2:].zfill(prefix_length)
        path_hash_prefixes.append(inner_bin_rolename)
        bin_rolename_targets.extend(target_paths_in_bin[inner_bin_index])
        
      # Delegate from the "unclaimed" targets role to each 'bin_rolename'
      # (i.e., outer_bin_index).
      self.delegate(bin_rolename, keys_of_hashed_bins,
                    list_of_targets=bin_rolename_targets,
                    path_hash_prefixes=path_hash_prefixes)   
      logger.debug('Delegated from ' + repr(self.rolename) + ' to ' + repr(bin_rolename))



  def add_target_to_bin(self, target_filepath):
    """
    <Purpose>
      Add the fileinfo of 'target_filepath' to the expected hashed bin, if
      the bin is available.  The hashed bin should have been created by 
      {targets_role}.delegate_hashed_bins().  Assuming the target filepath
      falls under the repository's targets directory, determine the filepath's
      hash prefix, locate the expected bin (if any), and then add the fileinfo
      to the expected bin.  Example:  'targets/foo.tar.gz' may be added to
      the 'targets/unclaimed/58-5f.json' role's list of targets by calling this
      method.

    <Arguments>
      target_filepath:
        The filepath of the target to be added to a hashed bin.  The filepath
        must fall under repository's targets directory.

    <Exceptions>
      tuf.ssl_commons.exceptions.FormatError, if 'target_filepath' is
      improperly formatted.
      
      tuf.ssl_commons.exceptions.Error, if 'target_filepath' cannot be added to
      a hashed bin (e.g., an invalid target filepath, or the expected hashed
      bin does not exist.)

    <Side Effects>
      The fileinfo of 'target_filepath' is added to a hashed bin of this Targets
      object.

    <Returns>
      None. 
    """
    
    # Do the arguments have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.
    # Raise 'tuf.ssl_commons.exceptions.FormatError' if there is a mismatch.
    tuf.ssl_crypto.formats.PATH_SCHEMA.check_match(target_filepath)
    
    return self._locate_and_update_target_in_bin(target_filepath, 'add_target')



  def remove_target_from_bin(self, target_filepath):
    """
    <Purpose>
      Remove the fileinfo of 'target_filepath' from the expected hashed bin, if
      the bin is available.  The hashed bin should have been created by 
      {targets_role}.delegate_hashed_bins().  Assuming the target filepath
      falls under the repository's targets directory, determine the filepath's
      hash prefix, locate the expected bin (if any), and then remove the
      fileinfo from the expected bin.  Example:  'targets/foo.tar.gz' may be
      removed from the '58-5f.json' role's list of targets by
      calling this method.

    <Arguments>
      target_filepath:
        The filepath of the target to be added to a hashed bin.  The filepath
        must fall under repository's targets directory.

    <Exceptions>
      tuf.ssl_commons.exceptions.FormatError, if 'target_filepath' is
      improperly formatted.
      
      tuf.ssl_commons.exceptions.Error, if 'target_filepath' cannot be removed
      from a hashed bin (e.g., an invalid target filepath, or the expected
      hashed bin does not exist.)

    <Side Effects>
      The fileinfo of 'target_filepath' is removed from a hashed bin of this
      Targets object.

    <Returns>
      None. 
    """
    
    # Do the arguments have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.
    # Raise 'tuf.ssl_commons.exceptions.FormatError' if there is a mismatch.
    tuf.ssl_crypto.formats.PATH_SCHEMA.check_match(target_filepath)
   
    return self._locate_and_update_target_in_bin(target_filepath, 'remove_target')



  def _locate_and_update_target_in_bin(self, target_filepath, method_name):
    """
    <Purpose>
      Assuming the target filepath falls under the repository's targets
      directory, determine the filepath's hash prefix, locate the expected bin
      (if any), and then call the 'method_name' method of the expected hashed
      bin role.

    <Arguments>
      target_filepath:
        The filepath of the target that may be specified in one of the hashed
        bins.  'target_filepath' must fall under repository's targets directory.

      method_name:
        A supported method, in string format, of the Targets() class.  For
        example, 'add_target' and 'remove_target'.  If 'target_filepath' were 
        to be manually added or removed from a bin: 
        
        repository.targets('58-f7').add_target(target_filepath)
        repository.targets('000-007').remove_target(target_filepath)

    <Exceptions>
      tuf.ssl_commons.exceptions.Error, if 'target_filepath' cannot be updated
      (e.g., an invalid target filepath, or the expected hashed bin does not
      exist.)

    <Side Effects>
      The fileinfo of 'target_filepath' is added to a hashed bin of this Targets
      object.

    <Returns>
      None. 
    """

    # Determine the prefix length of any one of the hashed bins.  The prefix
    # length is not stored in the roledb, so it must be determined here by
    # inspecting one of path hash prefixes listed.
    roleinfo = tuf.roledb.get_roleinfo(self.rolename)
    prefix_length = 0
    delegation = None
   
    # Set 'delegation' if this Targets role has performed any delegations.
    if len(roleinfo['delegations']['roles']):
      delegation = roleinfo['delegations']['roles'][0]
    
    else:
      raise tuf.ssl_commons.exceptions.Error(self.rolename + ' has not'
        ' delegated to any roles.')

    # Set 'prefix_length' if this Targets object has delegated to hashed bins,
    # otherwise raise an exception.
    if 'path_hash_prefixes' in delegation and len(delegation['path_hash_prefixes']):
      prefix_length = len(delegation['path_hash_prefixes'][0])
      
    else:
      raise tuf.ssl_commons.exceptions.Error(self.rolename + ' has not'
        ' delegated to hashed bins.')
   
    # Ensure the filepath falls under the repository's targets directory.
    filepath = os.path.abspath(target_filepath)
    if not filepath.startswith(self._targets_directory + os.sep):
      raise tuf.ssl_commons.exceptions.Error(repr(filepath) + ' is not under'
        ' the Repository\'s targets directory: ' + repr(self._targets_directory))
    
    # Determine the hash prefix of 'target_path' by computing the digest of
    # its path relative to the targets directory.  Example:
    # '{repository_root}/targets/file1.txt' -> '/file1.txt'.
    relative_path = filepath[len(self._targets_directory):]
    digest_object = tuf.ssl_crypto.hash.digest(algorithm=HASH_FUNCTION)
    digest_object.update(relative_path.encode('utf-8'))
    path_hash = digest_object.hexdigest()
    path_hash_prefix = path_hash[:prefix_length]

    # Search for 'path_hash_prefix', and if found, extract the hashed bin's
    # rolename.  The hashed bin name is needed so that 'target_filepath' can be
    # added to the Targets object of the hashed bin.
    hashed_bin_name = None
    for delegation in roleinfo['delegations']['roles']:
      if path_hash_prefix in delegation['path_hash_prefixes']:
        hashed_bin_name = delegation['name']
        break
      
      else:
        logger.debug('"path_hash_prefix" not found.')

    # 'self._delegated_roles' is keyed by relative rolenames, so update
    # 'hashed_bin_name'.
    if hashed_bin_name is not None:
      
      # 'method_name' should be one of the supported methods of the Targets()
      # class.
      getattr(self._delegated_roles[hashed_bin_name], method_name)(target_filepath)

    else:
      raise tuf.ssl_commons.exceptions.Error(target_filepath + ' not found'
        ' in any of the bins.')



  @property
  def delegations(self):
    """
    <Purpose>
      A getter method that returns the delegations made by this Targets role.

      >>>
      >>>
      >>>

    <Arguments>
      None.

    <Exceptions>
      tuf.ssl_commons.exceptions.UnknownRoleError, if this Targets' rolename
      does not exist in 'tuf.roledb'. 

    <Side Effects>
      None.

    <Returns>
      A list containing the Targets objects of this Targets' delegations.
    """

    return list(self._delegated_roles.values())





def create_new_repository(repository_directory):
  """
  <Purpose>
    Create a new repository, instantiate barebones metadata for the top-level
    roles, and return a Repository object.  On disk, create_new_repository()
    only creates the directories needed to hold the metadata and targets files.
    The repository object returned may be modified to update the newly created
    repository.  The methods of the returned object may be called to create
    actual repository files (e.g., repository.write()).

  <Arguments>
    repository_directory:
      The directory that will eventually hold the metadata and target files of
      the TUF repository.

  <Exceptions>
    tuf.ssl_commons.exceptions.FormatError, if the arguments are improperly
    formatted.

  <Side Effects>
    The 'repository_directory' is created if it does not exist, including its
    metadata and targets sub-directories.

  <Returns>
    A 'tuf.repository_tool.Repository' object.
  """

  # Does 'repository_directory' have the correct format?
  # Ensure the arguments have the appropriate number of objects and object
  # types, and that all dict keys are properly named.
  # Raise 'tuf.ssl_commons.exceptions.FormatError' if there is a mismatch.
  tuf.ssl_crypto.formats.PATH_SCHEMA.check_match(repository_directory)

  # Set the repository, metadata, and targets directories.  These directories
  # are created if they do not exist.
  repository_directory = os.path.abspath(repository_directory)
  metadata_directory = None
  targets_directory = None
  
  # Try to create 'repository_directory' if it does not exist.
  try:
    logger.info('Creating ' + repr(repository_directory))
    os.makedirs(repository_directory)
  
  # 'OSError' raised if the leaf directory already exists or cannot be created.
  # Check for case where 'repository_directory' has already been created. 
  except OSError as e:
    if e.errno == errno.EEXIST:
      pass 
    
    else:
      raise
  
  # Set the metadata and targets directories.  The metadata directory is a
  # staged one so that the "live" repository is not affected.  The
  # staged metadata changes may be moved over to "live" after all updated
  # have been completed.
  metadata_directory = \
    os.path.join(repository_directory, METADATA_STAGED_DIRECTORY_NAME)
  targets_directory = \
    os.path.join(repository_directory, TARGETS_DIRECTORY_NAME) 
  
  # Try to create the metadata directory that will hold all of the metadata
  # files, such as 'root.json' and 'snapshot.json'.
  try:
    logger.info('Creating ' + repr(metadata_directory))
    os.mkdir(metadata_directory)
  
  # 'OSError' raised if the leaf directory already exists or cannot be created.
  except OSError as e:
    if e.errno == errno.EEXIST:
      pass
    
    else:
      raise
  
  # Try to create the targets directory that will hold all of the target files.
  try:
    logger.info('Creating ' + repr(targets_directory))
    os.mkdir(targets_directory)
  
  except OSError as e:
    if e.errno == errno.EEXIST:
      pass
    
    else:
      raise
 
  # Create the bare bones repository object, where only the top-level roles
  # have been set and contain default values (e.g., Root roles has a threshold
  # of 1, expires 1 year into the future, etc.)
  repository = Repository(repository_directory, metadata_directory,
                          targets_directory)
  
  return repository





def load_repository(repository_directory):
  """
  <Purpose>
    Return a repository object containing the contents of metadata files loaded
    from the repository.

  <Arguments>
    repository_directory:

  <Exceptions>
    tuf.ssl_commons.exceptions.FormatError, if 'repository_directory' or any of
    the metadata files are improperly formatted.

    tuf.ssl_commons.exceptions.RepositoryError, if the Root role cannot be
    found.  At a minimum, a repository must contain 'root.json'
  
  <Side Effects>
   All the metadata files found in the repository are loaded and their contents
   stored in a repository_tool.Repository object.

  <Returns>
    repository_tool.Repository object.
  """
 
  # Does 'repository_directory' have the correct format?
  # Raise 'tuf.ssl_commons.exceptions.FormatError' if there is a mismatch.
  tuf.ssl_crypto.formats.PATH_SCHEMA.check_match(repository_directory)

  # Load top-level metadata.
  #tuf.roledb.clear_roledb(clear_all=True)
  #tuf.ssl_crypto.keydb.clear_keydb(clear_all=True)

  repository_directory = os.path.abspath(repository_directory)
  metadata_directory = os.path.join(repository_directory,
                                    METADATA_STAGED_DIRECTORY_NAME)
  targets_directory = os.path.join(repository_directory,
                                    TARGETS_DIRECTORY_NAME)

  # The Repository() object loaded (i.e., containing all the metadata roles
  # found) and returned.
  repository = Repository(repository_directory, metadata_directory,
                          targets_directory)
  
  filenames = repo_lib.get_metadata_filenames(metadata_directory)

  # The Root file is always available without a version number (a consistent
  # snapshot) attached to the filename.  Store the 'consistent_snapshot' value
  # and read the loaded Root file so that other metadata files may be located.
  consistent_snapshot = False

  # Load the metadata of the top-level roles (i.e., Root, Timestamp, Targets,
  # and Snapshot).
  repository, consistent_snapshot = repo_lib._load_top_level_metadata(repository,
                                                                      filenames)
 
  # Load the delegated targets metadata and generate their fileinfo.  The
  # extracted fileinfo is stored in the 'meta' field of the snapshot metadata
  # object.
  targets_objects = {}
  loaded_metadata = []
  targets_objects['targets'] = repository.targets

  for metadata_role in os.listdir(metadata_directory):

    metadata_path = os.path.join(metadata_directory, metadata_role)
    metadata_name = \
      metadata_path[len(metadata_directory):].lstrip(os.path.sep)
    
    # Strip the version number if 'consistent_snapshot' is True,
    # or if 'metadata_role' is Root.
    # Example:  '10.django.json' --> 'django.json'
    consistent_snapshot = \
      metadata_role.endswith('root.json') or consistent_snapshot == True
    metadata_name, version_number_junk = \
      repo_lib._strip_version_number(metadata_name, consistent_snapshot)

    if metadata_name.endswith(METADATA_EXTENSION): 
      extension_length = len(METADATA_EXTENSION)
      metadata_name = metadata_name[:-extension_length]
    
    else:
      logger.debug('Skipping file with unsupported metadata'
        ' extension: ' + repr(metadata_path))
      continue
   
    # Skip top-level roles, only interested in delegated roles now that the
    # top-level roles have already been loaded.
    if metadata_name in ['root', 'snapshot', 'targets', 'timestamp']:
      continue
   
    # Keep a store of metadata previously loaded metadata to prevent re-loading
    # duplicate versions.  Duplicate versions may occur with
    # 'consistent_snapshot', where the same metadata may be available in
    # multiples files (the different hash is included in each filename.
    if metadata_name in loaded_metadata:
      continue

    signable = None
    
    try:
      signable = tuf.ssl_crypto.util.load_json_file(metadata_path)
    
    except (tuf.ssl_commons.exceptions.Error, ValueError, IOError):
      logger.debug('Tried to load metadata with invalid JSON'
        ' content: ' + repr(metadata_path))
      continue
    
    metadata_object = signable['signed']
 
    # Extract the metadata attributes of 'metadata_name' and update its
    # corresponding roleinfo.
    roleinfo = {'name': metadata_name,
                'signing_keyids': [],
                'signatures': [],
                'partial_loaded': False,
                'compressions': [],
                'paths': {},
               }

    roleinfo['signatures'].extend(signable['signatures'])
    roleinfo['version'] = metadata_object['version']
    roleinfo['expires'] = metadata_object['expires']
    
    for filepath, fileinfo in six.iteritems(metadata_object['targets']):
      roleinfo['paths'].update({filepath: fileinfo.get('custom', {})})
    roleinfo['delegations'] = metadata_object['delegations']

    if os.path.exists(metadata_path + '.gz'):
      roleinfo['compressions'].append('gz')

    else:
      logger.debug('A compressed version does not exist.')
  
    tuf.roledb.add_role(metadata_name, roleinfo) 
    loaded_metadata.append(metadata_name)

    # Generate the Targets objects of the delegated roles of 'metadata_name'
    # and add it to the top-level 'targets' object.
    new_targets_object = Targets(targets_directory, metadata_name, roleinfo)
    targets_object = targets_objects['targets']
    targets_objects[metadata_name] = new_targets_object
    
    targets_object._delegated_roles[(os.path.basename(metadata_name))] = \
                          new_targets_object

    # Extract the keys specified in the delegations field of the Targets
    # role.  Add 'key_object' to the list of recognized keys.  Keys may be
    # shared, so do not raise an exception if 'key_object' has already been
    # added.  In contrast to the methods that may add duplicate keys, do not
    # log a warning here as there may be many such duplicate key warnings.
    # The repository maintainer should have also been made aware of the
    # duplicate key when it was added.
    for key_metadata in six.itervalues(metadata_object['delegations']['keys']):
      key_object, junk = tuf.ssl_crypto.keys.format_metadata_to_key(key_metadata)
      try:
        tuf.ssl_crypto.keydb.add_key(key_object)
      
      except tuf.ssl_commons.exceptions.KeyAlreadyExistsError:
        pass
  
  return repository





if __name__ == '__main__':
  # The interactive sessions of the documentation strings can
  # be tested by running repository_tool.py as a standalone module:
  # $ python repository_tool.py.
  import doctest
  doctest.testmod()
