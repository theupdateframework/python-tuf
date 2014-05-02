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
import tuf._vendor.iso8601 as iso8601

# See 'log.py' to learn how logging is handled in TUF.
logger = logging.getLogger('tuf.repository_tool')

# Add a console handler so that users are aware of potentially unintended
# states, such as multiple roles that share keys.
tuf.log.add_console_handler()
tuf.log.set_console_log_level(logging.WARNING)

# Recommended RSA key sizes:
# http://www.emc.com/emc-plus/rsa-labs/historical/twirl-and-rsa-key-size.htm#table1 
# According to the document above, revised May 6, 2003, RSA keys of
# size 3072 provide security through 2031 and beyond.  2048-bit keys
# are the recommended minimum and are good from the present through 2030.
DEFAULT_RSA_KEY_BITS = 3072

# The algorithm used by the repository to generate the digests of the
# target filepaths, which are included in metadata files and may be prepended
# to the filenames of consistent snapshots.
HASH_FUNCTION = 'sha256'

# The extension of TUF metadata.
METADATA_EXTENSION = '.json'

# The metadata filenames of the top-level roles.
ROOT_FILENAME = 'root' + METADATA_EXTENSION
TARGETS_FILENAME = 'targets' + METADATA_EXTENSION
SNAPSHOT_FILENAME = 'snapshot' + METADATA_EXTENSION
TIMESTAMP_FILENAME = 'timestamp' + METADATA_EXTENSION

# The targets and metadata directory names.  Metadata files are written
# to the staged metadata directory instead of the "live" one.
METADATA_STAGED_DIRECTORY_NAME = 'metadata.staged'
METADATA_DIRECTORY_NAME = 'metadata'
TARGETS_DIRECTORY_NAME = 'targets' 

# The full list of supported TUF metadata extensions.
METADATA_EXTENSIONS = ['.json', '.json.gz']

# The recognized compression extensions. 
SUPPORTED_COMPRESSION_EXTENSIONS = ['.gz']

# Supported key types.
SUPPORTED_KEY_TYPES = ['rsa', 'ed25519']

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

# Log warning when metadata expires in n days, or less.
# root = 1 month, snapshot = 1 day, targets = 10 days, timestamp = 1 day.
ROOT_EXPIRES_WARN_SECONDS = 2630000
SNAPSHOT_EXPIRES_WARN_SECONDS = 86400
TARGETS_EXPIRES_WARN_SECONDS = 864000
TIMESTAMP_EXPIRES_WARN_SECONDS = 86400


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
    repository.timestamp.expiration = datetime.datetime(2015, 08, 08, 12, 00)
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
    tuf.FormatError, if the arguments are improperly formatted.

  <Side Effects>
    Creates top-level role objects and assigns them as attributes.

  <Returns>
    A Repository object that contains default Metadata objects for the top-level
    roles.
  """
 
  def __init__(self, repository_directory, metadata_directory, targets_directory):
  
    # Do the arguments have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.
    # Raise 'tuf.FormatError' if any are improperly formatted.
    tuf.formats.PATH_SCHEMA.check_match(repository_directory)
    tuf.formats.PATH_SCHEMA.check_match(metadata_directory)
    tuf.formats.PATH_SCHEMA.check_match(targets_directory)
    
    self._repository_directory = repository_directory
    self._metadata_directory = metadata_directory
    self._targets_directory = targets_directory
   
    # Set the top-level role objects.
    self.root = Root() 
    self.snapshot = Snapshot()
    self.timestamp = Timestamp()
    self.targets = Targets(self._targets_directory, 'targets')



  def write(self, write_partial=False, consistent_snapshot=False):
    """
    <Purpose>
      Write all the JSON Metadata objects to their corresponding files.
      write() raises an exception if any of the role metadata to be written to
      disk is invalid, such as an insufficient threshold of signatures, missing
      private keys, etc.
    
    <Arguments>
      mrite_partial:
        A boolean indicating whether partial metadata should be written to
        disk.  Partial metadata may be written to allow multiple maintainters
        to independently sign and update role metadata.  write() raises an
        exception if a metadata role cannot be written due to not having enough
        signatures.

      consistent_snapshot:
        A boolean indicating whether written metadata and target files should
        include a digest in the filename (i.e., <digest>.root.json,
        <digest>.targets.json.gz, <digest>.README.json, where <digest> is the
        file's SHA256 digest.  Example:
        1f4e35a60c8f96d439e27e858ce2869c770c1cdd54e1ef76657ceaaf01da18a3.root.json'
        
    <Exceptions>
      tuf.UnsignedMetadataError, if any of the top-level and delegated roles do
      not have the minimum threshold of signatures.

    <Side Effects>
      Creates metadata files in the repository's metadata directory.

    <Returns>
      None.
    """
    
    # Does 'write_partial' have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.
    # Raise 'tuf.FormatError' if any are improperly formatted.
    tuf.formats.BOOLEAN_SCHEMA.check_match(write_partial)
    tuf.formats.BOOLEAN_SCHEMA.check_match(consistent_snapshot) 
    
    # At this point the tuf.keydb and tuf.roledb stores must be fully
    # populated, otherwise write() throwns a 'tuf.UnsignedMetadataError'
    # exception if any of the top-level roles are missing signatures, keys, etc.

    # Write the metadata files of all the delegated roles.  Ensure target paths
    # are allowed, metadata is valid and properly signed, and required files and
    # directories are created. 
    delegated_rolenames = tuf.roledb.get_delegated_rolenames('targets')
    for delegated_rolename in delegated_rolenames:
      delegated_filename = os.path.join(self._metadata_directory,
                                        delegated_rolename + METADATA_EXTENSION)
      roleinfo = tuf.roledb.get_roleinfo(delegated_rolename)
      delegated_targets = roleinfo['paths']
      parent_rolename = tuf.roledb.get_parent_rolename(delegated_rolename)
      parent_roleinfo = tuf.roledb.get_roleinfo(parent_rolename) 
      parent_delegations = parent_roleinfo['delegations']
      
      # Raise exception if any of the targets of 'delegated_rolename' are not
      # allowed.
      tuf.util.ensure_all_targets_allowed(delegated_rolename, delegated_targets,
                                          parent_delegations)

      # Ensure the parent directories of 'metadata_filepath' exist, otherwise an
      # IO exception is raised if 'metadata_filepath' is written to a
      # sub-directory.
      tuf.util.ensure_parent_dir(delegated_filename)
   
      try:
        _generate_and_write_metadata(delegated_rolename, delegated_filename,
                                     write_partial, self._targets_directory,
                                     self._metadata_directory,
                                     consistent_snapshot)
      
      # Include only the exception message.
      except tuf.UnsignedMetadataError, e:
        raise tuf.UnsignedMetadataError(e[0])
      
    # Generate the 'root.json' metadata file.
    # _generate_and_write_metadata() raises a 'tuf.Error' exception if the
    # metadata cannot be written.
    root_filename = 'root' + METADATA_EXTENSION 
    root_filename = os.path.join(self._metadata_directory, root_filename)
    try: 
      signable_junk, root_filename = \
        _generate_and_write_metadata('root', root_filename, write_partial,
                                     self._targets_directory,
                                     self._metadata_directory,
                                     consistent_snapshot)
    
    # Include only the exception message.
    except tuf.UnsignedMetadataError, e:
      raise tuf.UnsignedMetadataError(e[0])
    
    # Generate the 'targets.json' metadata file.
    targets_filename = 'targets' + METADATA_EXTENSION 
    targets_filename = os.path.join(self._metadata_directory, targets_filename)
    try: 
      signable_junk, targets_filename = \
        _generate_and_write_metadata('targets', targets_filename, write_partial,
                                     self._targets_directory,
                                     self._metadata_directory,
                                     consistent_snapshot)
    
    # Include only the exception message.
    except tuf.UnsignedMetadataError, e:
      raise tuf.UnsignedMetadataError(e[0])
    
    # Generate the 'snapshot.json' metadata file.
    snapshot_filename = os.path.join(self._metadata_directory, 'snapshot')
    snapshot_filename = 'snapshot' + METADATA_EXTENSION 
    snapshot_filename = os.path.join(self._metadata_directory, snapshot_filename)
    filenames = {'root': root_filename, 'targets': targets_filename}
    snapshot_signable = None
    try: 
      snapshot_signable, snapshot_filename = \
        _generate_and_write_metadata('snapshot', snapshot_filename, write_partial,
                                     self._targets_directory,
                                     self._metadata_directory,
                                     consistent_snapshot, filenames)
    
    # Include only the exception message.
    except tuf.UnsignedMetadataError, e:
      raise tuf.UnsignedMetadataError(e[0])
    
    # Generate the 'timestamp.json' metadata file.
    timestamp_filename = 'timestamp' + METADATA_EXTENSION 
    timestamp_filename = os.path.join(self._metadata_directory, timestamp_filename)
    filenames = {'snapshot': snapshot_filename}
    try: 
      _generate_and_write_metadata('timestamp', timestamp_filename, write_partial,
                                   self._targets_directory,
                                   self._metadata_directory, consistent_snapshot,
                                   filenames)
    
    # Include only the exception message.
    except tuf.UnsignedMetadataError, e:
      raise tuf.UnsignedMetadataError(e[0])

     
    # Delete the metadata of roles no longer in 'tuf.roledb'.  Obsolete roles
    # may have been revoked and should no longer have their metadata files
    # available on disk, otherwise loading a repository may unintentionally load
    # them.
    _delete_obsolete_metadata(self._metadata_directory,
                              snapshot_signable['signed'], consistent_snapshot)


  
  def write_partial(self):
    """
    <Purpose>
      Write all the JSON Metadata objects to their corresponding files, but
      allow metadata files to contain an invalid threshold of signatures.  
    
    <Arguments>
      None.

    <Exceptions>
      None.

    <Side Effects>
      Creates metadata files in the repository's metadata directory.

    <Returns>
      None.
    """

    self.write(write_partial=True)
  
  
  
  def status(self):
    """
    <Purpose>
      Determine the status of the top-level roles, including those delegated by
      the Targets role.  status() checks if each role provides sufficient public
      and private keys, signatures, and that a valid metadata file is generated
      if write() were to be called.  Metadata files are temporarily written so
      that file hashes and lengths may be verified, determine if delegated role
      trust is fully obeyed, and target paths valid according to parent roles.
      status() does not do a simple check for number of threshold keys and
      signatures.

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
    # content.  Ensure temporary files generated are removed after verification
    # results are completed.
    try:
      temp_repository_directory = tempfile.mkdtemp()
      targets_directory = self._targets_directory
      metadata_directory = os.path.join(temp_repository_directory,
                                        METADATA_STAGED_DIRECTORY_NAME)
      os.mkdir(metadata_directory)

    
      # Retrieve the roleinfo of the delegated roles, exluding the top-level
      # targets role.
      delegated_roles = tuf.roledb.get_delegated_rolenames('targets')
      insufficient_keys = []
      insufficient_signatures = []
     
      # Iterate the list of delegated roles and determine the list of invalid
      # roles.  First verify the public and private keys, and then the generated
      # metadata file.
      for delegated_role in delegated_roles:
        filename = delegated_role + METADATA_EXTENSION
        filename = os.path.join(metadata_directory, filename)
        
        # Ensure the parent directories of 'filename' exist, otherwise an
        # IO exception is raised if 'filename' is written to a sub-directory.
        tuf.util.ensure_parent_dir(filename)
       
        # Append any invalid roles to the 'insufficient_keys' and
        # 'insufficient_signatures' lists
        try: 
          _check_role_keys(delegated_role)
        
        except tuf.InsufficientKeysError, e:
          insufficient_keys.append(delegated_role)
          continue
        
        try: 
          _generate_and_write_metadata(delegated_role, filename, False,
                                       targets_directory, metadata_directory)
        except tuf.UnsignedMetadataError, e:
          insufficient_signatures.append(delegated_role)
     
      # Print the verification results of the delegated roles and return
      # immediately after each invalid case.
      if len(insufficient_keys):
        message = \
          'Delegated roles with insufficient keys:\n'+repr(insufficient_keys)
        print(message)
        return
      
      if len(insufficient_signatures):
        message = \
          'Delegated roles with insufficient signatures:\n'+\
          repr(insufficient_signatures)
        print(message) 
        return

      # Verify the top-level roles and print the results.
      _print_status_of_top_level_roles(targets_directory, metadata_directory)
    
    finally:
      shutil.rmtree(temp_repository_directory, ignore_errors=True)


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
      tuf.FormatError, if the arguments are improperly formatted.

      tuf.Error, if 'file_directory' is not a valid directory.

      Python IO exceptions.

    <Side Effects>
      None.

    <Returns>
      A list of absolute paths to target files in the given 'files_directory'.
    """

    # Do the arguments have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.
    # Raise 'tuf.FormatError' if any are improperly formatted.
    tuf.formats.PATH_SCHEMA.check_match(files_directory)
    tuf.formats.BOOLEAN_SCHEMA.check_match(recursive_walk)
    tuf.formats.BOOLEAN_SCHEMA.check_match(followlinks)

    # Ensure a valid directory is given.
    if not os.path.isdir(files_directory):
      message = repr(files_directory)+' is not a directory.'
      raise tuf.Error(message)
   
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
      # recursively walk files_directory.
      if recursive_walk is False:
        del dirnames[:]

    return targets





class Metadata(object):
  """
  <Purpose>
    Provide a base class to represent a TUF Metadata role.  There are four
    top-level roles: Root, Targets, Snapshot, and Timestamp.  The Metadata class
    provides methods that are needed by all top-level roles, such as adding
    and removing public keys, private keys, and signatures.  Metadata
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
    


  def add_verification_key(self, key):
    """
    <Purpose>
      Add 'key' to the role.  Adding a key, which should contain only the public
      portion, signifies the corresponding private key and signatures the role
      is expected to provide.  A threshold of signatures is required for a role
      to be considered properly signed.  If a metadata file contains an
      insufficient threshold of signatures, it must not be accepted.

      >>> 
      >>> 
      >>> 

    <Arguments>
      key:
        The role key to be added, conformant to 'tuf.formats.ANYKEY_SCHEMA'.
        Adding a public key to a role means that its corresponding private key
        must generate and add its signature to the role.  A threshold number of
        signatures is required for a role to be fully signed.

    <Exceptions>
      tuf.FormatError, if the 'key' argument is improperly formatted.    

    <Side Effects>
      The role's entries in 'tuf.keydb.py' and 'tuf.roledb.py' are updated.

    <Returns>
      None.
    """
   
    # Does 'key' have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.
    # Raise 'tuf.FormatError' if any are improperly formatted.
    tuf.formats.ANYKEY_SCHEMA.check_match(key)

    # Ensure 'key', which should contain the public portion, is added to
    # 'tuf.keydb.py'.  Add 'key' to the list of recognized keys.  Keys may be
    # shared, so do not raise an exception if 'key' has already been loaded.
    try:
      tuf.keydb.add_key(key)
    
    except tuf.KeyAlreadyExistsError, e:
      message = 'Adding a verification key that has already been used.'
      logger.warn(message)

    keyid = key['keyid']
    roleinfo = tuf.roledb.get_roleinfo(self.rolename)
   
    # Add 'key' to the role's entry in 'tuf.roledb.py' and avoid duplicates.
    if keyid not in roleinfo['keyids']: 
      roleinfo['keyids'].append(keyid)
      
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
        The role's key, conformant to 'tuf.formats.ANYKEY_SCHEMA'.  'key'
        should contain only the public portion, as only the public key is
        needed.  The 'add_verification_key()' method should have previously
        added 'key'. 

    <Exceptions>
      tuf.FormatError, if the 'key' argument is improperly formatted.
      
      tuf.Error, if the 'key' argument has not been previously added.
    
    <Side Effects>
      Updates the role's 'tuf.roledb.py' entry.

    <Returns>
      None.
    """
    
    # Does 'key' have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.
    # Raise 'tuf.FormatError' if any are improperly formatted.
    tuf.formats.ANYKEY_SCHEMA.check_match(key)
    
    keyid = key['keyid']
    roleinfo = tuf.roledb.get_roleinfo(self.rolename)
    
    if keyid in roleinfo['keyids']: 
      roleinfo['keyids'].remove(keyid)
      
      tuf.roledb.update_roleinfo(self._rolename, roleinfo)
    
    else:
      raise tuf.Error('Verification key not found.')
   


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
        The role's key, conformant to 'tuf.formats.ANYKEY_SCHEMA'.  It must
        contain the private key, so that role signatures may be generated when
        write() or write_partial() is eventually called to generate valid
        metadata files.

    <Exceptions>
      tuf.FormatError, if 'key' is improperly formatted.

      tuf.Error, if the private key is not found in 'key'.

    <Side Effects>
      Updates the role's 'tuf.keydb.py' and 'tuf.roledb.py' entries.

    <Returns>
      None.
    """
    
    # Does 'key' have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.
    # Raise 'tuf.FormatError' if any are improperly formatted.
    tuf.formats.ANYKEY_SCHEMA.check_match(key)
  
    # Ensure the private portion of the key is available, otherwise signatures
    # cannot be generated when the metadata file is written to disk.
    if not len(key['keyval']['private']):
      message = 'This is not a private key.'
      raise tuf.Error(message)

    # Has the key, with the private portion included, been added to the keydb?
    # The public version of the key may have been previously added.
    try:
      tuf.keydb.add_key(key)
    
    except tuf.KeyAlreadyExistsError, e:
      tuf.keydb.remove_key(key['keyid'])
      tuf.keydb.add_key(key)

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
        The role key to be unloaded, conformant to 'tuf.formats.ANYKEY_SCHEMA'.

    <Exceptions>
      tuf.FormatError, if the 'key' argument is improperly formatted.

      tuf.Error, if the 'key' argument has not been previously loaded.

    <Side Effects>
      Updates the signing keys of the role in 'tuf.roledb.py'.

    <Returns>
      None.
    """
    
    # Does 'key' have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.
    # Raise 'tuf.FormatError' if any are improperly formatted.
    tuf.formats.ANYKEY_SCHEMA.check_match(key)
    
    # Update the role's 'signing_keys' field in 'tuf.roledb.py'.
    roleinfo = tuf.roledb.get_roleinfo(self.rolename)
    
    if key['keyid'] in roleinfo['signing_keyids']:
      roleinfo['signing_keyids'].remove(key['keyid'])
      
      tuf.roledb.update_roleinfo(self.rolename, roleinfo)
    
    else:
      raise tuf.Error('Signing key not found.')
      


  def add_signature(self, signature):
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
        'tuf.formats.SIGNATURE_SCHEMA'.

    <Exceptions>
      tuf.FormatError, if the 'signature' argument is improperly formatted.

    <Side Effects>
      Adds 'signature', if not already added, to the role's 'signatures' field
      in 'tuf.roledb.py'.

    <Returns>
      None.
    """
    
    # Does 'signature' have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.
    # Raise 'tuf.FormatError' if any are improperly formatted.
    tuf.formats.SIGNATURE_SCHEMA.check_match(signature)
  
    roleinfo = tuf.roledb.get_roleinfo(self.rolename)
    
    # Ensure the roleinfo contains a 'signatures' field.
    if 'signatures' not in roleinfo:
      roleinfo['signatures'] = []
   
    # Update the role's roleinfo by adding 'signature', if it has not been
    # added.
    if signature not in roleinfo['signatures']:
      roleinfo['signatures'].append(signature)
      tuf.roledb.update_roleinfo(self.rolename, roleinfo)



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
        'tuf.formats.SIGNATURE_SCHEMA'.

    <Exceptions>
      tuf.FormatError, if the 'signature' argument is improperly formatted.

      tuf.Error, if 'signature' has not been previously added to this role.

    <Side Effects>
      Updates the 'signatures' field of the role in 'tuf.roledb.py'.

    <Returns>
      None.
    """
    
    # Does 'signature' have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.
    # Raise 'tuf.FormatError' if any are improperly formatted.
    tuf.formats.SIGNATURE_SCHEMA.check_match(signature)
  
    roleinfo = tuf.roledb.get_roleinfo(self.rolename)
    
    if signature in roleinfo['signatures']:
      roleinfo['signatures'].remove(signature)
      
      tuf.roledb.update_roleinfo(self.rolename, roleinfo)

    else:
      raise tuf.Error('Signature not found.')



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
      A list of signatures, conformant to 'tuf.formats.SIGNATURES_SCHEMA'.
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
      The role's name, conformant to 'tuf.formats.ROLENAME_SCHEMA'.
      Examples: 'root', 'timestamp', 'targets/unclaimed/django'.
    """

    return self._rolename
  
  
  
  @property
  def version(self):
    """
    <Purpose>
      A getter method that returns the role's version number, conformant to
      'tuf.formats.VERSION_SCHEMA'.

    <Arguments>
      None.

    <Exceptions>
      None.

    <Side Effects>
      None.

    <Returns>
      The role's version number, conformant to 'tuf.formats.VERSION_SCHEMA'.
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
        The role's version number, conformant to 'tuf.formats.VERSION_SCHEMA'.

    <Exceptions>
      tuf.FormatError, if the 'version' argument is improperly formatted.

    <Side Effects>
      Modifies the 'version' attribute of the Repository object and updates
      the role's version in 'tuf.roledb.py'.

    <Returns>
      None.
    """
    
    # Does 'version' have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.
    # Raise 'tuf.FormatError' if any are improperly formatted.
    tuf.formats.METADATAVERSION_SCHEMA.check_match(version)
    
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
      The role's threshold value, conformant to 'tuf.formats.THRESHOLD_SCHEMA'.
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
        signed.  Conformant to 'tuf.formats.THRESHOLD_SCHEMA'.

    <Exceptions>
      tuf.FormatError, if the 'threshold' argument is improperly formatted.

    <Side Effects>
      Modifies the threshold attribute of the Repository object and updates
      the roles threshold in 'tuf.roledb.py'.

    <Returns>
      None.
    """
   
    # Does 'threshold' have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.
    # Raise 'tuf.FormatError' if any are improperly formatted.
    tuf.formats.THRESHOLD_SCHEMA.check_match(threshold)
    
    roleinfo = tuf.roledb.get_roleinfo(self._rolename)
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
      tuf.FormatError, if 'datetime_object' is not a datetime.datetime() object. 
   
      tuf.Error, if 'datetime_object' has already expired.

    <Side Effects>
      Modifies the expiration attribute of the Repository object.

    <Returns>
      None.
    """
    
    # Is 'datetime_object' a datetime.datetime() object?
    # Raise 'tuf.FormatError' if not.
    if not isinstance(datetime_object, datetime.datetime):
      message = repr(datetime_object) + ' is not a datetime.datetime() object.'
      raise tuf.FormatError(message) 

    # truncate the microseconds value to produce a correct schema string 
    # of the form yyyy-mm-ddThh:mm:ssZ
    datetime_object = datetime_object.replace(microsecond = 0)
    
    # Ensure the expiration has not already passed.
    current_datetime_object = \
      tuf.formats.unix_timestamp_to_datetime(int(time.time()))
    
    if datetime_object < current_datetime_object:
      message = repr(self.rolename) + ' has already expired.'
      raise tuf.Error(message)
   
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
      'tuf.formats.KEYIDS_SCHEMA'.
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
      'targets.json' role, the metadata files 'targets.json' and 'targets.json.gz'
      are written.

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
      'tuf.formats.COMPRESSIONS_SCHEMA'.
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
        'tuf.formats.COMPRESSIONS_SCHEMA'.

    <Exceptions>
      tuf.FormatError, if 'compression_list' is improperly formatted.

    <Side Effects>
      Updates the role's compression algorithms listed in 'tuf.roledb.py'.

    <Returns>
      None. 
    """
   
    # Does 'compression_name' have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.
    # Raise 'tuf.FormatError' if any are improperly formatted.
    tuf.formats.COMPRESSIONS_SCHEMA.check_match(compression_list)

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
    
    except tuf.RoleAlreadyExistsError, e:
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
    Since Snapshot is a top-level role and must exist, a default Timestamp object
    is instantiated when a new Repository object is created.

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

    # By default, 'snapshot' metadata is set to expire 1 week from the current
    # time.  The expiration may be modified.
    expiration = \
      tuf.formats.unix_timestamp_to_datetime(int(time.time() + TIMESTAMP_EXPIRATION))
    expiration = expiration.isoformat() + 'Z'

    roleinfo = {'keyids': [], 'signing_keyids': [], 'threshold': 1,
                'signatures': [], 'version': 0, 'compressions': [''],
                'expires': expiration, 'partial_loaded': False}
    
    try: 
      tuf.roledb.add_role(self.rolename, roleinfo)
    
    except tuf.RoleAlreadyExistsError, e:
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
    
    except tuf.RoleAlreadyExistsError, e:
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
    
    This Targets object sub-classes Metadata, so the expected
    Metadata operations like adding/removing public keys, signatures, private
    keys, and updating metadata attributes (e.g., version and expiration) is
    supported.  Since Targets is a top-level role and must exist, a default
    Targets object (for 'targets.json', not delegated roles) is instantiated when
    a new Repository object is created.

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
      'tuf.formats.ROLEDB_SCHEMA'.

  <Exceptions>
    tuf.FormatError, if the arguments are improperly formatted.

  <Side Effects>
    Modifies the roleinfo of the targets role in 'tuf.roledb', or creates
    a default one named 'targets'.
  
  <Returns>
    None.
  """
  
  def __init__(self, targets_directory, rolename='targets', roleinfo=None):
   
    # Do the arguments have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.
    # Raise 'tuf.FormatError' if any are improperly formatted.
    tuf.formats.PATH_SCHEMA.check_match(targets_directory)
    tuf.formats.ROLENAME_SCHEMA.check_match(rolename)
    
    if roleinfo is not None:
      tuf.formats.ROLEDB_SCHEMA.check_match(roleinfo)

    super(Targets, self).__init__()
    self._targets_directory = targets_directory
    self._rolename = rolename 
    self._target_files = []
    self._delegated_roles = {}
  
    # By default, Targets objects are set to expire 3 months from the current
    # time.  May be later modified.
    expiration = \
      tuf.formats.unix_timestamp_to_datetime(int(time.time() + TARGETS_EXPIRATION))
    expiration = expiration.isoformat() + 'Z'

    # If 'roleinfo' is not provided, set an initial default.
    if roleinfo is None:
      roleinfo = {'keyids': [], 'signing_keyids': [], 'threshold': 1,
                  'version': 0, 'compressions': [''], 'expires': expiration,
                  'signatures': [], 'paths': [], 'path_hash_prefixes': [],
                  'partial_loaded': False, 'delegations': {'keys': {},
                                                           'roles': []}}
   
    # Add the new role to the 'tuf.roledb'.
    try:
      tuf.roledb.add_role(self.rolename, roleinfo)
    
    except tuf.RoleAlreadyExistsError, e:
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
      tuf.FormatError, if the arguments are improperly formatted.

      tuf.UnknownRoleError, if 'rolename' has not been delegated by this
      Targets object.

    <Side Effects>
      Modifies the roleinfo of the targets role in 'tuf.roledb'.
    
    <Returns>
      The Targets object of 'rolename'. 
    """
    
    # Do the arguments have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.
    # Raise 'tuf.FormatError' if any are improperly formatted.
    tuf.formats.ROLENAME_SCHEMA.check_match(rolename)
   
    if rolename in self._delegated_roles:
      return self._delegated_roles[rolename]
    
    else:
      message = repr(rolename)+' has not been delegated by '+repr(self.rolename) 
      raise tuf.UnknownRoleError(message)



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



  def add_restricted_paths(self, list_of_directory_paths, child_rolename):
    """
    <Purpose>
      Add 'list_of_directory_paths' to the restricted paths of 'child_rolename'.
      The updater client verifies the target paths specified by child roles, and
      searches for targets by visiting these restricted paths.  A child role may
      only provide targets specifically listed in the delegations field of the
      parent, or a target that falls under a restricted path.

      >>> 
      >>>
      >>>

    <Arguments>
      list_of_directory_paths:
        A list of directory paths 'child_rolename' should also be restricted to.

      child_rolename:
        The child delegation that requires an update to its restricted paths,
        as listed in the parent role's delegations (e.g., 'Django' in
        'targets/unclaimed/Django').

    <Exceptions>
      tuf.Error, if a directory path in 'list_of_directory_paths' is not a
      directory, or not under the repository's targets directory.  If
      'child_rolename' has not been delegated yet. 

    <Side Effects>
      Modifies this Targets' delegations field.
    
    <Returns>
      None.
    """
    
    # Does 'filepath' have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.
    # Raise 'tuf.FormatError' if there is a mismatch.
    tuf.formats.PATHS_SCHEMA.check_match(list_of_directory_paths)
    tuf.formats.ROLENAME_SCHEMA.check_match(child_rolename)

    # A list of verified paths to be added to the child role's entry in the
    # parent's delegations.
    directory_paths = []
   
    # Ensure the 'child_rolename' has been delegated, otherwise it will not
    # have an entry in the parent role's delegations field.
    full_child_rolename = self._rolename + '/' + child_rolename 
    if not tuf.roledb.role_exists(full_child_rolename):
      raise tuf.Error(repr(full_child_rolename)+' has not been delegated.')

    # Are the paths in 'list_of_directory_paths' valid?
    for directory_path in list_of_directory_paths:
      directory_path = os.path.abspath(directory_path)
      if not os.path.isdir(directory_path):
        message = repr(directory_path)+ ' is not a directory.'
        raise tuf.Error(message)

      # Are the paths in the repository's targets directory?  Append a trailing
      # path separator with os.path.join(path, '').
      targets_directory = os.path.join(self._targets_directory, '')
      directory_path = os.path.join(directory_path, '')
      if not directory_path.startswith(targets_directory):
        message = repr(directory_path)+' is not under the Repository\'s '+\
          'targets directory: '+repr(self._targets_directory)
        raise tuf.Error(message)

      directory_paths.append(directory_path[len(self._targets_directory):])

    # Get the current role's roleinfo, so that its delegations field can be
    # updated.
    roleinfo = tuf.roledb.get_roleinfo(self._rolename)
   
    # Update the restricted paths of 'child_rolename'. 
    for role in roleinfo['delegations']['roles']:
      if role['name'] == full_child_rolename:
        restricted_paths = role['paths'] 
    
    for directory_path in directory_paths:
      if directory_path not in restricted_paths:
        restricted_paths.append(directory_path)
   
    tuf.roledb.update_roleinfo(self._rolename, roleinfo)



  def add_target(self, filepath):
    """
    <Purpose>
      Add a filepath (must be under the repository's targets directory) to the
      Targets object.
      
      This method does not actually create 'filepath' on the file system.
      'filepath' must already exist on the file system.

      >>> 
      >>>
      >>>

    <Arguments>
      filepath:
        The path of the target file.  It must be located in the repository's
        targets directory.

    <Exceptions>
      tuf.FormatError, if 'filepath' is improperly formatted.

      tuf.Error, if 'filepath' is not found under the repository's targets
      directory.

    <Side Effects>
      Adds 'filepath' to this role's list of targets.  This role's
      'tuf.roledb.py' is also updated.

    <Returns>
      None.
    """
    
    # Does 'filepath' have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.
    # Raise 'tuf.FormatError' if there is a mismatch.
    tuf.formats.PATH_SCHEMA.check_match(filepath)

    filepath = os.path.abspath(filepath)
   
    # Ensure 'filepath' is found under the repository's targets directory.
    if not filepath.startswith(self._targets_directory): 
      message = repr(filepath)+' is not under the Repository\'s targets '+\
        'directory: '+repr(self._targets_directory)
      raise tuf.Error(message)

    # Add 'filepath' (i.e., relative to the targets directory) to the role's
    # list of targets.  'filepath' will be verified as an allowed path according
    # to this Targets parent role when write() is called.  Not verifying
    # 'filepath' here allows freedom to add targets and parent restrictions
    # in any order, and minimize the number of times these checks are performed.
    if os.path.isfile(filepath):
      
      # Update the role's 'tuf.roledb.py' entry and avoid duplicates.
      targets_directory_length = len(self._targets_directory) 
      roleinfo = tuf.roledb.get_roleinfo(self._rolename)
      relative_path = filepath[targets_directory_length:]
      if relative_path not in roleinfo['paths']:
        roleinfo['paths'].append(relative_path)
      tuf.roledb.update_roleinfo(self._rolename, roleinfo)
    
    else:
      message = repr(filepath)+' is not a valid file.'
      raise tuf.Error(message)
 

  
  def add_targets(self, list_of_targets):
    """
    <Purpose>
      Add a list of target filepaths (all relative to 'self.targets_directory').
      This method does not actually create files on the file system.  The
      list of target must already exist.
      
      >>> 
      >>>
      >>>

    <Arguments>
      list_of_targets:
        A list of target filepaths that are added to the paths of this Targets
        object.

    <Exceptions>
      tuf.FormatError, if the arguments are improperly formatted.
      
      tuf.Error, if any of the paths listed in 'list_of_targets' is not found
      under the repository's targets directory or is invalid.

    <Side Effects>
      This Targets' roleinfo is updated with the paths in 'list_of_targets'.

    <Returns>
      None.
    """

    # Does 'list_of_targets' have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.
    # Raise 'tuf.FormatError' if there is a mismatch.
    tuf.formats.RELPATHS_SCHEMA.check_match(list_of_targets)

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
        message = repr(filepath)+' is not under the Repository\'s targets '+\
          'directory: '+repr(self._targets_directory)
        raise tuf.Error(message)
      
      if os.path.isfile(filepath):
        relative_list_of_targets.append(filepath[targets_directory_length:])
      
      else:
        message = repr(filepath)+' is not a valid file.'
        raise tuf.Error(message)

    # Update this Targets 'tuf.roledb.py' entry.
    roleinfo = tuf.roledb.get_roleinfo(self._rolename)
    for relative_target in relative_list_of_targets:
      if relative_target not in roleinfo['paths']:
        roleinfo['paths'].append(relative_target)
    
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
      tuf.FormatError, if 'filepath' is improperly formatted.

      tuf.Error, if 'filepath' is not under the repository's targets directory,
      or not found.

    <Side Effects>
      Modifies this Targets 'tuf.roledb.py' entry.
    
    <Returns>
      None.
    """

    # Does 'filepath' have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.
    # Raise 'tuf.FormatError' if there is a mismatch.
    tuf.formats.RELPATH_SCHEMA.check_match(filepath)
   
    filepath = os.path.abspath(filepath)
    targets_directory_length = len(self._targets_directory)
    
    # Ensure 'filepath' is under the repository targets directory.
    if not filepath.startswith(self._targets_directory+os.sep):
      message = repr(filepath)+' is not under the Repository\'s targets '+\
        'directory: '+repr(self._targets_directory)
      raise tuf.Error(message)

    # The relative filepath is listed in 'paths'.
    relative_filepath = filepath[targets_directory_length:]
   
    # Remove 'relative_filepath', if found, and update this Targets roleinfo.  
    fileinfo = tuf.roledb.get_roleinfo(self.rolename)
    if relative_filepath in fileinfo['paths']:
      fileinfo['paths'].remove(relative_filepath)
      tuf.roledb.update_roleinfo(self.rolename, fileinfo)
    
    else:
      raise tuf.Error('Target file path not found.')



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
    roleinfo['paths'] = []
    
    tuf.roledb.update_roleinfo(self.rolename, roleinfo) 



  def get_delegated_rolenames(self):
    """
    <Purpose>
      Return all delegations of a role, including any made by child delegations.
      If ['a/b/', 'a/b/c/', 'a/b/c/d'] have been delegated,
      repository.a.get_delegated_rolenames() returns:
      ['a/b', 'a/b/c', 'a/b/c/d'].

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



  def delegate(self, rolename, public_keys, list_of_targets,
               threshold=1, restricted_paths=None, path_hash_prefixes=None):
    """
    <Purpose>
      Create a new delegation, where 'rolename' is a child delegation of this
      Targets object.  The keys and roles database is updated, including the
      delegations field of this Targets.  The delegation of 'rolename' is added
      and accessible (e.g., 'repository.targets(rolename).
      
      Actual metadata files are not updated, only when repository.write() or
      repository.write_partial() is called.

      >>> 
      >>>
      >>>

    <Arguments>
      rolename:
        The name of the delegated role, as in 'django' (i.e., not the full
        rolename).

      public_keys:
        A list of TUF key objects in 'ANYKEYLIST_SCHEMA' format.  The list
        may contain any of the supported key types: RSAKEY_SCHEMA,
        ED25519KEY_SCHEMA, etc.

      list_of_targets:
        A list of target filepaths that are added to the paths of 'rolename'.
        'list_of_targets' is a list of target filepaths, and can be empty.

      threshold:
        The threshold number of keys of 'rolename'. 

      restricted_paths:
        A list of restricted directory or file paths of 'rolename'.  Any target
        files added to 'rolename' must fall under one of the restricted paths.
      
      path_hash_prefixes:
        A list of hash prefixes in 'tuf.formats.PATH_HASH_PREFIXES_SCHEMA'
        format, used in hashed bin delegations.  Targets may be located and
        stored in hashed bins by calculating the target path's hash prefix.

    <Exceptions>
      tuf.FormatError, if any of the arguments are improperly formatted.

      tuf.Error, if the delegated role already exists or if any of the arguments
      is an invalid path (i.e., not under the repository's targets directory).

    <Side Effects>
      A new Target object is created for 'rolename' that is accessible to the
      caller (i.e., targets.unclaimed.<rolename>).  The 'tuf.keydb.py' and
      'tuf.roledb.py' stores are updated with 'public_keys'.

    <Returns>
      None.
    """

    # Do the arguments have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.
    # Raise 'tuf.FormatError' if there is a mismatch.
    tuf.formats.ROLENAME_SCHEMA.check_match(rolename)
    tuf.formats.ANYKEYLIST_SCHEMA.check_match(public_keys)
    tuf.formats.RELPATHS_SCHEMA.check_match(list_of_targets)
    tuf.formats.THRESHOLD_SCHEMA.check_match(threshold)
    if restricted_paths is not None:
      tuf.formats.RELPATHS_SCHEMA.check_match(restricted_paths)
    if path_hash_prefixes is not None:
      tuf.formats.PATH_HASH_PREFIXES_SCHEMA.check_match(path_hash_prefixes)
    
    # Check if 'rolename' is not already a delegation.  'tuf.roledb' expects the
    # full rolename. 
    full_rolename = self._rolename+'/'+rolename

    if tuf.roledb.role_exists(full_rolename):
      raise tuf.Error(repr(full_rolename)+' already delegated.')

    # Keep track of the valid keyids (added to the new Targets object) and their
    # keydicts (added to this Targets delegations). 
    keyids = [] 
    keydict = {}

    # Add all the keys of 'public_keys' to tuf.keydb.
    for key in public_keys:
      keyid = key['keyid']
      key_metadata_format = tuf.keys.format_keyval_to_metadata(key['keytype'],
                                                               key['keyval'])
      # Update 'keyids' and 'keydict'.
      new_keydict = {keyid: key_metadata_format}
      keydict.update(new_keydict)
      keyids.append(keyid)

    # Ensure the paths of 'list_of_targets' all fall under the repository's
    # targets.
    relative_targetpaths = []
    targets_directory_length = len(self._targets_directory)
    
    for target in list_of_targets:
      target = os.path.abspath(target)
      if not target.startswith(self._targets_directory+os.sep):
        message = repr(target)+' is not under the Repository\'s targets '+\
        'directory: '+repr(self._targets_directory)
        raise tuf.Error(message)

      relative_targetpaths.append(target[targets_directory_length:])
    
    # Ensure the paths of 'restricted_paths' all fall under the repository's
    # targets.
    relative_restricted_paths = []
   
    if restricted_paths is not None: 
      for path in restricted_paths:
        path = os.path.abspath(path)+os.sep
        if not path.startswith(self._targets_directory+os.sep):
          message = repr(path)+' is not under the Repository\'s targets '+\
          'directory: '+repr(self._targets_directory)
          raise tuf.Error(message)
        
        # Append a trailing path separator with os.path.join(path, '').
        path = os.path.join(path, '')
        relative_restricted_paths.append(path[targets_directory_length:])
   
    # Create a new Targets object for the 'rolename' delegation.  An initial
    # expiration is set (3 months from the current time).
    expiration = \
      tuf.formats.unix_timestamp_to_datetime(int(time.time() + TARGETS_EXPIRATION))
    expiration = expiration.isoformat() + 'Z'
    
    roleinfo = {'name': full_rolename, 'keyids': keyids, 'signing_keyids': [],
                'threshold': threshold, 'version': 0, 'compressions': [''],
                'expires': expiration, 'signatures': [], 'partial_loaded': False,
                'paths': relative_targetpaths, 'delegations': {'keys': {},
                'roles': []}}

    # The new targets object is added as an attribute to this Targets object. 
    new_targets_object = Targets(self._targets_directory, full_rolename,
                                 roleinfo)
    
    # Update the 'delegations' field of the current role.
    current_roleinfo = tuf.roledb.get_roleinfo(self.rolename) 
    current_roleinfo['delegations']['keys'].update(keydict)

    # Update the roleinfo of this role.  A ROLE_SCHEMA object requires only
    # 'keyids', 'threshold', and 'paths'.
    roleinfo = {'name': full_rolename,
                'keyids': roleinfo['keyids'],
                'threshold': roleinfo['threshold'],
                'paths': roleinfo['paths']}
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

    # Add the new delegation to this Targets object.  For example, 'django' is
    # added to 'repository.targets' (i.e., repository.targets('django')).
    self._delegated_roles[rolename] = new_targets_object



  def revoke(self, rolename):
    """
    <Purpose>
      Revoke this Targets' 'rolename' delegation.  Its 'rolename' attribute is
      deleted, including the entries in its 'delegations' field and in
      'tuf.roledb'.
      
      Actual metadata files are not updated, only when repository.write() or
      repository.write_partial() is called.
      
      >>>
      >>>
      >>>

    <Arguments>
      rolename:
        The rolename (e.g., 'Django' in 'targets/unclaimed/Django') of
        the child delegation the parent role (this role) wants to revoke.

    <Exceptions>
      tuf.FormatError, if 'rolename' is improperly formatted.

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
    # Raise 'tuf.FormatError' if there is a mismatch.
    tuf.formats.ROLENAME_SCHEMA.check_match(rolename) 

    # Remove 'rolename' from this Target's delegations dict.  
    # The child delegation's full rolename is required to locate in the parent's
    # delegations list.
    roleinfo = tuf.roledb.get_roleinfo(self.rolename)
    full_rolename = self.rolename+'/'+rolename
    
    for role in roleinfo['delegations']['roles']:
      if role['name'] == full_rolename:
        roleinfo['delegations']['roles'].remove(role)

    tuf.roledb.update_roleinfo(self.rolename, roleinfo) 
    
    # Remove 'rolename' from 'tuf.roledb.py'.  The delegations of 'rolename' are
    # also removed.
    tuf.roledb.remove_role(full_rolename)
   
    # Remove the rolename delegation from the current role.  For example, the
    # 'django' role is removed from 'repository.targets('unclaimed')('django').
    del self._delegated_roles[rolename]



  def delegate_hashed_bins(self, list_of_targets, keys_of_hashed_bins,
                           number_of_bins=1024):
    """
    <Purpose>
      Distribute a large number of target files over multiple delegated roles
      (hashed bins).  The metadata files of delegated roles will be nearly equal
      in size (i.e., 'list_of_targets' is uniformly distributed by calculating
      the target filepath's hash and determing which bin it should reside in.
      The updater client will use "lazy bin walk" to find a target file's hashed
      bin destination.  The parent role lists a range of path hash prefixes each
      hashed bin contains.  This method is intended for repositories with a
      large number of target files, a way of easily distributing and managing
      the metadata that lists the targets, and minimizing the number of metadata
      files (and their size) downloaded by the client.  See tuf-spec.txt and the
      following link for more information:
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
        repository.targets('unclaimed')('000-003').add_verification_key()
      
      number_of_bins:
        The number of delegated roles, or hashed bins, that should be generated
        and contain the target file attributes listed in 'list_of_targets'.
        'number_of_bins' must be a power of 2.  Each bin may contain a
        range of path hash prefixes (e.g., target filepath digests that range
        from [000]... - [003]..., where the series of digits in brackets is
        considered the hash prefix).

    <Exceptions>
      tuf.FormatError, if the arguments are improperly formatted.
      
      tuf.Error, if 'number_of_bins' is not a power of 2, or one of the targets
        in 'list_of_targets' is not located under the repository's targets
        directory.

    <Side Effects>
      Delegates multiple target roles from the current parent role.

    <Returns>
      None.
    """      
    
    # Do the arguments have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.
    # Raise 'tuf.FormatError' if there is a mismatch.
    tuf.formats.PATHS_SCHEMA.check_match(list_of_targets)
    tuf.formats.ANYKEYLIST_SCHEMA.check_match(keys_of_hashed_bins)
    tuf.formats.NUMBINS_SCHEMA.check_match(number_of_bins)
    
    # Convert 'number_of_bins' to hexadecimal and determine the number of
    # hexadecimal digits needed by each hash prefix.  Calculate the total number
    # of hash prefixes (e.g., 000 - FFF total values) to be spread over
    # 'number_of_bins' and strip the first two characters ('0x') from Python's
    # representation of hexadecimal values (so that they are not used in
    # the calculation of the prefix length.)
    # Example: number_of_bins = 32, total_hash_prefixes = 256, and each hashed
    # bin is responsible for 8 hash prefixes.
    # Hashed bin roles created = 00-07.json, 08-0f.json, ..., f8-ff.json.
    prefix_length =  len(hex(number_of_bins - 1)[2:])
    total_hash_prefixes = 16 ** prefix_length

    # For simplicity, ensure that 'total_hash_prefixes' (16 ^ n) can be evenly
    # distributed over 'number_of_bins' (must be 2 ^ n).  Each bin will contain
    # (total_hash_prefixes / number_of_bins) hash prefixes.
    if total_hash_prefixes % number_of_bins != 0:
      message = 'The "number_of_bins" argument must be a power of 2.'
      raise tuf.Error(message)

    logger.info('Creating hashed bin delegations.')
    logger.info(repr(len(list_of_targets)) + ' total targets.')
    logger.info(repr(number_of_bins) + ' hashed bins.')
    logger.info(repr(total_hash_prefixes) + ' total hash prefixes.')

    # Store the target paths that fall into each bin.  The digest of the
    # target path, reduced to the first 'prefix_length' hex digits, is
    # calculated to determine which 'bin_index' is should go. 
    target_paths_in_bin = {}
    for bin_index in xrange(total_hash_prefixes):
      target_paths_in_bin[bin_index] = []
    
    # Assign every path to its bin.  Ensure every target is located under the
    # repository's targets directory.
    for target_path in list_of_targets:
      target_path = os.path.abspath(target_path)
      if not target_path.startswith(self._targets_directory+os.sep):
        message = 'A path in the list of targets argument is not '+\
          'under the repository\'s targets directory: '+repr(target_path) 
        raise tuf.Error(message)
      
      # Determine the hash prefix of 'target_path' by computing the digest of
      # its path relative to the targets directory.  Example:
      # '{repository_root}/targets/file1.txt' -> 'file1.txt'.
      relative_path = target_path[len(self._targets_directory):]
      digest_object = tuf.hash.digest(algorithm=HASH_FUNCTION)
      digest_object.update(relative_path)
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
    # are listed in 'path_hash_prefixes' of 'outer_bin_index.
    for outer_bin_index in xrange(0, total_hash_prefixes, bin_offset):
      # The bin index is hex padded from the left with zeroes for up to the
      # 'prefix_length' (e.g., 'targets/unclaimed/000-003').  Ensure the correct
      # hash bin name is generated if a prefix range is unneeded.
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

      for inner_bin_index in xrange(outer_bin_index, outer_bin_index+bin_offset):
        # 'inner_bin_rolename' needed in padded hex.  For example, "00b".
        inner_bin_rolename = hex(inner_bin_index)[2:].zfill(prefix_length)
        path_hash_prefixes.append(inner_bin_rolename)
        bin_rolename_targets.extend(target_paths_in_bin[inner_bin_index])
        
      # Delegate from the "unclaimed" targets role to each 'bin_rolename'
      # (i.e., outer_bin_index).
      self.delegate(bin_rolename, keys_of_hashed_bins,
                    list_of_targets=bin_rolename_targets,
                    path_hash_prefixes=path_hash_prefixes)   

      message = 'Delegated from '+repr(self.rolename)+' to '+repr(bin_rolename)
      logger.debug(message)



  def add_target_to_bin(self, target_filepath):
    """
    <Purpose>
      Add the fileinfo of 'target_filepath' to the expected hashed bin if
      the bin is available.  The hashed bin should have been created by 
      {targets_role}.delegate_hashed_bins().  Assuming the target filepath
      falls under the repository's targets directory, determine the filepath's
      hash prefix, locate the expected bin (if any), and then add the fileinfo
      to the expected bin.  Example:  'targets/foo.tar.gz' may be added to
      the 'targets/unclaimed/58-5f.json' role's list of targets by calling this
      method.

      >>>
      >>>
      >>>

    <Arguments>
      target_filepath:
        The filepath of the target to be added to a hashed bin.  The filepath
        must fall under repository's targets directory.

    <Exceptions>
      tuf.FormatError, if 'target_filepath' is improperly formatted.
      
      tuf.Error, if 'target_filepath' cannot be added to a hashed bin
      (e.g., an invalid target filepath, or the expected hashed bin does not
      exist.)

    <Side Effects>
      The fileinfo of 'target_filepath' is added to a hashed bin of this Targets
      object.

    <Returns>
      None. 
    """
    
    # Do the arguments have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.
    # Raise 'tuf.FormatError' if there is a mismatch.
    tuf.formats.PATH_SCHEMA.check_match(target_filepath)

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
      raise tuf.Error(self.rolename + ' has not delegated to any roles.')

    # Set 'prefix_length' if this Targets object has delegated to hashed bins,
    # otherwise raise an exception.
    if 'path_hash_prefixes' in delegation and len(delegation['path_hash_prefixes']):
      prefix_length = len(delegation['path_hash_prefixes'][0])
      
    else:
      raise tuf.Error(self.rolename + ' has not delegated to hashed bins.')
   
    # Ensure the filepath falls under the repository's targets directory.
    filepath = os.path.abspath(target_filepath)
    if not filepath.startswith(self._targets_directory + os.sep):
      message = repr(filepath)+' is not under the Repository\'s targets '+\
        'directory: '+repr(self._targets_directory)
      raise tuf.Error(message)
    
    # Determine the hash prefix of 'target_path' by computing the digest of
    # its path relative to the targets directory.  Example:
    # '{repository_root}/targets/file1.txt' -> '/file1.txt'.
    relative_path = filepath[len(self._targets_directory):]
    digest_object = tuf.hash.digest(algorithm=HASH_FUNCTION)
    digest_object.update(relative_path)
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
        continue

    # 'self._delegated_roles' is keyed by relative rolenames, so update
    # 'hashed_bin_name'.
    if hashed_bin_name is not None:
      hashed_bin_name = hashed_bin_name[len(self.rolename)+1:] 
      self._delegated_roles[hashed_bin_name].add_target(target_filepath)

    else:
      raise tuf.Error(target_filepath + ' cannot be added to any bins.')



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
      tuf.UnknownRoleError, if this Targets' rolename does not exist in
      'tuf.roledb'. 

    <Side Effects>
      None.

    <Returns>
      A list containing the Targets objects of this Targets' delegations.
    """

    return self._delegated_roles.values()





def _generate_and_write_metadata(rolename, metadata_filename, write_partial,
                                 targets_directory, metadata_directory,
                                 consistent_snapshot=False, filenames=None):
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
  snapshot_compressions = tuf.roledb.get_roleinfo('snapshot')['compressions']

  # Generate the appropriate role metadata for 'rolename'. 
  if rolename == 'root':
    metadata = generate_root_metadata(roleinfo['version'],
                                      roleinfo['expires'], consistent_snapshot)
    
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
    root_filename = filenames['root']
    targets_filename = filenames['targets']
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
                                           roleinfo['expires'],
                                           snapshot_compressions)
    
    _log_warning_if_expires_soon(TIMESTAMP_FILENAME, roleinfo['expires'],
                                 TIMESTAMP_EXPIRES_WARN_SECONDS)

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
      signable = sign_metadata(metadata, roleinfo['signing_keyids'],
                               metadata_filename)
  # non-partial write()
  else:
    if tuf.sig.verify(signable, rolename) and not roleinfo['partial_loaded']:
      metadata['version'] = metadata['version'] + 1
      signable = sign_metadata(metadata, roleinfo['signing_keyids'],
                               metadata_filename)
  
  # Write the metadata to file if contains a threshold of signatures. 
  signable['signatures'].extend(roleinfo['signatures']) 
  
  if tuf.sig.verify(signable, rolename) or write_partial:
    _remove_invalid_and_duplicate_signatures(signable)
    compressions = roleinfo['compressions']
    filename = write_metadata_file(signable, metadata_filename, compressions,
                                   consistent_snapshot)
    
    # The root and timestamp files should also be written without a digest if
    # 'consistent_snaptshots' is True.  Client may request a timestamp and root
    # file without knowing its digest and file size.
    if rolename == 'root' or rolename == 'timestamp':
      write_metadata_file(signable, metadata_filename, compressions,
                          consistent_snapshot=False)
    
  
  # 'signable' contains an invalid threshold of signatures. 
  else:
    message = 'Not enough signatures for '+repr(metadata_filename)
    raise tuf.UnsignedMetadataError(message, signable)
  
  return signable, filename 





def _print_status_of_top_level_roles(targets_directory, metadata_directory):
  """
  Non-public function that prints whether any of the top-level roles contain an
  invalid number of public and private keys, or an insufficient threshold of
  signatures.  Considering that the top-level metadata have to be verified in
  the expected root -> targets -> snapshot -> timestamp order, this function
  prints the error message and returns as soon as a required metadata file is
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
    
    except tuf.InsufficientKeysError, e:
      print(str(e))
      return

  # Do the top-level roles contain a valid threshold of signatures?  Top-level
  # metadata is verified in Root -> Targets -> Snapshot -> Timestamp order.
  # Verify the metadata of the Root role.
  try:
    signable, root_filename = \
      _generate_and_write_metadata('root', root_filename, False,
                                   targets_directory, metadata_directory)
    _print_status('root', signable)
 
  # 'tuf.UnsignedMetadataError' raised if metadata contains an invalid threshold
  # of signatures.  Print the valid/threshold message, where valid < threshold.
  except tuf.UnsignedMetadataError, e:
    signable = e[1]
    _print_status('root', signable)
    return

  # Verify the metadata of the Targets role.
  try:
    signable, targets_filename = \
      _generate_and_write_metadata('targets', targets_filename, False,
                                   targets_directory, metadata_directory)
    _print_status('targets', signable)
  
  except tuf.UnsignedMetadataError, e:
    signable = e[1]
    _print_status('targets', signable)
    return

  # Verify the metadata of the snapshot role.
  filenames = {'root': root_filename, 'targets': targets_filename} 
  try:
    signable, snapshot_filename = \
      _generate_and_write_metadata('snapshot', snapshot_filename, False,
                                   targets_directory, metadata_directory,
                                   False, filenames)
    _print_status('snapshot', signable)
  
  except tuf.UnsignedMetadataError, e:
    signable = e[1]
    _print_status('snapshot', signable)
    return
  
  # Verify the metadata of the Timestamp role.
  filenames = {'snapshot': snapshot_filename}
  try:
    signable, snapshot_filename = \
      _generate_and_write_metadata('timestamp', snapshot_filename, False,
                                   targets_directory, metadata_directory,
                                   False, filenames)
    _print_status('timestamp', signable)
  
  except tuf.UnsignedMetadataError, e:
    signable = e[1]
    _print_status('timestamp', signable)
    return




def _print_status(rolename, signable):
  """
  Non-public function prints the number of (good/threshold) signatures of
  'rolename'.
  """
  
  status = tuf.sig.get_signature_status(signable, rolename)

  message = repr(rolename)+' role contains '+ repr(len(status['good_sigs']))+\
    ' / '+repr(status['threshold'])+' signatures.'
  print(message)





def _prompt(message, result_type=str):
  """
    Non-public function that prompts the user for input by printing 'message',
    converting the input to 'result_type', and returning the value to the
    caller.
  """

  return result_type(raw_input(message))





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
  at least 1 good signature, but an insufficient threshold (which means
  'rolename' was written to disk with repository.write_partial().  If 'rolename'
  is found to be partially loaded, mark it as partially loaded in its
  'tuf.roledb' roleinfo.  This function exists to assist in deciding whether
  a role's version number should be incremented when write() or write_parital()
  is called.  Return True if 'rolename' was partially loaded, False otherwise. 
  """

  # The signature status lists the number of good signatures, including
  # bad, untrusted, unknown, etc.
  status = tuf.sig.get_signature_status(signable, rolename)
  
  if len(status['good_sigs']) < status['threshold'] and \
                                                  len(status['good_sigs']) >= 1:
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
    raise tuf.Error(repr(directory)+' directory does not exist.')

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
    message = repr(rolename)+' role contains '+repr(total_keyids)+' / '+ \
      repr(threshold)+' public keys.'
    raise tuf.InsufficientKeysError(message)

  # Raise an exception for an invalid threshold of signing keys.
  if total_signatures == 0 and total_signing_keys < threshold: 
    message = repr(rolename)+' role contains '+repr(total_signing_keys)+' / '+ \
      repr(threshold)+' signing keys.'
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
    
    except tuf.UnknownKeyError, e:
      signable['signatures'].remove(signature)
    
    # Remove 'signature' from 'signable' if it is an invalid signature.
    if not tuf.keys.verify_signature(key, signature, signed):
      signable['signatures'].remove(signature)
    
    # Although valid, it may still need removal if it is a duplicate.  Check
    # the keyid, rather than the signature, to remove duplicate PSS signatures.
    #  PSS may generate multiple different signatures for the same keyid.
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
      
        # Strip the digest if 'consistent_snapshot' is True.
        # Example:  'targets/unclaimed/13df98ab0.django.json'  -->
        # 'targets/unclaimed/django.json'.  Consistent and non-consistent
        # metadata might co-exist if write() and write(consistent_snapshot=True)
        # are mixed, so ensure only 'digest.filename' metadata is stripped.
        embeded_digest = None
        if metadata_name not in snapshot_metadata['meta']: 
          metadata_name, embeded_digest = \
            _strip_consistent_snapshot_digest(metadata_name, consistent_snapshot)
        
        # Strip filename extensions.  The role database does not include the
        # metadata extension.
        metadata_name_extension = metadata_name
        for metadata_extension in METADATA_EXTENSIONS: 
          if metadata_name.endswith(metadata_extension):
            metadata_name = metadata_name[:-len(metadata_extension)]
        
        # Delete the metadata file if it does not exist in 'tuf.roledb'.
        # 'repository_tool.py' might have marked 'metadata_name' as removed, but
        # its metadata file is not actually deleted yet.  Do it now.
        if not tuf.roledb.role_exists(metadata_name):
          logger.info('Removing outdated metadata: ' + repr(metadata_path))
          os.remove(metadata_path)

        # Delete outdated consistent snapshots.  snapshot metadata includes
        # the file extension of roles.
        if consistent_snapshot and embeded_digest is not None:
          file_hashes = snapshot_metadata['meta'][metadata_name_extension] \
                                        ['hashes'].values()
          if embeded_digest not in file_hashes:
            logger.info('Removing outdated metadata: ' + repr(metadata_path))
            os.remove(metadata_path)





def _get_written_metadata_and_digests(metadata_signable):
  """
  Non-public function that returns the actual content of written metadata and
  its digest.
  """

  written_metadata_content = unicode(json.dumps(metadata_signable, indent=1,
                                     sort_keys=True))
  written_metadata_digests = {}

  for hash_algorithm in tuf.conf.REPOSITORY_HASH_ALGORITHMS:
    digest_object = tuf.hash.digest(hash_algorithm)
    digest_object.update(written_metadata_content)
    written_metadata_digests.update({hash_algorithm: digest_object.hexdigest()})
  
  return written_metadata_content, written_metadata_digests





def _strip_consistent_snapshot_digest(metadata_filename, consistent_snapshot):
  """
  Strip from 'metadata_filename' any digest data (in the expected
  '{dirname}/digest.filename' format) that it may contain, and return it.
  """
 
  embeded_digest = ''

  # Strip the digest if 'consistent_snapshot' is True.
  # Example:  'targets/unclaimed/13df98ab0.django.json'  -->
  # 'targets/unclaimed/django.json'
  if consistent_snapshot:
    dirname, basename = os.path.split(metadata_filename)
    embeded_digest = basename[:basename.find('.')]
    
    # Ensure the digest, including the period, is stripped.
    basename = basename[basename.find('.')+1:]
    
    metadata_filename = os.path.join(dirname, basename)
  

  return metadata_filename, embeded_digest






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
    tuf.FormatError, if the arguments are improperly formatted.

  <Side Effects>
    The 'repository_directory' is created if it does not exist, including its
    metadata and targets sub-directories.

  <Returns>
    A 'tuf.repository_tool.Repository' object.
  """

  # Does 'repository_directory' have the correct format?
  # Ensure the arguments have the appropriate number of objects and object
  # types, and that all dict keys are properly named.
  # Raise 'tuf.FormatError' if there is a mismatch.
  tuf.formats.PATH_SCHEMA.check_match(repository_directory)

  # Set the repository, metadata, and targets directories.  These directories
  # are created if they do not exist.
  repository_directory = os.path.abspath(repository_directory)
  metadata_directory = None
  targets_directory = None
  
  # Try to create 'repository_directory' if it does not exist.
  try:
    message = 'Creating '+repr(repository_directory)
    logger.info(message)
    os.makedirs(repository_directory)
  
  # 'OSError' raised if the leaf directory already exists or cannot be created.
  # Check for case where 'repository_directory' has already been created. 
  except OSError, e:
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
    message = 'Creating '+repr(metadata_directory)
    logger.info(message)
    os.mkdir(metadata_directory)
  
  # 'OSError' raised if the leaf directory already exists or cannot be created.
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
    tuf.FormatError, if 'repository_directory' or any of the metadata files
    are improperly formatted.

    tuf.RepositoryError, if the Root role cannot be found.  At a minimum,
    a repository must contain 'root.json'
  
  <Side Effects>
   All the metadata files found in the repository are loaded and their contents
   stored in a repository_tool.Repository object.

  <Returns>
    repository_tool.Repository object.
  """
 
  # Does 'repository_directory' have the correct format?
  # Raise 'tuf.FormatError' if there is a mismatch.
  tuf.formats.PATH_SCHEMA.check_match(repository_directory)

  # Load top-level metadata.
  repository_directory = os.path.abspath(repository_directory)
  metadata_directory = os.path.join(repository_directory,
                                    METADATA_STAGED_DIRECTORY_NAME)
  targets_directory = os.path.join(repository_directory,
                                    TARGETS_DIRECTORY_NAME)

  # The Repository() object loaded (i.e., containing all the metadata roles
  # found) and returned.
  repository = Repository(repository_directory, metadata_directory,
                          targets_directory)
  
  filenames = get_metadata_filenames(metadata_directory)

  # The Root file is always available without a consistent snapshots digest
  # attached to the filename.  Store the 'consistent_snapshot' value read the
  # loaded Root file so that other metadata files may be located.
  # 'consistent_snapshot' value. 
  consistent_snapshot = False

  # Load the metadata of the top-level roles (i.e., Root, Timestamp, Targets,
  # and Snapshot).
  repository, consistent_snapshot = _load_top_level_metadata(repository,
                                                              filenames)
 
  # Load delegated targets metadata.
  # Walk the 'targets/' directory and generate the fileinfo of all the files
  # listed.  This information is stored in the 'meta' field of the snapshot
  # metadata object.
  targets_objects = {}
  loaded_metadata = []
  targets_objects['targets'] = repository.targets
  targets_metadata_directory = os.path.join(metadata_directory,
                                            TARGETS_DIRECTORY_NAME)
  if os.path.exists(targets_metadata_directory) and \
                    os.path.isdir(targets_metadata_directory):
    for root, directories, files in os.walk(targets_metadata_directory):
      
      # 'files' here is a list of target file names.
      for basename in files:
        metadata_path = os.path.join(root, basename)
        metadata_name = \
          metadata_path[len(metadata_directory):].lstrip(os.path.sep)

        # Strip the digest if 'consistent_snapshot' is True.
        # Example:  'targets/unclaimed/13df98ab0.django.json' -->
        # 'targets/unclaimed/django.json'
        metadata_name, digest_junk = \
          _strip_consistent_snapshot_digest(metadata_name, consistent_snapshot)

        if metadata_name.endswith(METADATA_EXTENSION): 
          extension_length = len(METADATA_EXTENSION)
          metadata_name = metadata_name[:-extension_length]
        
        else:
          continue
        
        # Keep a store metadata previously loaded metadata to prevent
        # re-loading duplicate versions.  Duplicate versions may occur with
        # consistent_snapshot, where the same metadata may be available in
        # multiples files (the different hash is included in each filename.
        if metadata_name in loaded_metadata:
          continue

        signable = None
        try:
          signable = tuf.util.load_json_file(metadata_path)
        
        except (ValueError, IOError), e:
          continue
        
        metadata_object = signable['signed']
     
        # Extract the metadata attributes 'metadata_name' and update its
        # corresponding roleinfo.
        roleinfo = tuf.roledb.get_roleinfo(metadata_name)
        roleinfo['signatures'].extend(signable['signatures'])
        roleinfo['version'] = metadata_object['version']
        roleinfo['expires'] = metadata_object['expires']
        roleinfo['paths'] = metadata_object['targets'].keys()
        roleinfo['delegations'] = metadata_object['delegations']

        if os.path.exists(metadata_path+'.gz'):
          roleinfo['compressions'].append('gz')
       
        # The roleinfo of 'metadata_name' should have been initialized with
        # defaults when it was loaded from its parent role.
        if _metadata_is_partially_loaded(metadata_name, signable, roleinfo):
          roleinfo['partial_loaded'] = True
        
        tuf.roledb.update_roleinfo(metadata_name, roleinfo)
        loaded_metadata.append(metadata_name)

        # Generate the Targets objects of the delegated roles of
        # 'metadata_name' and update the parent role Targets object.
        new_targets_object = Targets(targets_directory, metadata_name, roleinfo)
        targets_object = \
          targets_objects[tuf.roledb.get_parent_rolename(metadata_name)]
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
        for key_metadata in metadata_object['delegations']['keys'].values():
          key_object = tuf.keys.format_metadata_to_key(key_metadata)
          try: 
            tuf.keydb.add_key(key_object)
          
          except tuf.KeyAlreadyExistsError, e:
            pass
       
        # Add the delegated role's initial roleinfo, to be fully populated
        # when its metadata file is next loaded in the os.walk() iteration.
        for role in metadata_object['delegations']['roles']:
          rolename = role['name'] 
          roleinfo = {'name': role['name'], 'keyids': role['keyids'],
                      'threshold': role['threshold'],
                      'compressions': [''], 'signing_keyids': [],
                      'signatures': [],
                      'partial_loaded': False,
                      'delegations': {'keys': {},
                                      'roles': []}}
          tuf.roledb.add_role(rolename, roleinfo)

  return repository





def _load_top_level_metadata(repository, top_level_filenames):
  """
  Load the metadata of the Root, Timestamp, Targets, and Snapshot roles.
  At a minimum, the Root role must exist and successfully load.
  """

  root_filename = top_level_filenames[ROOT_FILENAME] 
  targets_filename = top_level_filenames[TARGETS_FILENAME] 
  snapshot_filename = top_level_filenames[SNAPSHOT_FILENAME] 
  timestamp_filename = top_level_filenames[TIMESTAMP_FILENAME]

  root_metadata = None
  targets_metadata = None
  snapshot_metadata = None
  timestamp_metadata = None
  
  # Load 'root.json'.  A Root role file without a digest is always written. 
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

    if os.path.exists(root_filename+'.gz'):
      roleinfo['compressions'].append('gz')
   
    # By default, roleinfo['partial_loaded'] of top-level roles should be set to
    # False in 'create_roledb_from_root_metadata()'.  Update this field, if
    # necessary, now that we have its signable object.
    if _metadata_is_partially_loaded('root', signable, roleinfo):
      roleinfo['partial_loaded'] = True
    
    _log_warning_if_expires_soon(ROOT_FILENAME, roleinfo['expires'],
                                 ROOT_EXPIRES_WARN_SECONDS)
    
    tuf.roledb.update_roleinfo('root', roleinfo)

    # Ensure the 'consistent_snapshot' field is extracted.
    consistent_snapshot = root_metadata['consistent_snapshot']
  
  else:
    message = 'Cannot load the required root file: '+repr(root_filename)
    raise tuf.RepositoryError(message)
  
  # Load 'timestamp.json'.  A Timestamp role file without a digest is always
  # written. 
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
    snapshot_hashes = timestamp_metadata['meta'][SNAPSHOT_FILENAME]['hashes']
    snapshot_digest = random.choice(snapshot_hashes.values())
    dirname, basename = os.path.split(snapshot_filename)
    snapshot_filename = os.path.join(dirname, snapshot_digest + '.' + basename)
  
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
    if os.path.exists(snapshot_filename+'.gz'):
      roleinfo['compressions'].append('gz')
    
    if _metadata_is_partially_loaded('snapshot', signable, roleinfo):
      roleinfo['partial_loaded'] = True
    
    _log_warning_if_expires_soon(SNAPSHOT_FILENAME, roleinfo['expires'],
                                 SNAPSHOT_EXPIRES_WARN_SECONDS)
    
    tuf.roledb.update_roleinfo('snapshot', roleinfo)
  
  else:
    pass 

  # Load 'targets.json'.  A consistent snapshot of Targets must be calculated if
  # 'consistent_snapshot' is True.
  if consistent_snapshot:
    targets_hashes = snapshot_metadata['meta'][TARGETS_FILENAME]['hashes']
    targets_digest = random.choice(targets_hashes.values())
    dirname, basename = os.path.split(targets_filename)
    targets_filename = os.path.join(dirname, targets_digest + '.' + basename)
  
  if os.path.exists(targets_filename):
    signable = tuf.util.load_json_file(targets_filename)
    tuf.formats.check_signable_object_format(signable)
    targets_metadata = signable['signed']

    for signature in signable['signatures']:
      repository.targets.add_signature(signature)
   
    # Update 'targets.json' in 'tuf.roledb.py' 
    roleinfo = tuf.roledb.get_roleinfo('targets')
    roleinfo['paths'] = targets_metadata['targets'].keys()
    roleinfo['version'] = targets_metadata['version']
    roleinfo['expires'] = targets_metadata['expires']
    roleinfo['delegations'] = targets_metadata['delegations']
    if os.path.exists(targets_filename+'.gz'):
      roleinfo['compressions'].append('gz')
   
    if _metadata_is_partially_loaded('targets', signable, roleinfo):
      roleinfo['partial_loaded'] = True
   
    _log_warning_if_expires_soon(TARGETS_FILENAME, roleinfo['expires'],
                                 TARGETS_EXPIRES_WARN_SECONDS)
    
    tuf.roledb.update_roleinfo('targets', roleinfo)

    # Add the keys specified in the delegations field of the Targets role.
    for key_metadata in targets_metadata['delegations']['keys'].values():
      key_object = tuf.keys.format_metadata_to_key(key_metadata)
     
      # Add 'key_object' to the list of recognized keys.  Keys may be shared,
      # so do not raise an exception if 'key_object' has already been loaded.
      # In contrast to the methods that may add duplicate keys, do not log
      # a warning as there may be many such duplicate key warnings.  The
      # repository maintainer should have also been made aware of the duplicate
      # key when it was added.
      try: 
        tuf.keydb.add_key(key_object)
      
      except tuf.KeyAlreadyExistsError, e:
        pass

    for role in targets_metadata['delegations']['roles']:
      rolename = role['name'] 
      roleinfo = {'name': role['name'], 'keyids': role['keyids'],
                  'threshold': role['threshold'], 'compressions': [''],
                  'signing_keyids': [], 'partial_loaded': False,
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
    
    logger.warn(message)





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
  if password is None:
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
  file_object.write(public)
  
  # The temporary file is closed after the final move.
  file_object.move(filepath+'.pub')

  # Write the private key in encrypted PEM format to '<filepath>'.
  # Unlike the public key file, the private key does not have a file
  # extension.
  file_object = tuf.util.TempFile()
  file_object.write(encrypted_pem)
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
  if password is None:
    message = 'Enter a password for the encrypted RSA file: '
    password = _get_password(message, confirm=False)

  # Does 'password' have the correct format?
  tuf.formats.PASSWORD_SCHEMA.check_match(password)

  encrypted_pem = None

  # Read the contents of 'filepath' that should be an encrypted PEM.
  with open(filepath, 'rb') as file_object:
    encrypted_pem = file_object.read()

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
    rsa_pubkey_pem = file_object.read()

  # Convert 'rsa_pubkey_pem' to 'tuf.formats.RSAKEY_SCHEMA' format.
  try: 
    rsakey_dict = tuf.keys.format_rsakey_from_pem(rsa_pubkey_pem)
  
  except tuf.FormatError, e:
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
  if password is None:
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
  file_object.write(json.dumps(ed25519key_metadata_format))
  
  # The temporary file is closed after the final move.
  file_object.move(filepath+'.pub')

  # Write the encrypted key string, conformant to
  # 'tuf.formats.ENCRYPTEDKEY_SCHEMA', to '<filepath>'.
  file_object = tuf.util.TempFile()
  file_object.write(encrypted_key)
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
  if ed25519_key['keytype'] != 'ed25519':
    message = 'Invalid key type loaded: '+repr(ed25519_key['keytype'])
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
  if password is None:
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
    message = 'Invalid key type loaded: '+repr(key_object['keytype'])
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





def get_metadata_fileinfo(filename):
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

  # Does 'filename' have the correct format?
  # Ensure the arguments have the appropriate number of objects and object
  # types, and that all dict keys are properly named.
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
  filesize, filehashes = \
    tuf.util.get_file_details(filename, tuf.conf.REPOSITORY_HASH_ALGORITHMS)
  custom = None

  return tuf.formats.make_fileinfo(filesize, filehashes, custom)






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





def generate_root_metadata(version, expiration_date, consistent_snapshot):
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
      raise tuf.Error(repr(rolename)+' not in "tuf.roledb".')
   
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
                                                     consistent_snapshot)

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
      The target files tracked by 'targets.json'.  'target_files' is a list of
      target paths that are relative to the targets directory (e.g.,
      ['file1.txt', 'Django/module.py']).

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
  tuf.formats.PATHS_SCHEMA.check_match(target_files)
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
  for target in target_files:
   
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
      message = repr(target_path)+' cannot be read.  Unable to generate '+ \
        'targets metadata.'
      raise tuf.Error(message)
    
    filedict[relative_targetpath] = get_metadata_fileinfo(target_path)
    
    if write_consistent_targets:
      for target_digest in filedict[relative_targetpath]['hashes'].values():
        dirname, basename = os.path.split(target_path)
        digest_filename = target_digest + '.' + basename
        digest_target = os.path.join(dirname, digest_filename)

        if not os.path.exists(digest_target):
          logger.warn('Hard linking target file to ' + repr(digest_target))
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

  # Retrieve the fileinfo of 'root.json' and 'targets.json'.  This file
  # information includes data such as file length, hashes of the file, etc.
  filedict = {}
  filedict[ROOT_FILENAME] = get_metadata_fileinfo(root_filename)
  filedict[TARGETS_FILENAME] = get_metadata_fileinfo(targets_filename)

  # Add compressed versions of the 'targets.json' and 'root.json' metadata,
  # if they exist.
  for extension in SUPPORTED_COMPRESSION_EXTENSIONS:
    compressed_root_filename = root_filename+extension
    compressed_targets_filename = targets_filename+extension
    
    # If the compressed versions of the root and targets metadata is found,
    # add their file attributes to 'filedict'.
    if os.path.exists(compressed_root_filename):
      filedict[ROOT_FILENAME+extension] = \
        get_metadata_fileinfo(compressed_root_filename)
    if os.path.exists(compressed_targets_filename): 
      filedict[TARGETS_FILENAME+extension] = \
        get_metadata_fileinfo(compressed_targets_filename)

  # Walk the 'targets/' directory and generate the fileinfo of all the role
  # files found.  This information is stored in the 'meta' field of the snapshot
  # metadata object.
  targets_metadata = os.path.join(metadata_directory, 'targets')
  if os.path.exists(targets_metadata) and os.path.isdir(targets_metadata):
    for directory_path, junk_directories, files in os.walk(targets_metadata):
      
      # 'files' here is a list of file names.
      for basename in files:
        metadata_path = os.path.join(directory_path, basename)
        metadata_name = \
          metadata_path[len(metadata_directory):].lstrip(os.path.sep)
        
        # Strip the digest if 'consistent_snapshot' is True.
        # Example:  'targets/unclaimed/13df98ab0.django.json'  -->
        # 'targets/unclaimed/django.json'
        metadata_name, digest_junk = \
          _strip_consistent_snapshot_digest(metadata_name, consistent_snapshot)
        
        # All delegated roles are added to the snapshot file, including
        # compressed versions.
        for metadata_extension in METADATA_EXTENSIONS: 
          if metadata_name.endswith(metadata_extension):
            rolename = metadata_name[:-len(metadata_extension)]
            
            # Obsolete role files may still be found.  Ensure only roles loaded
            # in the roledb are included in the snapshot metadata.
            if tuf.roledb.role_exists(rolename):
              filedict[metadata_name] = get_metadata_fileinfo(metadata_path)

  # Generate the snapshot metadata object.
  snapshot_metadata = tuf.formats.SnapshotFile.make_metadata(version,
                                                           expiration_date,
                                                           filedict)

  return snapshot_metadata





def generate_timestamp_metadata(snapshot_filename, version,
                                expiration_date, compressions=()):
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

    compressions:
      Compression extensions (e.g., 'gz').  If 'snapshot.json' is also saved in
      compressed form, these compression extensions should be stored in
      'compressions' so the compressed timestamp files can be added to the
      timestamp metadata object.

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
  tuf.formats.COMPRESSIONS_SCHEMA.check_match(compressions)

  # Retrieve the fileinfo of the snapshot metadata file.
  # This file information contains hashes, file length, custom data, etc.
  fileinfo = {}
  fileinfo[SNAPSHOT_FILENAME] = get_metadata_fileinfo(snapshot_filename)

  # Save the fileinfo of the compressed versions of 'timestamp.json'
  # in 'fileinfo'.  Log the files included in 'fileinfo'.
  for file_extension in compressions:
    if not len(file_extension):
      continue

    compressed_filename = snapshot_filename + '.' + file_extension
    try:
      compressed_fileinfo = get_metadata_fileinfo(compressed_filename)
    
    except:
      logger.warn('Cannot get fileinfo about '+repr(compressed_filename))
    
    else:
      logger.info('Including fileinfo about '+repr(compressed_filename))
      fileinfo[SNAPSHOT_FILENAME + '.' + file_extension] = compressed_fileinfo

  # Generate the timestamp metadata object.
  timestamp_metadata = tuf.formats.TimestampFile.make_metadata(version,
                                                               expiration_date,
                                                               fileinfo)

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
    logger.info('Signing '+repr(filename)+' with '+key['keyid'])

    # Create a new signature list.  If 'keyid' is encountered,
    # do not add it to new list.
    signatures = []
    for signature in signable['signatures']:
      if not keyid == signature['keyid']:
        signatures.append(signature)
    signable['signatures'] = signatures

    # Generate the signature using the appropriate signing method.
    if key['keytype'] in SUPPORTED_KEY_TYPES:
      if len(key['keyval']['private']):
        signed = signable['signed']
        signature = tuf.keys.create_signature(key, signed)
        signable['signatures'].append(signature)
      
      else:
        logger.warn('Private key unset.  Skipping: '+repr(keyid))
    
    else:
      raise tuf.Error('The keydb contains a key with an invalid key type.')

  # Raise 'tuf.FormatError' if the resulting 'signable' is not formatted
  # correctly.
  tuf.formats.check_signable_object_format(signable)

  return signable





def write_metadata_file(metadata, filename, compressions, consistent_snapshot):
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
      If a compression algorithm is specified in 'compressions', the
      compression extention is appended to 'filename'.

    compressions:
      Specify the algorithms, as a list of strings, used to compress the file;
      The only currently available compression option is 'gz' (gzip).

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
  tuf.formats.COMPRESSIONS_SCHEMA.check_match(compressions)
  tuf.formats.BOOLEAN_SCHEMA.check_match(consistent_snapshot)

  # Verify the directory of 'filename', and convert 'filename' to its absolute
  # path so that temporary files are moved to their expected destinations.
  filename = os.path.abspath(filename)
  written_filename = filename
  _check_directory(os.path.dirname(filename))
  consistent_filenames = []

  # Generate the actual metadata file content of 'metadata'.  Metadata is
  # saved as json and includes formatting, such as indentation and sorted
  # objects.  The new digest of 'metadata' is also calculated to help determine
  # if re-saving is required.
  file_content, new_digests = _get_written_metadata_and_digests(metadata)
 
  if consistent_snapshot:
    for new_digest in new_digests.values():
      dirname, basename = os.path.split(filename)
      digest_and_filename = new_digest + '.' + basename
      consistent_filenames.append(os.path.join(dirname, digest_and_filename))
    written_filename = consistent_filenames.pop() 
 
  # Verify whether new metadata needs to be written (i.e., has not been
  # previously written or has changed.
  write_new_metadata = False

  # Has the uncompressed metadata changed?  Does it exist?  If so, set
  # 'write_compressed_version' to True so that it is written.
  # compressed metadata should only be written if it does not exist or the
  # uncompressed version has changed).
  try:
    file_length_junk, old_digests = tuf.util.get_file_details(written_filename)
    if old_digests != new_digests:
      write_new_metadata = True
  
  # 'tuf.Error' raised if 'filename' does not exist.
  except tuf.Error, e:
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
    logger.info('Saving ' + repr(written_filename))
    file_object.move(written_filename)
    
    for consistent_filename in consistent_filenames:
      logger.info('Linking ' + repr(consistent_filename))
      os.link(written_filename, consistent_filename)
   
   
  # Generate the compressed versions of 'metadata', if necessary.  A compressed
  # file may be written (without needing to write the uncompressed version) if
  # the repository maintainer adds compression after writing the uncompressed
  # version.
  for compression in compressions:
    file_object = None 
   
    # Ignore the empty string that signifies non-compression.  The uncompressed
    # file was previously written above, if necessary.
    if not len(compression):
      continue

    elif compression == 'gz':
      file_object = tuf.util.TempFile()
      compressed_filename = filename + '.gz'

      # Instantiate a gzip object, but save compressed content to
      # 'file_object' (i.e., GzipFile instance is based on its 'fileobj'
      # argument).
      with gzip.GzipFile(fileobj=file_object, mode='wb') as gzip_object:
        gzip_object.write(file_content)
    
    else:
      raise tuf.FormatError('Unknown compression algorithm: '+repr(compression))
   
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
  
  except OSError, e:
    if e.errno == errno.EEXIST:
      message = 'Cannot create a fresh client metadata directory: '+ \
        repr(client_metadata_directory)+'.  Already exists.'
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
  # $ python repository_tool.py.
  import doctest
  doctest.testmod()
