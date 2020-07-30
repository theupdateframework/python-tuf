
#!/usr/bin/env python

# Copyright 2013 - 2017, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
<Program Name>
  repository_tool.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  October 19, 2013

<Copyright>
  See LICENSE-MIT OR LICENSE for licensing information.

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
import time
import datetime
import logging
import tempfile
import shutil
import json

from collections import deque

import tuf
import tuf.formats
import tuf.roledb
import tuf.sig
import tuf.log
import tuf.exceptions
import tuf.repository_lib as repo_lib

import securesystemslib.keys
import securesystemslib.formats
import securesystemslib.util
import iso8601
import six

import securesystemslib.storage


# Copy API
# pylint: disable=unused-import

# Copy generic repository API functions to be used via `repository_tool`
from tuf.repository_lib import (
    create_tuf_client_directory,
    disable_console_log_messages)


# Copy key-related API functions to be used via `repository_tool`
from tuf.repository_lib import (
    import_rsa_privatekey_from_file,
    import_ed25519_privatekey_from_file)

from securesystemslib.interface import (
    generate_and_write_rsa_keypair,
    generate_and_write_ecdsa_keypair,
    generate_and_write_ed25519_keypair,
    import_rsa_publickey_from_file,
    import_ecdsa_publickey_from_file,
    import_ed25519_publickey_from_file,
    import_ecdsa_privatekey_from_file)

from securesystemslib.keys import (
    generate_rsa_key,
    generate_ecdsa_key,
    generate_ed25519_key,
    import_rsakey_from_pem,
    import_ecdsakey_from_pem)


# See 'log.py' to learn how logging is handled in TUF.
logger = logging.getLogger(__name__)

# Add a console handler so that users are aware of potentially unintended
# states, such as multiple roles that share keys.
tuf.log.add_console_handler()
tuf.log.set_console_log_level(logging.INFO)

# Recommended RSA key sizes:
# https://en.wikipedia.org/wiki/Key_size#Asymmetric_algorithm_key_lengths
# Based on the above, RSA keys of size 3072 are expected to provide security
# through 2031 and beyond.
DEFAULT_RSA_KEY_BITS=3072

# The default number of hashed bin delegations
DEFAULT_NUM_BINS=1024

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

    storage_backend:
      An object which implements
      securesystemslib.storage.StorageBackendInterface.

    repository_name:
      The name of the repository.  If not supplied, 'rolename' is added to the
      'default' repository.

    use_timestamp_length:
      Whether to include the optional length attribute of the snapshot
      metadata file in the timestamp metadata.
      Default is True.

    use_timestamp_hashes:
      Whether to include the optional hashes attribute of the snapshot
      metadata file in the timestamp metadata.
      Default is True.

    use_snapshot_length:
      Whether to include the optional length attribute for targets
      metadata files in the snapshot metadata.
      Default is False to save bandwidth but without losing security
      from rollback attacks.
      Read more at section 5.6 from the Mercury paper:
      https://www.usenix.org/conference/atc17/technical-sessions/presentation/kuppusamy

    use_snapshot_hashes:
      Whether to include the optional hashes attribute for targets
      metadata files in the snapshot metadata.
      Default is False to save bandwidth but without losing security
      from rollback attacks.
      Read more at section 5.6 from the Mercury paper:
      https://www.usenix.org/conference/atc17/technical-sessions/presentation/kuppusamy

  <Exceptions>
    securesystemslib.exceptions.FormatError, if the arguments are improperly
    formatted.

  <Side Effects>
    Creates top-level role objects and assigns them as attributes.

  <Returns>
    A Repository object that contains default Metadata objects for the top-level
    roles.
  """

  def __init__(self, repository_directory, metadata_directory,
      targets_directory, storage_backend, repository_name='default',
      use_timestamp_length=True, use_timestamp_hashes=True,
      use_snapshot_length=False, use_snapshot_hashes=False):

    # Do the arguments have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.  Raise
    # 'securesystemslib.exceptions.FormatError' if any are improperly formatted.
    securesystemslib.formats.PATH_SCHEMA.check_match(repository_directory)
    securesystemslib.formats.PATH_SCHEMA.check_match(metadata_directory)
    securesystemslib.formats.PATH_SCHEMA.check_match(targets_directory)
    securesystemslib.formats.NAME_SCHEMA.check_match(repository_name)
    securesystemslib.formats.BOOLEAN_SCHEMA.check_match(use_timestamp_length)
    securesystemslib.formats.BOOLEAN_SCHEMA.check_match(use_timestamp_hashes)
    securesystemslib.formats.BOOLEAN_SCHEMA.check_match(use_snapshot_length)
    securesystemslib.formats.BOOLEAN_SCHEMA.check_match(use_snapshot_hashes)

    self._repository_directory = repository_directory
    self._metadata_directory = metadata_directory
    self._targets_directory = targets_directory
    self._repository_name = repository_name
    self._storage_backend = storage_backend
    self._use_timestamp_length = use_timestamp_length
    self._use_timestamp_hashes = use_timestamp_hashes
    self._use_snapshot_length = use_snapshot_length
    self._use_snapshot_hashes = use_snapshot_hashes

    try:
      tuf.roledb.create_roledb(repository_name)
      tuf.keydb.create_keydb(repository_name)

    except securesystemslib.exceptions.InvalidNameError:
      logger.debug(repr(repository_name) + ' already exists.  Overwriting'
          ' its contents.')

    # Set the top-level role objects.
    self.root = Root(self._repository_name)
    self.snapshot = Snapshot(self._repository_name)
    self.timestamp = Timestamp(self._repository_name)
    self.targets = Targets(self._targets_directory, 'targets',
        repository_name=self._repository_name)



  def writeall(self, consistent_snapshot=False, use_existing_fileinfo=False):
    """
    <Purpose>
      Write all the JSON Metadata objects to their corresponding files for
      roles which have changed.
      writeall() raises an exception if any of the role metadata to be written
      to disk is invalid, such as an insufficient threshold of signatures,
      missing private keys, etc.

    <Arguments>
      consistent_snapshot:
        A boolean indicating whether role metadata files should have their
        version numbers as filename prefix when written to disk, i.e
        'VERSION.ROLENAME.json', and target files should be copied to a
        filename that has their hex digest as filename prefix, i.e
        'HASH.FILENAME'. Note that:
        - root metadata is always written with a version prefix, independently
          of 'consistent_snapshot'
        - the latest version of each metadata file is always also written
          without version prefix
        - target files are only copied to a hash-prefixed filename if
          'consistent_snapshot' is True and 'use_existing_fileinfo' is False.
          If both are True hash-prefixed target file copies must be created
          out-of-band.

      use_existing_fileinfo:
        Boolean indicating whether the fileinfo dicts in the roledb should be
        written as-is (True) or whether hashes should be generated (False,
        requires access to the targets files on-disk).

    <Exceptions>
      tuf.exceptions.UnsignedMetadataError, if any of the top-level
      and delegated roles do not have the minimum threshold of signatures.

    <Side Effects>
      Creates metadata files in the repository's metadata directory.

    <Returns>
      None.
    """

    # Do the arguments have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.  Raise
    # 'securesystemslib.exceptions.FormatError' if any are improperly
    # formatted.
    securesystemslib.formats.BOOLEAN_SCHEMA.check_match(consistent_snapshot)

    # At this point, tuf.keydb and tuf.roledb must be fully populated,
    # otherwise writeall() throws a 'tuf.exceptions.UnsignedMetadataError' for
    # the top-level roles.  exception if any of the top-level roles are missing
    # signatures, keys, etc.

    # Write the metadata files of all the Targets roles that are dirty (i.e.,
    # have been modified via roledb.update_roleinfo()).
    filenames = {'root': os.path.join(self._metadata_directory,
        repo_lib.ROOT_FILENAME), 'targets': os.path.join(self._metadata_directory,
        repo_lib.TARGETS_FILENAME), 'snapshot': os.path.join(self._metadata_directory,
        repo_lib.SNAPSHOT_FILENAME), 'timestamp': os.path.join(self._metadata_directory,
        repo_lib.TIMESTAMP_FILENAME)}

    snapshot_signable = None
    dirty_rolenames = tuf.roledb.get_dirty_roles(self._repository_name)

    for dirty_rolename in dirty_rolenames:

      # Ignore top-level roles, they will be generated later in this method.
      if dirty_rolename in tuf.roledb.TOP_LEVEL_ROLES:
        continue

      dirty_filename = os.path.join(self._metadata_directory,
          dirty_rolename + METADATA_EXTENSION)
      repo_lib._generate_and_write_metadata(dirty_rolename, dirty_filename,
          self._targets_directory, self._metadata_directory,
          self._storage_backend, consistent_snapshot, filenames,
          repository_name=self._repository_name,
          use_existing_fileinfo=use_existing_fileinfo)

    # Metadata should be written in (delegated targets -> root -> targets ->
    # snapshot -> timestamp) order.  Begin by generating the 'root.json'
    # metadata file.  _generate_and_write_metadata() raises a
    # 'securesystemslib.exceptions.Error' exception if the metadata cannot be
    # written.
    root_roleinfo = tuf.roledb.get_roleinfo('root', self._repository_name)
    old_consistent_snapshot = root_roleinfo['consistent_snapshot']
    if 'root' in dirty_rolenames or consistent_snapshot != old_consistent_snapshot:
      repo_lib._generate_and_write_metadata('root', filenames['root'],
          self._targets_directory, self._metadata_directory,
          self._storage_backend, consistent_snapshot, filenames,
          repository_name=self._repository_name)

    # Generate the 'targets.json' metadata file.
    if 'targets' in dirty_rolenames:
      repo_lib._generate_and_write_metadata('targets', filenames['targets'],
          self._targets_directory, self._metadata_directory,
          self._storage_backend, consistent_snapshot,
          repository_name=self._repository_name,
          use_existing_fileinfo=use_existing_fileinfo)

    # Generate the 'snapshot.json' metadata file.
    if 'snapshot' in dirty_rolenames:
      snapshot_signable, junk = repo_lib._generate_and_write_metadata('snapshot',
          filenames['snapshot'], self._targets_directory,
          self._metadata_directory, self._storage_backend,
          consistent_snapshot, filenames,
          repository_name=self._repository_name,
          use_snapshot_length=self._use_snapshot_length,
          use_snapshot_hashes=self._use_snapshot_hashes)

    # Generate the 'timestamp.json' metadata file.
    if 'timestamp' in dirty_rolenames:
      repo_lib._generate_and_write_metadata('timestamp', filenames['timestamp'],
          self._targets_directory, self._metadata_directory,
          self._storage_backend, consistent_snapshot,
          filenames, repository_name=self._repository_name,
          use_timestamp_length=self._use_timestamp_length,
          use_timestamp_hashes=self._use_timestamp_hashes)

    tuf.roledb.unmark_dirty(dirty_rolenames, self._repository_name)

    # Delete the metadata of roles no longer in 'tuf.roledb'.  Obsolete roles
    # may have been revoked and should no longer have their metadata files
    # available on disk, otherwise loading a repository may unintentionally
    # load them.
    if snapshot_signable is not None:
      repo_lib._delete_obsolete_metadata(self._metadata_directory,
          snapshot_signable['signed'], consistent_snapshot, self._repository_name,
          self._storage_backend)



  def write(self, rolename, consistent_snapshot=False, increment_version_number=True,
      use_existing_fileinfo=False):
    """
    <Purpose>
      Write the JSON metadata for 'rolename' to its corresponding file on disk.
      Unlike writeall(), write() allows the metadata file to contain an invalid
      threshold of signatures.

    <Arguments>
      rolename:
        The name of the role to be written to disk.

      consistent_snapshot:
        A boolean indicating whether the role metadata file should have its
        version number as filename prefix when written to disk, i.e
        'VERSION.ROLENAME.json'. Note that:
        - root metadata is always written with a version prefix, independently
          of 'consistent_snapshot'
        - the latest version of the metadata file is always also written
          without version prefix
        - if the metadata is targets metadata and 'consistent_snapshot' is
          True, the corresponding target files are copied to a filename with
          their hex digest as filename prefix, i.e 'HASH.FILENAME', unless
          'use_existing_fileinfo' is also True.
          If 'consistent_snapshot' and 'use_existing_fileinfo' both are True,
          hash-prefixed target file copies must be created out-of-band.

      increment_version_number:
        Boolean indicating whether the version number of 'rolename' should be
        automatically incremented.

      use_existing_fileinfo:
        Boolean indicating whether the fileinfo dicts in the roledb should be
        written as-is (True) or whether hashes should be generated (False,
        requires access to the targets files on-disk).

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

    repo_lib._generate_and_write_metadata(rolename, rolename_filename,
        self._targets_directory, self._metadata_directory,
        self._storage_backend, consistent_snapshot,
        filenames=filenames, allow_partially_signed=True,
        increment_version_number=increment_version_number,
        repository_name=self._repository_name,
        use_existing_fileinfo=use_existing_fileinfo)

    # Ensure 'rolename' is no longer marked as dirty after the successful write().
    tuf.roledb.unmark_dirty([rolename], self._repository_name)





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
          metadata_directory, self._repository_name, self._storage_backend)

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

    logger.info('Dirty roles: ' + str(tuf.roledb.get_dirty_roles(self._repository_name)))



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

    tuf.roledb.mark_dirty(roles, self._repository_name)



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

    tuf.roledb.unmark_dirty(roles, self._repository_name)



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
      securesystemslib.exceptions.FormatError, if the arguments are improperly
      formatted.

      securesystemslib.exceptions.Error, if 'file_directory' is not a valid
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
    # 'securesystemslib.exceptions.FormatError' if any are improperly formatted.
    securesystemslib.formats.PATH_SCHEMA.check_match(files_directory)
    securesystemslib.formats.BOOLEAN_SCHEMA.check_match(recursive_walk)
    securesystemslib.formats.BOOLEAN_SCHEMA.check_match(followlinks)

    # Ensure a valid directory is given.
    if not os.path.isdir(files_directory):
      raise securesystemslib.exceptions.Error(repr(files_directory) + ' is not'
        ' a directory.')

    # A list of the target filepaths found in 'files_directory'.
    targets = []

    # FIXME: We need a way to tell Python 2, but not Python 3, to return
    # filenames in Unicode; see #61 and:
    # http://docs.python.org/2/howto/unicode.html#unicode-filenames
    for dirpath, dirnames, filenames in os.walk(files_directory,
                                                followlinks=followlinks):
      for filename in filenames:
        full_target_path = os.path.join(os.path.abspath(dirpath), filename)
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
    attributes, such as rolename, version, threshold, expiration, and key list
    are also provided by the Metadata base class.

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
    self._repository_name = None


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
        'securesystemslib.formats.ANYKEY_SCHEMA'.  Adding a public key to a role
        means that its corresponding private key must generate and add its
        signature to the role.  A threshold number of signatures is required
        for a role to be fully signed.

      expires:
        The date in which 'key' expires.  'expires' is a datetime.datetime()
        object.

    <Exceptions>
      securesystemslib.exceptions.FormatError, if any of the arguments are
      improperly formatted.

      securesystemslib.exceptions.Error, if the 'expires' datetime has already
      expired.

    <Side Effects>
      The role's entries in 'tuf.keydb.py' and 'tuf.roledb.py' are
      updated.

    <Returns>
      None.
    """

    # Does 'key' have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.  Raise
    # 'securesystemslib.exceptions.FormatError' if any are improperly formatted.
    securesystemslib.formats.ANYKEY_SCHEMA.check_match(key)

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
    # Raise 'securesystemslib.exceptions.FormatError' if not.
    if not isinstance(expires, datetime.datetime):
      raise securesystemslib.exceptions.FormatError(repr(expires) + ' is not a'
          ' datetime.datetime() object.')

    # Truncate the microseconds value to produce a correct schema string
    # of the form 'yyyy-mm-ddThh:mm:ssZ'.
    expires = expires.replace(microsecond = 0)

    # Ensure the expiration has not already passed.
    current_datetime = \
      tuf.formats.unix_timestamp_to_datetime(int(time.time()))

    if expires < current_datetime:
      raise securesystemslib.exceptions.Error(repr(key) + ' has already'
          ' expired.')

    # Update the key's 'expires' entry.
    expires = expires.isoformat() + 'Z'
    key['expires'] = expires

    # Ensure 'key', which should contain the public portion, is added to
    # 'tuf.keydb.py'.  Add 'key' to the list of recognized keys.
    # Keys may be shared, so do not raise an exception if 'key' has already
    # been loaded.
    try:
      tuf.keydb.add_key(key, repository_name=self._repository_name)

    except tuf.exceptions.KeyAlreadyExistsError:
      logger.warning('Adding a verification key that has already been used.')

    keyid = key['keyid']
    roleinfo = tuf.roledb.get_roleinfo(self.rolename, self._repository_name)

    # Save the keyids that are being replaced since certain roles will need to
    # re-sign metadata with these keys (e.g., root).  Use list() to make a copy
    # of roleinfo['keyids'] to ensure we're modifying distinct lists.
    previous_keyids = list(roleinfo['keyids'])

    # Add 'key' to the role's entry in 'tuf.roledb.py', and avoid duplicates.
    if keyid not in roleinfo['keyids']:
      roleinfo['keyids'].append(keyid)
      roleinfo['previous_keyids'] = previous_keyids

      tuf.roledb.update_roleinfo(self._rolename, roleinfo,
          repository_name=self._repository_name)



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
        The role's key, conformant to 'securesystemslib.formats.ANYKEY_SCHEMA'.
        'key' should contain only the public portion, as only the public key is
        needed.  The 'add_verification_key()' method should have previously
        added 'key'.

    <Exceptions>
      securesystemslib.exceptions.FormatError, if the 'key' argument is
      improperly formatted.

      securesystemslib.exceptions.Error, if the 'key' argument has not been
      previously added.

    <Side Effects>
      Updates the role's 'tuf.roledb.py' entry.

    <Returns>
      None.
    """

    # Does 'key' have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.  Raise
    # 'securesystemslib.exceptions.FormatError' if any are improperly formatted.
    securesystemslib.formats.ANYKEY_SCHEMA.check_match(key)

    keyid = key['keyid']
    roleinfo = tuf.roledb.get_roleinfo(self.rolename, self._repository_name)

    if keyid in roleinfo['keyids']:
      roleinfo['keyids'].remove(keyid)

      tuf.roledb.update_roleinfo(self._rolename, roleinfo,
          repository_name=self._repository_name)

    else:
      raise securesystemslib.exceptions.Error('Verification key not found.')



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
        The role's key, conformant to 'securesystemslib.formats.ANYKEY_SCHEMA'.
        It must contain the private key, so that role signatures may be
        generated when writeall() or write() is eventually called to generate
        valid metadata files.

    <Exceptions>
      securesystemslib.exceptions.FormatError, if 'key' is improperly formatted.

      securesystemslib.exceptions.Error, if the private key is not found in 'key'.

    <Side Effects>
      Updates the role's 'tuf.keydb.py' and 'tuf.roledb.py' entries.

    <Returns>
      None.
    """

    # Does 'key' have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.  Raise
    # 'securesystemslib.exceptions.FormatError' if any are improperly formatted.
    securesystemslib.formats.ANYKEY_SCHEMA.check_match(key)

    # Ensure the private portion of the key is available, otherwise signatures
    # cannot be generated when the metadata file is written to disk.
    if 'private' not in key['keyval'] or not len(key['keyval']['private']):
      raise securesystemslib.exceptions.Error('This is not a private key.')

    # Has the key, with the private portion included, been added to the keydb?
    # The public version of the key may have been previously added.
    try:
      tuf.keydb.add_key(key, repository_name=self._repository_name)

    except tuf.exceptions.KeyAlreadyExistsError:
      tuf.keydb.remove_key(key['keyid'], self._repository_name)
      tuf.keydb.add_key(key, repository_name=self._repository_name)

    # Update the role's 'signing_keys' field in 'tuf.roledb.py'.
    roleinfo = tuf.roledb.get_roleinfo(self.rolename, self._repository_name)
    if key['keyid'] not in roleinfo['signing_keyids']:
      roleinfo['signing_keyids'].append(key['keyid'])

      tuf.roledb.update_roleinfo(self.rolename, roleinfo,
          repository_name=self._repository_name)



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
        'securesystemslib.formats.ANYKEY_SCHEMA'.

    <Exceptions>
      securesystemslib.exceptions.FormatError, if the 'key' argument is
      improperly formatted.

      securesystemslib.exceptions.Error, if the 'key' argument has not been
      previously loaded.

    <Side Effects>
      Updates the signing keys of the role in 'tuf.roledb.py'.

    <Returns>
      None.
    """

    # Does 'key' have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.  Raise
    # 'securesystemslib.exceptions.FormatError' if any are improperly formatted.
    securesystemslib.formats.ANYKEY_SCHEMA.check_match(key)

    # Update the role's 'signing_keys' field in 'tuf.roledb.py'.
    roleinfo = tuf.roledb.get_roleinfo(self.rolename, self._repository_name)

    # TODO: Should we consider removing keys from keydb that are no longer
    # associated with any roles?  There could be many no-longer-used keys
    # stored in the keydb if not.  For now, just unload the key.
    if key['keyid'] in roleinfo['signing_keyids']:
      roleinfo['signing_keyids'].remove(key['keyid'])

      tuf.roledb.update_roleinfo(self.rolename, roleinfo,
          repository_name=self._repository_name)

    else:
      raise securesystemslib.exceptions.Error('Signing key not found.')



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
        'securesystemslib.formats.SIGNATURE_SCHEMA'.

      mark_role_as_dirty:
        A boolean indicating whether the updated 'roleinfo' for 'rolename'
        should be marked as dirty.  The caller might not want to mark
        'rolename' as dirty if it is loading metadata from disk and only wants
        to populate roledb.py.  Likewise, add_role() would support a similar
        boolean to allow the repository tools to successfully load roles via
        load_repository() without needing to mark these roles as dirty (default
        behavior).

    <Exceptions>
      securesystemslib.exceptions.FormatError, if the 'signature' argument is
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
    # 'securesystemslib.exceptions.FormatError' if any are improperly formatted.
    securesystemslib.formats.SIGNATURE_SCHEMA.check_match(signature)
    securesystemslib.formats.BOOLEAN_SCHEMA.check_match(mark_role_as_dirty)

    roleinfo = tuf.roledb.get_roleinfo(self.rolename, self._repository_name)

    # Ensure the roleinfo contains a 'signatures' field.
    if 'signatures' not in roleinfo:
      roleinfo['signatures'] = []

    # Update the role's roleinfo by adding 'signature', if it has not been
    # added.
    if signature not in roleinfo['signatures']:
      roleinfo['signatures'].append(signature)
      tuf.roledb.update_roleinfo(self.rolename, roleinfo, mark_role_as_dirty,
          repository_name=self._repository_name)

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
        'securesystemslib.formats.SIGNATURE_SCHEMA'.

    <Exceptions>
      securesystemslib.exceptions.FormatError, if the 'signature' argument is
      improperly formatted.

      securesystemslib.exceptions.Error, if 'signature' has not been previously
      added to this role.

    <Side Effects>
      Updates the 'signatures' field of the role in 'tuf.roledb.py'.

    <Returns>
      None.
    """

    # Does 'signature' have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.  Raise
    # 'securesystemslib.exceptions.FormatError' if any are improperly formatted.
    securesystemslib.formats.SIGNATURE_SCHEMA.check_match(signature)

    roleinfo = tuf.roledb.get_roleinfo(self.rolename, self._repository_name)

    if signature in roleinfo['signatures']:
      roleinfo['signatures'].remove(signature)

      tuf.roledb.update_roleinfo(self.rolename, roleinfo,
          repository_name=self._repository_name)

    else:
      raise securesystemslib.exceptions.Error('Signature not found.')



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
      'securesystemslib.formats.SIGNATURES_SCHEMA'.
    """

    roleinfo = tuf.roledb.get_roleinfo(self.rolename, self._repository_name)
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

    roleinfo = tuf.roledb.get_roleinfo(self.rolename, self._repository_name)
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
      The role's version number, conformant to
      'tuf.formats.VERSION_SCHEMA'.
    """

    roleinfo = tuf.roledb.get_roleinfo(self.rolename, self._repository_name)
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
        'tuf.formats.VERSION_SCHEMA'.

    <Exceptions>
      securesystemslib.exceptions.FormatError, if the 'version' argument is
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
    # 'securesystemslib.exceptions.FormatError' if any are improperly formatted.
    tuf.formats.METADATAVERSION_SCHEMA.check_match(version)

    roleinfo = tuf.roledb.get_roleinfo(self.rolename, self._repository_name)
    roleinfo['version'] = version

    tuf.roledb.update_roleinfo(self._rolename, roleinfo,
        repository_name=self._repository_name)



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
      'tuf.formats.THRESHOLD_SCHEMA'.
    """

    roleinfo = tuf.roledb.get_roleinfo(self._rolename, self._repository_name)
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
        An integer value that sets the role's threshold value, or the minimum
        number of signatures needed for metadata to be considered fully
        signed.  Conformant to 'tuf.formats.THRESHOLD_SCHEMA'.

    <Exceptions>
      securesystemslib.exceptions.FormatError, if the 'threshold' argument is
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
    # 'securesystemslib.exceptions.FormatError' if any are improperly formatted.
    tuf.formats.THRESHOLD_SCHEMA.check_match(threshold)

    roleinfo = tuf.roledb.get_roleinfo(self._rolename, self._repository_name)
    roleinfo['previous_threshold'] = roleinfo['threshold']
    roleinfo['threshold'] = threshold

    tuf.roledb.update_roleinfo(self._rolename, roleinfo,
        repository_name=self._repository_name)


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

    roleinfo = tuf.roledb.get_roleinfo(self.rolename, self._repository_name)
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
      securesystemslib.exceptions.FormatError, if 'datetime_object' is not a
      datetime.datetime() object.

      securesystemslib.exceptions.Error, if 'datetime_object' has already
      expired.

    <Side Effects>
      Modifies the expiration attribute of the Repository object.
      The datetime given will be truncated to microseconds = 0

    <Returns>
      None.
    """

    # Is 'datetime_object' a datetime.datetime() object?
    # Raise 'securesystemslib.exceptions.FormatError' if not.
    if not isinstance(datetime_object, datetime.datetime):
      raise securesystemslib.exceptions.FormatError(
          repr(datetime_object) + ' is not a datetime.datetime() object.')

    # truncate the microseconds value to produce a correct schema string
    # of the form yyyy-mm-ddThh:mm:ssZ
    datetime_object = datetime_object.replace(microsecond = 0)

    # Ensure the expiration has not already passed.
    current_datetime_object = \
      tuf.formats.unix_timestamp_to_datetime(int(time.time()))

    if datetime_object < current_datetime_object:
      raise securesystemslib.exceptions.Error(repr(self.rolename) + ' has'
        ' already expired.')

    # Update the role's 'expires' entry in 'tuf.roledb.py'.
    roleinfo = tuf.roledb.get_roleinfo(self.rolename, self._repository_name)
    expires = datetime_object.isoformat() + 'Z'
    roleinfo['expires'] = expires

    tuf.roledb.update_roleinfo(self.rolename, roleinfo,
        repository_name=self._repository_name)



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
      'securesystemslib.formats.KEYIDS_SCHEMA'.
    """

    roleinfo = tuf.roledb.get_roleinfo(self.rolename, self._repository_name)
    signing_keyids = roleinfo['signing_keyids']

    return signing_keyids





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
    repository_name:
      The name of the repository.  If not supplied, 'rolename' is added to the
      'default' repository.

  <Exceptions>
    tuf.exceptions.FormatError, if the argument is improperly formatted.

  <Side Effects>
    A 'root' role is added to 'tuf.roledb.py'.

  <Returns>
    None.
  """

  def __init__(self, repository_name):

    super(Root, self).__init__()

    self._rolename = 'root'
    self._repository_name = repository_name

    # Is 'repository_name' properly formatted?  Otherwise, raise a
    # tuf.exceptions.FormatError exception.
    tuf.formats.ROLENAME_SCHEMA.check_match(repository_name)

    # By default, 'snapshot' metadata is set to expire 1 week from the current
    # time.  The expiration may be modified.
    expiration = tuf.formats.unix_timestamp_to_datetime(
        int(time.time() + ROOT_EXPIRATION))
    expiration = expiration.isoformat() + 'Z'

    roleinfo = {'keyids': [], 'signing_keyids': [], 'threshold': 1,
                'signatures': [], 'version': 0, 'consistent_snapshot': False,
                'expires': expiration, 'partial_loaded': False}
    try:
      tuf.roledb.add_role(self._rolename, roleinfo, self._repository_name)

    except tuf.exceptions.RoleAlreadyExistsError:
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
    repository_name:
      The name of the repository.  If not supplied, 'rolename' is added to the
      'default' repository.

  <Exceptions>
    tuf.exceptions.FormatError, if the argument is improperly formatted.

  <Side Effects>
    A 'timestamp' role is added to 'tuf.roledb.py'.

  <Returns>
    None.
  """

  def __init__(self, repository_name):

    super(Timestamp, self).__init__()

    self._rolename = 'timestamp'
    self._repository_name = repository_name

    # Is 'repository_name' properly formatted?  Otherwise, raise a
    # tuf.exceptions.FormatError exception.
    securesystemslib.formats.NAME_SCHEMA.check_match(repository_name)

    # By default, 'root' metadata is set to expire 1 year from the current
    # time.  The expiration may be modified.
    expiration = tuf.formats.unix_timestamp_to_datetime(
        int(time.time() + TIMESTAMP_EXPIRATION))
    expiration = expiration.isoformat() + 'Z'

    roleinfo = {'keyids': [], 'signing_keyids': [], 'threshold': 1,
                'signatures': [], 'version': 0, 'expires': expiration,
                'partial_loaded': False}

    try:
      tuf.roledb.add_role(self.rolename, roleinfo, self._repository_name)

    except tuf.exceptions.RoleAlreadyExistsError:
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
    repository_name:
      The name of the repository.  If not supplied, 'rolename' is added to the
      'default' repository.

  <Exceptions>
    tuf.exceptions.FormatError, if the argument is improperly formatted.

  <Side Effects>
    A 'snapshot' role is added to 'tuf.roledb.py'.

  <Returns>
    None.
  """

  def __init__(self, repository_name):

    super(Snapshot, self).__init__()

    self._rolename = 'snapshot'
    self._repository_name = repository_name

    # Is 'repository_name' properly formatted?  Otherwise, raise a
    # tuf.exceptions.FormatError exception.
    securesystemslib.formats.NAME_SCHEMA.check_match(repository_name)

    # By default, 'snapshot' metadata is set to expire 1 week from the current
    # time.  The expiration may be modified.
    expiration = tuf.formats.unix_timestamp_to_datetime(
        int(time.time() + SNAPSHOT_EXPIRATION))
    expiration = expiration.isoformat() + 'Z'

    roleinfo = {'keyids': [], 'signing_keyids': [], 'threshold': 1,
                'signatures': [], 'version': 0, 'expires': expiration,
                'partial_loaded': False}

    try:
      tuf.roledb.add_role(self._rolename, roleinfo, self._repository_name)

    except tuf.exceptions.RoleAlreadyExistsError:
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
      'tuf.formats.ROLEDB_SCHEMA'.

    repository_name:
      The name of the repository.  If not supplied, 'rolename' is added to the
      'default' repository.

  <Exceptions>
    securesystemslib.exceptions.FormatError, if the arguments are improperly
    formatted.

  <Side Effects>
    Modifies the roleinfo of the targets role in 'tuf.roledb', or creates
    a default one named 'targets'.

  <Returns>
    None.
  """

  def __init__(self, targets_directory, rolename='targets', roleinfo=None,
               parent_targets_object=None, repository_name='default'):

    # Do the arguments have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.  Raise
    # 'securesystemslib.exceptions.FormatError' if any are improperly formatted.
    securesystemslib.formats.PATH_SCHEMA.check_match(targets_directory)
    tuf.formats.ROLENAME_SCHEMA.check_match(rolename)
    securesystemslib.formats.NAME_SCHEMA.check_match(repository_name)

    if roleinfo is not None:
      tuf.formats.ROLEDB_SCHEMA.check_match(roleinfo)

    super(Targets, self).__init__()
    self._targets_directory = targets_directory
    self._rolename = rolename
    self._target_files = []
    self._delegated_roles = {}
    self._parent_targets_object = self
    self._repository_name = repository_name

    # Keep a reference to the top-level 'targets' object.  Any delegated roles
    # that may be created, can be added to and accessed via the top-level
    # 'targets' object.
    if parent_targets_object is not None:
      self._parent_targets_object = parent_targets_object

    # By default, Targets objects are set to expire 3 months from the current
    # time.  May be later modified.
    expiration = tuf.formats.unix_timestamp_to_datetime(
        int(time.time() + TARGETS_EXPIRATION))
    expiration = expiration.isoformat() + 'Z'

    # If 'roleinfo' is not provided, set an initial default.
    if roleinfo is None:
      roleinfo = {'keyids': [], 'signing_keyids': [], 'threshold': 1,
                  'version': 0, 'expires': expiration,
                  'signatures': [], 'paths': {}, 'path_hash_prefixes': [],
                  'partial_loaded': False, 'delegations': {'keys': {},
                                                           'roles': []}}

    # Add the new role to the 'tuf.roledb'.
    try:
      tuf.roledb.add_role(self.rolename, roleinfo, self._repository_name)

    except tuf.exceptions.RoleAlreadyExistsError:
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
      securesystemslib.exceptions.FormatError, if the arguments are improperly
      formatted.

      tuf.exceptions.UnknownRoleError, if 'rolename' has not been
      delegated by this Targets object.

    <Side Effects>
      Modifies the roleinfo of the targets role in 'tuf.roledb'.

    <Returns>
      The Targets object of 'rolename'.
    """

    # Do the arguments have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.  Raise
    # 'securesystemslib.exceptions.FormatError' if any are improperly formatted.
    tuf.formats.ROLENAME_SCHEMA.check_match(rolename)

    if rolename in self._delegated_roles:
      return self._delegated_roles[rolename]

    else:
      raise tuf.exceptions.UnknownRoleError(repr(rolename) + ' has'
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
      securesystemslib.exceptions.FormatError, if the arguments are improperly
      formatted.

    <Side Effects>
      Updates the Target object's dictionary of delegated targets.

    <Returns>
      The Targets object of 'rolename'.
    """

    # Do the arguments have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.  Raise
    # 'securesystemslib.exceptions.FormatError' if any are improperly formatted.
    tuf.formats.ROLENAME_SCHEMA.check_match(rolename)

    if not isinstance(targets_object, Targets):
      raise securesystemslib.exceptions.FormatError(repr(targets_object) + ' is'
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
      securesystemslib.exceptions.FormatError, if the argument is improperly
      formatted.

    <Side Effects>
      Updates the Target object's dictionary of delegated targets.

    <Returns>
      None.
    """

    # Do the arguments have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.  Raise
    # 'securesystemslib.exceptions.FormatError' if any are improperly formatted.
    tuf.formats.ROLENAME_SCHEMA.check_match(rolename)

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

    target_files = tuf.roledb.get_roleinfo(self._rolename,
        self._repository_name)['paths']
    return target_files



  def add_paths(self, paths, child_rolename):
    """
    <Purpose>
      Add 'paths' to the delegated paths of 'child_rolename'.  'paths' can be a
      list of either file paths or glob patterns.  The updater client verifies
      the target paths specified by child roles, and searches for targets by
      visiting these delegated paths.  A child role may only provide targets
      specifically listed in the delegations field of the delegating role, or a
      target that matches a delegated path.

      >>>
      >>>
      >>>

    <Arguments>
      paths:
        A list of glob patterns, or file paths, that 'child_rolename' is
        trusted to provide.

      child_rolename:
        The child delegation that requires an update to its delegated or
        trusted paths, as listed in the parent role's delegations (e.g.,
        'Django' in 'unclaimed').

    <Exceptions>
      securesystemslib.exceptions.FormatError, if a path or glob pattern in
      'paths' is not a string, or if 'child_rolename' is not a formatted
      rolename.

      securesystemslib.exceptions.Error, if 'child_rolename' has not been
      delegated yet.

      tuf.exceptions.InvalidNameError, if any path in 'paths' does not match
      pattern.

    <Side Effects>
      Modifies this Targets' delegations field.

    <Returns>
      None.
    """

    # Do the argument have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.
    # Raise 'securesystemslib.exceptions.FormatError' if there is a mismatch.
    securesystemslib.formats.PATHS_SCHEMA.check_match(paths)
    tuf.formats.ROLENAME_SCHEMA.check_match(child_rolename)

    # Ensure that 'child_rolename' exists, otherwise it will not have an entry
    # in the parent role's delegations field.
    if not tuf.roledb.role_exists(child_rolename, self._repository_name):
      raise securesystemslib.exceptions.Error(repr(child_rolename) + ' does'
          ' not exist.')

    for path in paths:
      # Check if the delegated paths or glob patterns are relative and use
      # forward slash as a separator or raise an exception. Paths' existence
      # on the file system is not verified. If the path is incorrect,
      # the targetfile won't be matched successfully during a client update.
      self._check_path(path)

    # Get the current role's roleinfo, so that its delegations field can be
    # updated.
    roleinfo = tuf.roledb.get_roleinfo(self._rolename, self._repository_name)

    # Update the delegated paths of 'child_rolename' to add relative paths.
    for role in roleinfo['delegations']['roles']:
      if role['name'] == child_rolename:
        for relative_path in paths:
          if relative_path not in role['paths']:
            role['paths'].append(relative_path)

          else:
            logger.debug(repr(relative_path) + ' is already a delegated path.')
      else:
        logger.debug(repr(role['name']) + ' does not match child rolename.')

    tuf.roledb.update_roleinfo(self._rolename, roleinfo,
        repository_name=self._repository_name)



  def add_target(self, filepath, custom=None, fileinfo=None):
    """
    <Purpose>
      Add a filepath (must be relative to the repository's targets directory)
      to the Targets object.

      If 'filepath' has already been added, it will be replaced with any new
      file or 'custom' information.

      >>>
      >>>
      >>>

    <Arguments>
      filepath:
        The path of the target file.  It must be relative to the repository's
        targets directory.

      custom:
        An optional dictionary providing additional information about the file.
        NOTE: if a custom value is passed, the fileinfo parameter must be None.
        This parameter will be deprecated in a future release of tuf, use of
        the fileinfo parameter is preferred.

      fileinfo:
        An optional fileinfo dictionary, conforming to
        tuf.formats.TARGETS_FILEINFO_SCHEMA, providing full information about the
        file, i.e:
          { 'length': 101,
            'hashes': { 'sha256': '123EDF...' },
            'custom': { 'permissions': '600'} # optional
          }
        NOTE: if a custom value is passed, the fileinfo parameter must be None.

    <Exceptions>
      securesystemslib.exceptions.FormatError, if 'filepath' is improperly
      formatted.

      tuf.exceptions.InvalidNameError, if 'filepath' does not match pattern.

    <Side Effects>
      Adds 'filepath' to this role's list of targets.  This role's
      'tuf.roledb.py' entry is also updated.

    <Returns>
      None.
    """

    # Does 'filepath' have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.  Raise
    # 'securesystemslib.exceptions.FormatError' if there is a mismatch.
    tuf.formats.RELPATH_SCHEMA.check_match(filepath)

    if fileinfo and custom:
      raise securesystemslib.exceptions.Error("Can only take one of"
          " custom or fileinfo, not both.")

    if fileinfo:
      tuf.formats.TARGETS_FILEINFO_SCHEMA.check_match(fileinfo)

    if custom is None:
      custom = {}
    else:
      tuf.formats.CUSTOM_SCHEMA.check_match(custom)

    # Add 'filepath' (i.e., relative to the targets directory) to the role's
    # list of targets.  'filepath' will not be verified as an allowed path
    # according to some delegating role.  Not verifying 'filepath' here allows
    # freedom to add targets and parent restrictions in any order, minimize
    # the number of times these checks are performed, and allow any role to
    # delegate trust of packages to this Targets role.

    # Check if the target is relative and uses forward slash as a separator
    # or raise an exception. File's existence on the file system is not
    # verified. If the file does not exist relative to the targets directory,
    # later calls to write() will fail.
    self._check_path(filepath)

    # Update the role's 'tuf.roledb.py' entry and avoid duplicates.
    roleinfo = tuf.roledb.get_roleinfo(self._rolename, self._repository_name)

    if filepath not in roleinfo['paths']:
      logger.debug('Adding new target: ' + repr(filepath))

    else:
      logger.debug('Replacing target: ' + repr(filepath))

    if fileinfo:
      roleinfo['paths'].update({filepath: fileinfo})
    else:
      roleinfo['paths'].update({filepath: {'custom': custom}})

    tuf.roledb.update_roleinfo(self._rolename, roleinfo,
        repository_name=self._repository_name)



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
      securesystemslib.exceptions.FormatError, if the arguments are improperly
      formatted.

      tuf.exceptions.InvalidNameError, if any target in 'list_of_targets'
      does not match pattern.

    <Side Effects>
      This Targets' roleinfo is updated with the paths in 'list_of_targets'.

    <Returns>
      None.
    """

    # Does 'list_of_targets' have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.
    # Raise 'securesystemslib.exceptions.FormatError' if there is a mismatch.
    tuf.formats.RELPATHS_SCHEMA.check_match(list_of_targets)

    # Ensure the paths in 'list_of_targets' are relative and use forward slash
    # as a separator or raise an exception. The paths of 'list_of_targets'
    # will be verified as existing and allowed paths according to this Targets
    # parent role when write() or writeall() is called.  Not verifying
    # filepaths here allows the freedom to add targets and parent restrictions
    # in any order and minimize the number of times these checks are performed.
    for target in list_of_targets:
      self._check_path(target)

    # Update this Targets 'tuf.roledb.py' entry.
    roleinfo = tuf.roledb.get_roleinfo(self._rolename, self._repository_name)
    for relative_target in list_of_targets:
      if relative_target not in roleinfo['paths']:
        logger.debug('Adding new target: ' + repr(relative_target))
      else:
        logger.debug('Replacing target: ' + repr(relative_target))
      roleinfo['paths'].update({relative_target: {}})

    tuf.roledb.update_roleinfo(self.rolename, roleinfo,
        repository_name=self._repository_name)



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
      securesystemslib.exceptions.FormatError, if 'filepath' is improperly
      formatted.

      securesystemslib.exceptions.Error, if 'filepath' is not located in the
      repository's targets directory, or not found.

    <Side Effects>
      Modifies this Targets 'tuf.roledb.py' entry.

    <Returns>
      None.
    """

    # Does 'filepath' have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.  Raise
    # 'securesystemslib.exceptions.FormatError' if there is a mismatch.
    tuf.formats.RELPATH_SCHEMA.check_match(filepath)

    # Remove 'relative_filepath', if found, and update this Targets roleinfo.
    fileinfo = tuf.roledb.get_roleinfo(self.rolename, self._repository_name)
    if filepath in fileinfo['paths']:
      del fileinfo['paths'][filepath]
      tuf.roledb.update_roleinfo(self.rolename, fileinfo,
          repository_name=self._repository_name)

    else:
      raise securesystemslib.exceptions.Error('Target file path not found.')



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

    roleinfo = tuf.roledb.get_roleinfo(self.rolename, self._repository_name)
    roleinfo['paths'] = {}

    tuf.roledb.update_roleinfo(self.rolename, roleinfo,
        repository_name=self._repository_name)





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

    return tuf.roledb.get_delegated_rolenames(self.rolename, self._repository_name)





  def _create_delegated_target(self, rolename, keyids, threshold, paths):
    """
    Create a new Targets object for the 'rolename' delegation.  An initial
    expiration is set (3 months from the current time).
    """

    expiration = tuf.formats.unix_timestamp_to_datetime(
        int(time.time() + TARGETS_EXPIRATION))
    expiration = expiration.isoformat() + 'Z'

    roleinfo = {'name': rolename, 'keyids': keyids, 'signing_keyids': [],
                'threshold': threshold, 'version': 0,
                'expires': expiration, 'signatures': [], 'partial_loaded': False,
                'paths': paths, 'delegations': {'keys': {}, 'roles': []}}

    # The new targets object is added as an attribute to this Targets object.
    new_targets_object = Targets(self._targets_directory, rolename, roleinfo,
        parent_targets_object=self._parent_targets_object,
        repository_name=self._repository_name)

    return new_targets_object





  def _update_roledb_delegations(self, keydict, delegations_roleinfo):
    """
    Update the roledb to include delegations of the keys in keydict and the
    roles in delegations_roleinfo
    """

    current_roleinfo = tuf.roledb.get_roleinfo(self.rolename, self._repository_name)
    current_roleinfo['delegations']['keys'].update(keydict)

    for roleinfo in delegations_roleinfo:
      current_roleinfo['delegations']['roles'].append(roleinfo)

    tuf.roledb.update_roleinfo(self.rolename, current_roleinfo,
        repository_name=self._repository_name)





  def delegate(self, rolename, public_keys, paths, threshold=1,
      terminating=False, list_of_targets=None, path_hash_prefixes=None):
    """
    <Purpose>
      Create a new delegation, where 'rolename' is a child delegation of this
      Targets object.  The keys and roles database is updated, including the
      delegations field of this Targets.  The delegation of 'rolename' is added
      and accessible (i.e., repository.targets(rolename)).

      Actual metadata files are not created, only when repository.writeall() or
      repository.write() is called.

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

      paths:
        The paths, or glob patterns, delegated to 'rolename'.  Any targets
        added to 'rolename', via add_targets() or 'list_of_targets', must
        match one of the paths or glob patterns in 'paths'.  Apart from the
        public keys of 'rolename', the delegated 'paths' is often known and
        specified when a delegation is first performed.  If the delegator
        is unsure of which 'paths' to delegate, 'paths' can be set to [''].

      threshold:
        The threshold number of keys of 'rolename'.

      terminating:
        Boolean that indicates whether this role allows the updater client to
        continue searching for targets (target files it is trusted to list but
        has not yet specified) in other delegations.  If 'terminating' is True
        and 'updater.target()' does not find 'example_target.tar.gz' in this
        role, a 'tuf.exceptions.UnknownTargetError' exception should be raised.
        If 'terminating' is False (default), and 'target/other_role' is also
        trusted with 'example_target.tar.gz' and has listed it,
        updater.target() should backtrack and return the target file specified
        by 'target/other_role'.

      list_of_targets:
        A list of target filepaths that are added to 'rolename'.
        'list_of_targets' is a list of target filepaths, can be empty, and each
        filepath must be located in the repository's targets directory.  The
        list of targets should also exist at the specified paths, otherwise
        non-existent target paths might not be added when the targets file is
        written to disk with writeall() or write().

      path_hash_prefixes:
        A list of hash prefixes in
        'tuf.formats.PATH_HASH_PREFIXES_SCHEMA' format, used in
        hashed bin delegations.  Targets may be located and stored in hashed
        bins by calculating the target path's hash prefix.

    <Exceptions>
      securesystemslib.exceptions.FormatError, if any of the arguments are
      improperly formatted.

      securesystemslib.exceptions.Error, if the delegated role already exists.

      tuf.exceptions.InvalidNameError, if any path in 'paths' or target in
      'list_of_targets' does not match pattern.

    <Side Effects>
      A new Target object is created for 'rolename' that is accessible to the
      caller (i.e., targets.<rolename>).  The 'tuf.keydb.py' and
      'tuf.roledb.py' stores are updated with 'public_keys'.

    <Returns>
      None.
    """

    # Do the arguments have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.
    # Raise 'securesystemslib.exceptions.FormatError' if there is a mismatch.
    tuf.formats.ROLENAME_SCHEMA.check_match(rolename)
    securesystemslib.formats.ANYKEYLIST_SCHEMA.check_match(public_keys)
    tuf.formats.RELPATHS_SCHEMA.check_match(paths)
    tuf.formats.THRESHOLD_SCHEMA.check_match(threshold)
    securesystemslib.formats.BOOLEAN_SCHEMA.check_match(terminating)

    if list_of_targets is not None:
      tuf.formats.RELPATHS_SCHEMA.check_match(list_of_targets)

    if path_hash_prefixes is not None:
      tuf.formats.PATH_HASH_PREFIXES_SCHEMA.check_match(path_hash_prefixes)

    # Keep track of the valid keyids (added to the new Targets object) and
    # their keydicts (added to this Targets delegations).
    keyids, keydict = _keys_to_keydict(public_keys)

    # Ensure the paths of 'list_of_targets' are located in the repository's
    # targets directory.
    relative_targetpaths = {}

    if list_of_targets:
      for target in list_of_targets:
        # Check if the target path is relative or raise an exception. File's
        # existence on the file system is not verified. If the file does not
        # exist relative to the targets directory, later calls to write()
        # will fail.
        self._check_path(target)
        relative_targetpaths.update({target: {}})

    for path in paths:
      # Check if the delegated paths or glob patterns are relative or
      # raise an exception. Paths' existence on the file system is not
      # verified. If the path is incorrect, the targetfile won't be matched
      # successfully during a client update.
      self._check_path(path)

    # The new targets object is added as an attribute to this Targets object.
    new_targets_object = self._create_delegated_target(rolename, keyids,
        threshold, relative_targetpaths)

    # Update the roleinfo of this role.  A ROLE_SCHEMA object requires only
    # 'keyids', 'threshold', and 'paths'.
    roleinfo = {'name': rolename,
                'keyids': keyids,
                'threshold': threshold,
                'terminating': terminating,
                'paths': list(relative_targetpaths.keys())}

    if paths:
      roleinfo['paths'] = paths

    if path_hash_prefixes:
      roleinfo['path_hash_prefixes'] = path_hash_prefixes
      # A role in a delegations must list either 'path_hash_prefixes'
      # or 'paths'.
      del roleinfo['paths']

    # Update the public keys of 'new_targets_object'.
    for key in public_keys:
      new_targets_object.add_verification_key(key)

    # Add the new delegation to the top-level 'targets' role object (i.e.,
    # 'repository.targets()').  For example, 'django', which was delegated by
    # repository.target('claimed'), is added to 'repository.targets('django')).
    if self.rolename != 'targets':
      self._parent_targets_object.add_delegated_role(rolename,
          new_targets_object)

    # Add 'new_targets_object' to the delegating role object (this object).
    self.add_delegated_role(rolename, new_targets_object)

    # Update the 'delegations' field of the current role.
    self._update_roledb_delegations(keydict, [roleinfo])





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
      securesystemslib.exceptions.FormatError, if 'rolename' is improperly
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
    # Raise 'securesystemslib.exceptions.FormatError' if there is a mismatch.
    tuf.formats.ROLENAME_SCHEMA.check_match(rolename)

    # Remove 'rolename' from this Target's delegations dict.
    roleinfo = tuf.roledb.get_roleinfo(self.rolename, self._repository_name)

    for role in roleinfo['delegations']['roles']:
      if role['name'] == rolename:
        roleinfo['delegations']['roles'].remove(role)

    tuf.roledb.update_roleinfo(self.rolename, roleinfo,
        repository_name=self._repository_name)

    # Remove 'rolename' from 'tuf.roledb.py'.
    try:
      tuf.roledb.remove_role(rolename, self._repository_name)
      # Remove the rolename delegation from the current role.  For example, the
      # 'django' role is removed from repository.targets('django').
      del self._delegated_roles[rolename]
      self._parent_targets_object.remove_delegated_role(rolename)

    except (tuf.exceptions.UnknownRoleError, KeyError):
      pass



  def delegate_hashed_bins(self, list_of_targets, keys_of_hashed_bins,
      number_of_bins=DEFAULT_NUM_BINS):
    """
    <Purpose>
      Distribute a large number of target files over multiple delegated roles
      (hashed bins).  The metadata files of delegated roles will be nearly
      equal in size (i.e., 'list_of_targets' is uniformly distributed by
      calculating the target filepath's hash and determining which bin it should
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
      securesystemslib.exceptions.FormatError, if the arguments are improperly
      formatted.

      securesystemslib.exceptions.Error, if 'number_of_bins' is not a power of
      2, or one of the targets in 'list_of_targets' is not relative to the
      repository's targets directory.

      tuf.exceptions.InvalidNameError, if any target in 'list_of_targets'
      does not match pattern.

    <Side Effects>
      Delegates multiple target roles from the current parent role.

    <Returns>
      None.
    """

    # Do the arguments have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.
    # Raise 'securesystemslib.exceptions.FormatError' if there is a mismatch.
    securesystemslib.formats.PATHS_SCHEMA.check_match(list_of_targets)
    securesystemslib.formats.ANYKEYLIST_SCHEMA.check_match(keys_of_hashed_bins)
    tuf.formats.NUMBINS_SCHEMA.check_match(number_of_bins)

    prefix_length, prefix_count, bin_size = repo_lib.get_bin_numbers(number_of_bins)

    logger.info('Creating hashed bin delegations.\n' +
        repr(len(list_of_targets)) + ' total targets.\n' +
        repr(number_of_bins) + ' hashed bins.\n' +
        repr(prefix_count) + ' total hash prefixes.\n' +
        'Each bin ranges over ' + repr(bin_size) + ' hash prefixes.')

    # Generate a list of bin names, the range of prefixes to be delegated to
    # that bin, along with the corresponding full list of target prefixes
    # to be delegated to that bin
    ordered_roles = []
    for idx in range(0, prefix_count, bin_size):
      high = idx + bin_size - 1
      name = repo_lib.create_bin_name(idx, high, prefix_length)
      if bin_size == 1:
        target_hash_prefixes = [name]
      else:
        target_hash_prefixes = []
        for idy in range(idx, idx+bin_size):
          target_hash_prefixes.append("{prefix:0{len}x}".format(prefix=idy,
              len=prefix_length))

      role = {"name": name,
          "target_paths": [],
          "target_hash_prefixes": target_hash_prefixes}
      ordered_roles.append(role)

    for target_path in list_of_targets:
      # Check if the target path is relative or raise an exception. File's
      # existence on the file system is not verified. If the file does not
      # exist relative to the targets directory, later calls to write() and
      # writeall() will fail.
      self._check_path(target_path)

      # Determine the hash prefix of 'target_path' by computing the digest of
      # its path relative to the targets directory.
      # We must hash a target path as it appears in the metadata
      hash_prefix = repo_lib.get_target_hash(target_path)[:prefix_length]
      ordered_roles[int(hash_prefix, 16) // bin_size]["target_paths"].append(target_path)

    keyids, keydict = _keys_to_keydict(keys_of_hashed_bins)

    # A queue of roleinfo's that need to be updated in the roledb
    delegated_roleinfos = []

    for bin_role in ordered_roles:
      # TODO: originally we just called self.delegate() for each item in this
      # iteration. However, this is *extremely* slow when creating a large
      # number of hashed bins, i.e. 16k as is recommended for PyPI usage in
      # PEP 458: https://www.python.org/dev/peps/pep-0458/
      # The source of the slowness is the interactions with the roledb, which
      # causes several deep copies of roleinfo dictionaries:
      # https://github.com/theupdateframework/tuf/issues/1005
      # Once the underlying issues in #1005 are resolved, i.e. some combination
      # of the intermediate and long-term fixes, we may simplify here by
      # switching back to just calling self.delegate(), but until that time we
      # queue roledb interactions and perform all updates to the roledb in one
      # operation at the end of the iteration.

      relative_paths = {}
      for path in bin_role['target_paths']:
        relative_paths.update({path: {}})

      # Delegate from the "unclaimed" targets role to each 'bin_role'
      target = self._create_delegated_target(bin_role['name'], keyids, 1,
          relative_paths)

      roleinfo = {'name': bin_role['name'],
                  'keyids': keyids,
                  'threshold': 1,
                  'terminating': False,
                  'path_hash_prefixes': bin_role['target_hash_prefixes']}
      delegated_roleinfos.append(roleinfo)

      for key in keys_of_hashed_bins:
        target.add_verification_key(key)

      # Add the new delegation to the top-level 'targets' role object (i.e.,
      # 'repository.targets()').
      if self.rolename != 'targets':
        self._parent_targets_object.add_delegated_role(bin_role['name'],
            target)

      # Add 'new_targets_object' to the 'targets' role object (this object).
      self.add_delegated_role(bin_role['name'], target)
      logger.debug('Delegated from ' + repr(self.rolename) + ' to ' + repr(bin_role))


    self._update_roledb_delegations(keydict, delegated_roleinfos)




  def add_target_to_bin(self, target_filepath, number_of_bins=DEFAULT_NUM_BINS,
      fileinfo=None):
    """
    <Purpose>
      Add the fileinfo of 'target_filepath' to the expected hashed bin, if the
      bin is available.  The hashed bin should have been created by
      {targets_role}.delegate_hashed_bins().  Assuming the target filepath is
      located in the repository's targets directory, determine the filepath's
      hash prefix, locate the expected bin (if any), and then add the fileinfo
      to the expected bin.  Example:  'targets/foo.tar.gz' may be added to the
      'targets/unclaimed/58-5f.json' role's list of targets by calling this
      method.

    <Arguments>
      target_filepath:
        The filepath of the target to be added to a hashed bin.  The filepath
        must be located in the repository's targets directory.

      number_of_bins:
        The number of delegated roles, or hashed bins, in use by the repository.
        Note: 'number_of_bins' must be a power of 2.

      fileinfo:
        An optional fileinfo object, conforming to tuf.formats.TARGETS_FILEINFO_SCHEMA,
        providing full information about the file.

    <Exceptions>
      securesystemslib.exceptions.FormatError, if 'target_filepath' is
      improperly formatted.

      securesystemslib.exceptions.Error, if 'target_filepath' cannot be added to
      a hashed bin (e.g., an invalid target filepath, or the expected hashed
      bin does not exist.)

    <Side Effects>
      The fileinfo of 'target_filepath' is added to a hashed bin of this Targets
      object.

    <Returns>
      The name of the hashed bin that the target was added to.
    """

    # Do the arguments have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.
    # Raise 'securesystemslib.exceptions.FormatError' if there is a mismatch.
    securesystemslib.formats.PATH_SCHEMA.check_match(target_filepath)
    tuf.formats.NUMBINS_SCHEMA.check_match(number_of_bins)

    # TODO: check target_filepath is sane

    path_hash = repo_lib.get_target_hash(target_filepath)
    bin_name = repo_lib.find_bin_for_target_hash(path_hash, number_of_bins)

    # Ensure the Targets object has delegated to hashed bins
    if not self._delegated_roles.get(bin_name, None):
      raise securesystemslib.exceptions.Error(self.rolename + ' does not have'
          ' a delegated role ' + bin_name)

    self._delegated_roles[bin_name].add_target(target_filepath,
        fileinfo=fileinfo)

    return bin_name



  def remove_target_from_bin(self, target_filepath,
      number_of_bins=DEFAULT_NUM_BINS):
    """
    <Purpose>
      Remove the fileinfo of 'target_filepath' from the expected hashed bin, if
      the bin is available.  The hashed bin should have been created by
      {targets_role}.delegate_hashed_bins().  Assuming the target filepath is
      located in the repository's targets directory, determine the filepath's
      hash prefix, locate the expected bin (if any), and then remove the
      fileinfo from the expected bin.  Example:  'targets/foo.tar.gz' may be
      removed from the '58-5f.json' role's list of targets by calling this
      method.

    <Arguments>
      target_filepath:
        The filepath of the target to be added to a hashed bin.  The filepath
        must be located in the repository's targets directory.

      number_of_bins:
        The number of delegated roles, or hashed bins, in use by the repository.
        Note: 'number_of_bins' must be a power of 2.

    <Exceptions>
      securesystemslib.exceptions.FormatError, if 'target_filepath' is
      improperly formatted.

      securesystemslib.exceptions.Error, if 'target_filepath' cannot be removed
      from a hashed bin (e.g., an invalid target filepath, or the expected
      hashed bin does not exist.)

    <Side Effects>
      The fileinfo of 'target_filepath' is removed from a hashed bin of this
      Targets object.

    <Returns>
      The name of the hashed bin that the target was added to.
    """

    # Do the arguments have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.
    # Raise 'securesystemslib.exceptions.FormatError' if there is a mismatch.
    securesystemslib.formats.PATH_SCHEMA.check_match(target_filepath)
    tuf.formats.NUMBINS_SCHEMA.check_match(number_of_bins)

    # TODO: check target_filepath is sane?

    path_hash = repo_lib.get_target_hash(target_filepath)
    bin_name = repo_lib.find_bin_for_target_hash(path_hash, number_of_bins)

    # Ensure the Targets object has delegated to hashed bins
    if not self._delegated_roles.get(bin_name, None):
      raise securesystemslib.exceptions.Error(self.rolename + ' does not have'
          ' a delegated role ' + bin_name)

    self._delegated_roles[bin_name].remove_target(target_filepath)

    return bin_name


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
      tuf.exceptions.UnknownRoleError, if this Targets' rolename
      does not exist in 'tuf.roledb'.

    <Side Effects>
      None.

    <Returns>
      A list containing the Targets objects of this Targets' delegations.
    """

    return list(self._delegated_roles.values())





  def _check_path(self, pathname):
    """
    <Purpose>
      Check if a path matches the definition of a PATHPATTERN or a
      TARGETPATH (uses the forward slash (/) as directory separator and
      does not start with a directory separator). Checks are performed only
      on the path string, without accessing the file system.

    <Arguments>
      pathname:
        A file path or a glob pattern.

    <Exceptions>
      securesystemslib.exceptions.FormatError, if 'pathname' is improperly
      formatted.

      tuf.exceptions.InvalidNameError, if 'pathname' does not match pattern.

    <Returns>
      None.
    """

    tuf.formats.RELPATH_SCHEMA.check_match(pathname)

    if '\\' in pathname:
      raise tuf.exceptions.InvalidNameError('Path ' + repr(pathname)
          + ' does not use the forward slash (/) as directory separator.')

    if pathname.startswith('/'):
      raise tuf.exceptions.InvalidNameError('Path ' + repr(pathname)
          + ' starts with a directory separator. All paths should be relative'
          '  to targets directory.')





def _keys_to_keydict(keys):
  """
  Iterate over a list of keys and return a list of keyids and a dict mapping
  keyid to key metadata
  """
  keyids = []
  keydict = {}

  for key in keys:
    keyid = key['keyid']
    key_metadata_format = securesystemslib.keys.format_keyval_to_metadata(
        key['keytype'], key['scheme'], key['keyval'])

    new_keydict = {keyid: key_metadata_format}
    keydict.update(new_keydict)
    keyids.append(keyid)

  return keyids, keydict





def create_new_repository(repository_directory, repository_name='default',
    storage_backend=None, use_timestamp_length=True, use_timestamp_hashes=True,
    use_snapshot_length=False, use_snapshot_hashes=False):
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

    repository_name:
      The name of the repository.  If not supplied, 'rolename' is added to the
      'default' repository.

    storage_backend:
      An object which implements
      securesystemslib.storage.StorageBackendInterface. When no object is
      passed a FilesystemBackend will be instantiated and used.

    use_timestamp_length:
      Whether to include the optional length attribute of the snapshot
      metadata file in the timestamp metadata.
      Default is True.

    use_timestamp_hashes:
      Whether to include the optional hashes attribute of the snapshot
      metadata file in the timestamp metadata.
      Default is True.

    use_snapshot_length:
      Whether to include the optional length attribute for targets
      metadata files in the snapshot metadata.
      Default is False to save bandwidth but without losing security
      from rollback attacks.
      Read more at section 5.6 from the Mercury paper:
      https://www.usenix.org/conference/atc17/technical-sessions/presentation/kuppusamy

    use_snapshot_hashes:
      Whether to include the optional hashes attribute for targets
      metadata files in the snapshot metadata.
      Default is False to save bandwidth but without losing security
      from rollback attacks.
      Read more at section 5.6 from the Mercury paper:
      https://www.usenix.org/conference/atc17/technical-sessions/presentation/kuppusamy

  <Exceptions>
    securesystemslib.exceptions.FormatError, if the arguments are improperly
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
  # Raise 'securesystemslib.exceptions.FormatError' if there is a mismatch.
  securesystemslib.formats.PATH_SCHEMA.check_match(repository_directory)
  securesystemslib.formats.NAME_SCHEMA.check_match(repository_name)

  if storage_backend is None:
    storage_backend = securesystemslib.storage.FilesystemBackend()

  # Set the repository, metadata, and targets directories.  These directories
  # are created if they do not exist.
  repository_directory = os.path.abspath(repository_directory)
  metadata_directory = None
  targets_directory = None

  # Ensure the 'repository_directory' exists
  logger.info('Creating ' + repr(repository_directory))
  storage_backend.create_folder(repository_directory)

  # Set the metadata and targets directories.  The metadata directory is a
  # staged one so that the "live" repository is not affected.  The
  # staged metadata changes may be moved over to "live" after all updated
  # have been completed.
  metadata_directory = os.path.join(repository_directory,
      METADATA_STAGED_DIRECTORY_NAME)
  targets_directory = os.path.join(repository_directory, TARGETS_DIRECTORY_NAME)

  # Ensure the metadata directory exists
  logger.info('Creating ' + repr(metadata_directory))
  storage_backend.create_folder(metadata_directory)

  # Ensure the targets directory exists
  logger.info('Creating ' + repr(targets_directory))
  storage_backend.create_folder(targets_directory)

  # Create the bare bones repository object, where only the top-level roles
  # have been set and contain default values (e.g., Root roles has a threshold
  # of 1, expires 1 year into the future, etc.)
  repository = Repository(repository_directory, metadata_directory,
      targets_directory, storage_backend, repository_name, use_timestamp_length,
      use_timestamp_hashes, use_snapshot_length, use_snapshot_hashes)

  return repository





def load_repository(repository_directory, repository_name='default',
    storage_backend=None, use_timestamp_length=True, use_timestamp_hashes=True,
    use_snapshot_length=False, use_snapshot_hashes=False):
  """
  <Purpose>
    Return a repository object containing the contents of metadata files loaded
    from the repository.

  <Arguments>
    repository_directory:
      The root folder of the repository that contains the metadata and targets
      sub-directories.

    repository_name:
      The name of the repository.  If not supplied, 'default' is used as the
      repository name.

    storage_backend:
      An object which implements
      securesystemslib.storage.StorageBackendInterface. When no object is
      passed a FilesystemBackend will be instantiated and used.

    use_timestamp_length:
      Whether to include the optional length attribute of the snapshot
      metadata file in the timestamp metadata.
      Default is True.

    use_timestamp_hashes:
      Whether to include the optional hashes attribute of the snapshot
      metadata file in the timestamp metadata.
      Default is True.

    use_snapshot_length:
      Whether to include the optional length attribute for targets
      metadata files in the snapshot metadata.
      Default is False to save bandwidth but without losing security
      from rollback attacks.
      Read more at section 5.6 from the Mercury paper:
      https://www.usenix.org/conference/atc17/technical-sessions/presentation/kuppusamy

    use_snapshot_hashes:
      Whether to include the optional hashes attribute for targets
      metadata files in the snapshot metadata.
      Default is False to save bandwidth but without losing security
      from rollback attacks.
      Read more at section 5.6 from the Mercury paper:
      https://www.usenix.org/conference/atc17/technical-sessions/presentation/kuppusamy

  <Exceptions>
    securesystemslib.exceptions.FormatError, if 'repository_directory' or any of
    the metadata files are improperly formatted.

    tuf.exceptions.RepositoryError, if the Root role cannot be
    found.  At a minimum, a repository must contain 'root.json'

  <Side Effects>
   All the metadata files found in the repository are loaded and their contents
   stored in a repository_tool.Repository object.

  <Returns>
    repository_tool.Repository object.
  """

  # Does 'repository_directory' have the correct format?
  # Raise 'securesystemslib.exceptions.FormatError' if there is a mismatch.
  securesystemslib.formats.PATH_SCHEMA.check_match(repository_directory)
  securesystemslib.formats.NAME_SCHEMA.check_match(repository_name)

  if storage_backend is None:
    storage_backend = securesystemslib.storage.FilesystemBackend()

  repository_directory = os.path.abspath(repository_directory)
  metadata_directory = os.path.join(repository_directory,
      METADATA_STAGED_DIRECTORY_NAME)
  targets_directory = os.path.join(repository_directory, TARGETS_DIRECTORY_NAME)

  # The Repository() object loaded (i.e., containing all the metadata roles
  # found) and returned.
  repository = Repository(repository_directory, metadata_directory,
      targets_directory, storage_backend, repository_name, use_timestamp_length,
      use_timestamp_hashes, use_snapshot_length, use_snapshot_hashes)

  filenames = repo_lib.get_top_level_metadata_filenames(metadata_directory)

  # The Root file is always available without a version number (a consistent
  # snapshot) attached to the filename.  Store the 'consistent_snapshot' value
  # and read the loaded Root file so that other metadata files may be located.
  consistent_snapshot = False

  # Load the metadata of the top-level roles (i.e., Root, Timestamp, Targets,
  # and Snapshot).
  repository, consistent_snapshot = repo_lib._load_top_level_metadata(repository,
    filenames, repository_name)

  delegated_roles_filenames = repo_lib.get_delegated_roles_metadata_filenames(
      metadata_directory, consistent_snapshot, storage_backend)

  # Load the delegated targets metadata and their fileinfo.
  # The delegated targets roles form a tree/graph which is traversed in a
  # breadth-first-search manner starting from 'targets' in order to correctly
  # load the delegations hierarchy.
  parent_targets_object = repository.targets

  # Keep the next delegations to be loaded in a deque structure which
  # has the properties of a list but is designed to have fast appends
  # and pops from both ends
  delegations = deque()
  # A set used to keep the already loaded delegations and avoid an infinite
  # loop in case of cycles in the delegations graph
  loaded_delegations = set()

  # Top-level roles are already loaded, fetch targets and get its delegations.
  # Store the delegations in the form of delegated-delegating role tuples,
  # starting from the top-level targets:
  # [('role1', 'targets'), ('role2', 'targets'), ... ]
  roleinfo = tuf.roledb.get_roleinfo('targets', repository_name)
  for role in roleinfo['delegations']['roles']:
    delegations.append((role['name'], 'targets'))

  # Traverse the graph by appending the next delegation to the deque and
  # 'pop'-ing and loading the left-most element.
  while delegations:
    rolename, delegating_role = delegations.popleft()
    if (rolename, delegating_role) in loaded_delegations:
      logger.warning('Detected cycle in the delegation graph: ' +
          repr(delegating_role) + ' -> ' +
          repr(rolename) +
          ' is reached more than once.')
      continue

    # Instead of adding only rolename to the set, store the already loaded
    # delegated-delegating role tuples. This way a delegated role is added
    # to each of its delegating roles but when the role is reached twice
    # from the same delegating role an infinite loop is avoided.
    loaded_delegations.add((rolename, delegating_role))

    metadata_path = delegated_roles_filenames[rolename]
    signable = None

    try:
      signable = securesystemslib.util.load_json_file(metadata_path)

    except (securesystemslib.exceptions.Error, ValueError, IOError):
      logger.debug('Tried to load metadata with invalid JSON'
          ' content: ' + repr(metadata_path))
      continue

    metadata_object = signable['signed']

    # Extract the metadata attributes of 'metadata_object' and update its
    # corresponding roleinfo.
    roleinfo = {'name': rolename,
                'signing_keyids': [],
                'signatures': [],
                'partial_loaded': False
               }

    roleinfo['signatures'].extend(signable['signatures'])
    roleinfo['version'] = metadata_object['version']
    roleinfo['expires'] = metadata_object['expires']
    roleinfo['paths'] = metadata_object['targets']
    roleinfo['delegations'] = metadata_object['delegations']

    # Generate the Targets object of the delegated role,
    # add it to the top-level 'targets' object and to its
    # direct delegating role object.
    new_targets_object = Targets(targets_directory, rolename,
         roleinfo, parent_targets_object=parent_targets_object,
         repository_name=repository_name)

    parent_targets_object.add_delegated_role(rolename,
        new_targets_object)
    if delegating_role != 'targets':
      parent_targets_object(delegating_role).add_delegated_role(rolename,
          new_targets_object)

    # Append the next level delegations to the deque:
    # the 'delegated' role becomes the 'delegating'
    for delegation in metadata_object['delegations']['roles']:
      delegations.append((delegation['name'], rolename))

    # Extract the keys specified in the delegations field of the Targets
    # role.  Add 'key_object' to the list of recognized keys.  Keys may be
    # shared, so do not raise an exception if 'key_object' has already been
    # added.  In contrast to the methods that may add duplicate keys, do not
    # log a warning here as there may be many such duplicate key warnings.
    # The repository maintainer should have also been made aware of the
    # duplicate key when it was added.
    for key_metadata in six.itervalues(metadata_object['delegations']['keys']):

      # The repo may have used hashing algorithms for the generated keyids
      # that doesn't match the client's set of hash algorithms.  Make sure
      # to only used the repo's selected hashing algorithms.
      hash_algorithms = securesystemslib.settings.HASH_ALGORITHMS
      securesystemslib.settings.HASH_ALGORITHMS = \
          key_metadata['keyid_hash_algorithms']
      key_object, keyids = \
          securesystemslib.keys.format_metadata_to_key(key_metadata)
      securesystemslib.settings.HASH_ALGORITHMS = hash_algorithms
      try:
        for keyid in keyids: # pragma: no branch
          key_object['keyid'] = keyid
          tuf.keydb.add_key(key_object, keyid=None,
              repository_name=repository_name)

      except tuf.exceptions.KeyAlreadyExistsError:
        pass

  return repository





def dump_signable_metadata(metadata_filepath):
  """
  <Purpose>
    Dump the "signed" portion of metadata. It is the portion that is normally
    signed by the repository tool, which is in canonicalized JSON form.
    This function is intended for external tools that wish to independently
    sign metadata.

    The normal workflow for this use case is to:
    (1) call dump_signable_metadata(metadata_filepath)
    (2) sign the output with an external tool
    (3) call append_signature(signature, metadata_filepath)

  <Arguments>
    metadata_filepath:
      The path to the metadata file.  For example,
      repository/metadata/root.json.

  <Exceptions>
    securesystemslib.exceptions.FormatError, if the arguments are improperly
    formatted.

    IOError, if 'metadata_filepath' cannot be opened.

  <Side Effects>
    None.

  <Returns>
    Metadata content that is normally signed by the repository tool (i.e., the
    "signed" portion of a metadata file).
  """

  # Are the argument properly formatted?
  securesystemslib.formats.PATH_SCHEMA.check_match(metadata_filepath)

  signable = securesystemslib.util.load_json_file(metadata_filepath)

  # Is 'signable' a valid metadata file?
  tuf.formats.SIGNABLE_SCHEMA.check_match(signable)

  return securesystemslib.formats.encode_canonical(signable['signed'])





def append_signature(signature, metadata_filepath):
  """
  <Purpose>
    Append 'signature' to the metadata at 'metadata_filepath'.  The signature
    is assumed to be valid, and externally generated by signing the output of
    dump_signable_metadata(metadata_filepath).  This function is intended for
    external tools that wish to independently sign metadata.

    The normal workflow for this use case is to:
    (1) call dump_signable_metadata(metadata_filepath)
    (2) sign the output with an external tool
    (3) call append_signature(signature, metadata_filepath)

  <Arguments>
    signature:
      A TUF signature structure that contains the KEYID, signing method, and
      the signature.  It conforms to securesystemslib.formats.SIGNATURE_SCHEMA.

      For example:

      {
       "keyid": "a0a0f0cf08...",
       "method": "ed25519",
       "sig": "14f6e6566ec13..."
      }

    metadata_filepath:
      The path to the metadata file.  For example,
      repository/metadata/root.json.

  <Exceptions>
    securesystemslib.exceptions.FormatError, if the arguments are improperly
    formatted.

  <Side Effects>
    'metadata_filepath' is overwritten.

  <Returns>
    None.
  """

  # Are the arguments properly formatted?
  securesystemslib.formats.SIGNATURE_SCHEMA.check_match(signature)
  securesystemslib.formats.PATH_SCHEMA.check_match(metadata_filepath)

  signable = securesystemslib.util.load_json_file(metadata_filepath)

  # Is 'signable' a valid metadata file?
  tuf.formats.SIGNABLE_SCHEMA.check_match(signable)

  signable['signatures'].append(signature)

  file_object = tempfile.TemporaryFile()

  written_metadata_content = json.dumps(signable, indent=1,
      separators=(',', ': '), sort_keys=True).encode('utf-8')

  file_object.write(written_metadata_content)
  securesystemslib.util.persist_temp_file(file_object, metadata_filepath)





if __name__ == '__main__':
  # The interactive sessions of the documentation strings can
  # be tested by running repository_tool.py as a standalone module:
  # $ python repository_tool.py.
  import doctest
  doctest.testmod()
