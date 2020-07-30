#!/usr/bin/env python

# Copyright 2014 - 2017, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
<Program Name>
  repository_lib.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  June 1, 2014.

<Copyright>
  See LICENSE-MIT OR LICENSE for licensing information.

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
import time
import logging
import shutil
import json
import tempfile

import tuf
import tuf.formats
import tuf.exceptions
import tuf.keydb
import tuf.roledb
import tuf.sig
import tuf.log
import tuf.settings

import securesystemslib
import securesystemslib.hash
import securesystemslib.interface
import securesystemslib.util
import iso8601
import six

import securesystemslib.storage


# See 'log.py' to learn how logging is handled in TUF.
logger = logging.getLogger(__name__)

# Disable 'iso8601' logger messages to prevent 'iso8601' from clogging the
# log file.
iso8601_logger = logging.getLogger('iso8601')
iso8601_logger.disabled = True

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
SUPPORTED_KEY_TYPES = ['rsa', 'ed25519', 'ecdsa-sha2-nistp256']

# The algorithm used by the repository to generate the path hash prefixes
# of hashed bin delegations.  Please see delegate_hashed_bins()
HASH_FUNCTION = tuf.settings.DEFAULT_HASH_ALGORITHM




def _generate_and_write_metadata(rolename, metadata_filename,
  targets_directory, metadata_directory, storage_backend,
  consistent_snapshot=False, filenames=None, allow_partially_signed=False,
  increment_version_number=True, repository_name='default',
  use_existing_fileinfo=False, use_timestamp_length=True,
  use_timestamp_hashes=True, use_snapshot_length=False,
  use_snapshot_hashes=False):
  """
  Non-public function that can generate and write the metadata for the
  specified 'rolename'.  It also increments the version number of 'rolename' if
  the 'increment_version_number' argument is True.
  """

  metadata = None

  # Retrieve the roleinfo of 'rolename' to extract the needed metadata
  # attributes, such as version number, expiration, etc.
  roleinfo = tuf.roledb.get_roleinfo(rolename, repository_name)
  previous_keyids = roleinfo.get('previous_keyids', [])
  previous_threshold = roleinfo.get('previous_threshold', 1)
  signing_keyids = list(set(roleinfo['signing_keyids']))

  # Generate the appropriate role metadata for 'rolename'.
  if rolename == 'root':
    metadata = generate_root_metadata(roleinfo['version'], roleinfo['expires'],
        consistent_snapshot, repository_name)

    _log_warning_if_expires_soon(ROOT_FILENAME, roleinfo['expires'],
                                 ROOT_EXPIRES_WARN_SECONDS)



  elif rolename == 'snapshot':
    metadata = generate_snapshot_metadata(metadata_directory,
        roleinfo['version'], roleinfo['expires'],
        storage_backend, consistent_snapshot, repository_name,
        use_length=use_snapshot_length, use_hashes=use_snapshot_hashes)


    _log_warning_if_expires_soon(SNAPSHOT_FILENAME, roleinfo['expires'],
        SNAPSHOT_EXPIRES_WARN_SECONDS)

  elif rolename == 'timestamp':
    # If filenames don't have "snapshot_filename" key, defaults to "snapshot.json"
    snapshot_file_path = (filenames and filenames['snapshot']) \
        or SNAPSHOT_FILENAME

    metadata = generate_timestamp_metadata(snapshot_file_path, roleinfo['version'],
        roleinfo['expires'], storage_backend, repository_name,
        use_length=use_timestamp_length, use_hashes=use_timestamp_hashes)

    _log_warning_if_expires_soon(TIMESTAMP_FILENAME, roleinfo['expires'],
        TIMESTAMP_EXPIRES_WARN_SECONDS)

  # All other roles are either the top-level 'targets' role, or
  # a delegated role.
  else:
    # Only print a warning if the top-level 'targets' role expires soon.
    if rolename == 'targets':
      _log_warning_if_expires_soon(TARGETS_FILENAME, roleinfo['expires'],
          TARGETS_EXPIRES_WARN_SECONDS)

    # Don't hash-prefix consistent target files if they are handled out of band
    consistent_targets = consistent_snapshot and not use_existing_fileinfo

    metadata = generate_targets_metadata(targets_directory,
        roleinfo['paths'], roleinfo['version'], roleinfo['expires'],
        roleinfo['delegations'], consistent_targets, use_existing_fileinfo,
        storage_backend)

  # Before writing 'rolename' to disk, automatically increment its version
  # number (if 'increment_version_number' is True) so that the caller does not
  # have to manually perform this action.  The version number should be
  # incremented in both the metadata file and roledb (required so that Snapshot
  # references the latest version).

  # Store the 'current_version' in case the version number must be restored
  # (e.g., if 'rolename' cannot be written to disk because its metadata is not
  # properly signed).
  current_version = metadata['version']
  if increment_version_number:
    roleinfo = tuf.roledb.get_roleinfo(rolename, repository_name)
    metadata['version'] = metadata['version'] + 1
    roleinfo['version'] = roleinfo['version'] + 1
    tuf.roledb.update_roleinfo(rolename, roleinfo,
        repository_name=repository_name)

  else:
    logger.debug('Not incrementing ' + repr(rolename) + '\'s version number.')

  if rolename in tuf.roledb.TOP_LEVEL_ROLES and not allow_partially_signed:
    # Verify that the top-level 'rolename' is fully signed.  Only a delegated
    # role should not be written to disk without full verification of its
    # signature(s), since it can only be considered fully signed depending on
    # the delegating role.
    signable = sign_metadata(metadata, signing_keyids, metadata_filename,
        repository_name)


    def should_write():
      # Root must be signed by its previous keys and threshold.
      if rolename == 'root' and len(previous_keyids) > 0:
        if not tuf.sig.verify(signable, rolename, repository_name,
            previous_threshold, previous_keyids):
          return False

        else:
          logger.debug('Root is signed by a threshold of its previous keyids.')

      # In the normal case, we should write metadata if the threshold is met.
      return tuf.sig.verify(signable, rolename, repository_name,
          roleinfo['threshold'], roleinfo['signing_keyids'])


    if should_write():
      _remove_invalid_and_duplicate_signatures(signable, repository_name)

      # Root should always be written as if consistent_snapshot is True (i.e.,
      # write <version>.root.json and root.json to disk).
      if rolename == 'root':
        consistent_snapshot = True
      filename = write_metadata_file(signable, metadata_filename,
          metadata['version'], consistent_snapshot, storage_backend)

    # 'signable' contains an invalid threshold of signatures.
    else:
      # Since new metadata cannot be successfully written, restore the current
      # version number.
      roleinfo = tuf.roledb.get_roleinfo(rolename, repository_name)
      roleinfo['version'] = current_version
      tuf.roledb.update_roleinfo(rolename, roleinfo,
          repository_name=repository_name)

      # Note that 'signable' is an argument to tuf.UnsignedMetadataError().
      raise tuf.exceptions.UnsignedMetadataError('Not enough'
          ' signatures for ' + repr(metadata_filename), signable)

  # 'rolename' is a delegated role or a top-level role that is partially
  # signed, and thus its signatures should not be verified.
  else:
    signable = sign_metadata(metadata, signing_keyids, metadata_filename,
        repository_name)
    _remove_invalid_and_duplicate_signatures(signable, repository_name)

    # Root should always be written as if consistent_snapshot is True (i.e.,
    # <version>.root.json and root.json).
    if rolename == 'root':
      filename = write_metadata_file(signable, metadata_filename,
          metadata['version'], consistent_snapshot=True,
          storage_backend=storage_backend)

    else:
      filename = write_metadata_file(signable, metadata_filename,
          metadata['version'], consistent_snapshot, storage_backend)

  return signable, filename





def _metadata_is_partially_loaded(rolename, signable, repository_name):
  """
  Non-public function that determines whether 'rolename' is loaded with
  at least zero good signatures, but an insufficient threshold (which means
  'rolename' was written to disk with repository.write_partial()).  A repository
  maintainer may write partial metadata without including a valid signature.
  However, the final repository.write() must include a threshold number of
  signatures.

  If 'rolename' is found to be partially loaded, mark it as partially loaded in
  its 'tuf.roledb' roleinfo.  This function exists to assist in deciding whether
  a role's version number should be incremented when write() or write_parital()
  is called.  Return True if 'rolename' was partially loaded, False otherwise.
  """

  # The signature status lists the number of good signatures, including
  # bad, untrusted, unknown, etc.
  status = tuf.sig.get_signature_status(signable, rolename, repository_name)

  if len(status['good_sigs']) < status['threshold'] and \
                                                  len(status['good_sigs']) >= 0:
    return True

  else:
    return False





def _check_role_keys(rolename, repository_name):
  """
  Non-public function that verifies the public and signing keys of 'rolename'.
  If either contain an invalid threshold of keys, raise an exception.
  """

  # Extract the total number of public and private keys of 'rolename' from its
  # roleinfo in 'tuf.roledb'.
  roleinfo = tuf.roledb.get_roleinfo(rolename, repository_name)
  total_keyids = len(roleinfo['keyids'])
  threshold = roleinfo['threshold']
  total_signatures = len(roleinfo['signatures'])
  total_signing_keys = len(roleinfo['signing_keyids'])

  # Raise an exception for an invalid threshold of public keys.
  if total_keyids < threshold:
    raise tuf.exceptions.InsufficientKeysError(repr(rolename) + ' role contains'
      ' ' + repr(total_keyids) + ' / ' + repr(threshold) + ' public keys.')

  # Raise an exception for an invalid threshold of signing keys.
  if total_signatures == 0 and total_signing_keys < threshold:
    raise tuf.exceptions.InsufficientKeysError(repr(rolename) + ' role contains'
      ' ' + repr(total_signing_keys) + ' / ' + repr(threshold) + ' signing keys.')





def _remove_invalid_and_duplicate_signatures(signable, repository_name):
  """
    Non-public function that removes invalid or duplicate signatures from
    'signable'.  'signable' may contain signatures (invalid) from previous
    versions of the metadata that were loaded with load_repository().  Invalid,
    or duplicate signatures, are removed from 'signable'.
  """

  # Store the keyids of valid signatures.  'signature_keyids' is checked for
  # duplicates rather than comparing signature objects because PSS may generate
  # duplicate valid signatures for the same data, yet contain different
  # signatures.
  signature_keyids = []

  for signature in signable['signatures']:
    signed = securesystemslib.formats.encode_canonical(signable['signed']).encode('utf-8')
    keyid = signature['keyid']
    key = None

    # Remove 'signature' from 'signable' if the listed keyid does not exist
    # in 'tuf.keydb'.
    try:
      key = tuf.keydb.get_key(keyid, repository_name=repository_name)

    except tuf.exceptions.UnknownKeyError:
      signable['signatures'].remove(signature)
      continue

    # Remove 'signature' from 'signable' if it is an invalid signature.
    if not securesystemslib.keys.verify_signature(key, signature, signed):
      logger.debug('Removing invalid signature for ' + repr(keyid))
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
    consistent_snapshot, repository_name, storage_backend):
  """
  Non-public function that deletes metadata files marked as removed by
  'repository_tool.py'.  Revoked metadata files are not actually deleted until
  this function is called.  Obsolete metadata should *not* be retained in
  "metadata.staged", otherwise they may be re-loaded by 'load_repository()'.

  Note: Obsolete metadata may not always be easily detected (by inspecting
  top-level metadata during loading) due to partial metadata and top-level
  metadata that have not been written yet.
  """

  # Walk the repository's metadata sub-directory, which is where all metadata
  # is stored (including delegated roles).  The 'django.json' role (e.g.,
  # delegated by Targets) would be located in the
  # '{repository_directory}/metadata/' directory.
  metadata_files = sorted(storage_backend.list_folder(metadata_directory))
  for metadata_role in metadata_files:
    if metadata_role.endswith('root.json'):
      continue

    metadata_path = os.path.join(metadata_directory, metadata_role)

    # Strip the version number if 'consistent_snapshot' is True.  Example:
    # '10.django.json' --> 'django.json'.  Consistent and non-consistent
    # metadata might co-exist if write() and
    # write(consistent_snapshot=True) are mixed, so ensure only
    # '<version_number>.filename' metadata is stripped.

    # Should we check if 'consistent_snapshot' is True? It might have been
    # set previously, but 'consistent_snapshot' can potentially be False
    # now.  We'll proceed with the understanding that 'metadata_name' can
    # have a prepended version number even though the repository is now
    # a non-consistent one.
    if metadata_role not in snapshot_metadata['meta']:
      metadata_role, junk = _strip_version_number(metadata_role,
          consistent_snapshot)

    else:
      logger.debug(repr(metadata_role) + ' found in the snapshot role.')

    # Strip metadata extension from filename.  The role database does not
    # include the metadata extension.
    if metadata_role.endswith(METADATA_EXTENSION):
      metadata_role = metadata_role[:-len(METADATA_EXTENSION)]
    else:
      logger.debug(repr(metadata_role) + ' does not match'
          ' supported extension ' + repr(METADATA_EXTENSION))

    if metadata_role in tuf.roledb.TOP_LEVEL_ROLES:
      logger.debug('Not removing top-level metadata ' + repr(metadata_role))
      return

    # Delete the metadata file if it does not exist in 'tuf.roledb'.
    # 'repository_tool.py' might have removed 'metadata_name,'
    # but its metadata file is not actually deleted yet.  Do it now.
    if not tuf.roledb.role_exists(metadata_role, repository_name):
      logger.info('Removing outdated metadata: ' + repr(metadata_path))
      storage_backend.remove(metadata_path)

    else:
      logger.debug('Not removing metadata: ' + repr(metadata_path))

      # TODO: Should we delete outdated consistent snapshots, or does it make
      # more sense for integrators to remove outdated consistent snapshots?




def _get_written_metadata(metadata_signable):
  """
  Non-public function that returns the actual content of written metadata.
  """

  # Explicitly specify the JSON separators for Python 2 + 3 consistency.
  written_metadata_content = json.dumps(metadata_signable, indent=1,
      separators=(',', ': '), sort_keys=True).encode('utf-8')

  return written_metadata_content





def _strip_version_number(metadata_filename, consistent_snapshot):
  """
  Strip from 'metadata_filename' any version number (in the
  expected '{dirname}/<version_number>.rolename.<ext>' format) that
  it may contain, and return the stripped filename and version number,
  as a tuple.  'consistent_snapshot' is a boolean indicating if a version
  number is prepended to 'metadata_filename'.
  """

  # Strip the version number if 'consistent_snapshot' is True.
  # Example: '10.django.json' --> 'django.json'
  if consistent_snapshot:
    dirname, basename = os.path.split(metadata_filename)
    version_number, basename = basename.split('.', 1)
    stripped_metadata_filename = os.path.join(dirname, basename)

    if not version_number.isdigit():
      return metadata_filename, ''

    else:
      return stripped_metadata_filename, version_number

  else:
    return metadata_filename, ''




def _load_top_level_metadata(repository, top_level_filenames, repository_name):
  """
  Load the metadata of the Root, Timestamp, Targets, and Snapshot roles.  At a
  minimum, the Root role must exist and load successfully.
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
  try:
    # Initialize the key and role metadata of the top-level roles.
    signable = securesystemslib.util.load_json_file(root_filename)
    tuf.formats.check_signable_object_format(signable)
    root_metadata = signable['signed']
    tuf.keydb.create_keydb_from_root_metadata(root_metadata, repository_name)
    tuf.roledb.create_roledb_from_root_metadata(root_metadata, repository_name)

    # Load Root's roleinfo and update 'tuf.roledb'.
    roleinfo = tuf.roledb.get_roleinfo('root', repository_name)
    roleinfo['consistent_snapshot'] = root_metadata['consistent_snapshot']
    roleinfo['signatures'] = []
    for signature in signable['signatures']:
      if signature not in roleinfo['signatures']:
        roleinfo['signatures'].append(signature)

      else:
        logger.debug('Found a Root signature that is already loaded:'
          ' ' + repr(signature))

    # By default, roleinfo['partial_loaded'] of top-level roles should be set
    # to False in 'create_roledb_from_root_metadata()'.  Update this field, if
    # necessary, now that we have its signable object.
    if _metadata_is_partially_loaded('root', signable, repository_name):
      roleinfo['partial_loaded'] = True

    else:
      logger.debug('Root was not partially loaded.')

    _log_warning_if_expires_soon(ROOT_FILENAME, roleinfo['expires'],
                                 ROOT_EXPIRES_WARN_SECONDS)

    tuf.roledb.update_roleinfo('root', roleinfo, mark_role_as_dirty=False,
        repository_name=repository_name)

    # Ensure the 'consistent_snapshot' field is extracted.
    consistent_snapshot = root_metadata['consistent_snapshot']

  except securesystemslib.exceptions.StorageError:
    raise tuf.exceptions.RepositoryError('Cannot load the required'
        ' root file: ' + repr(root_filename))

  # Load 'timestamp.json'.  A Timestamp role file without a version number is
  # always written.
  try:
    signable = securesystemslib.util.load_json_file(timestamp_filename)
    timestamp_metadata = signable['signed']
    for signature in signable['signatures']:
      repository.timestamp.add_signature(signature, mark_role_as_dirty=False)

    # Load Timestamp's roleinfo and update 'tuf.roledb'.
    roleinfo = tuf.roledb.get_roleinfo('timestamp', repository_name)
    roleinfo['expires'] = timestamp_metadata['expires']
    roleinfo['version'] = timestamp_metadata['version']

    if _metadata_is_partially_loaded('timestamp', signable, repository_name):
      roleinfo['partial_loaded'] = True

    else:
      logger.debug('The Timestamp role was not partially loaded.')

    _log_warning_if_expires_soon(TIMESTAMP_FILENAME, roleinfo['expires'],
                                 TIMESTAMP_EXPIRES_WARN_SECONDS)

    tuf.roledb.update_roleinfo('timestamp', roleinfo, mark_role_as_dirty=False,
        repository_name=repository_name)

  except securesystemslib.exceptions.StorageError:
    raise tuf.exceptions.RepositoryError('Cannot load the Timestamp file: '
        + repr(timestamp_filename))

  # Load 'snapshot.json'.  A consistent snapshot.json must be calculated if
  # 'consistent_snapshot' is True.
  # The Snapshot and Root roles are both accessed by their hashes.
  if consistent_snapshot:
    snapshot_version = timestamp_metadata['meta'][SNAPSHOT_FILENAME]['version']

    dirname, basename = os.path.split(snapshot_filename)
    basename = basename.split(METADATA_EXTENSION, 1)[0]
    snapshot_filename = os.path.join(dirname,
        str(snapshot_version) + '.' + basename + METADATA_EXTENSION)

  try:
    signable = securesystemslib.util.load_json_file(snapshot_filename)
    tuf.formats.check_signable_object_format(signable)
    snapshot_metadata = signable['signed']

    for signature in signable['signatures']:
      repository.snapshot.add_signature(signature, mark_role_as_dirty=False)

    # Load Snapshot's roleinfo and update 'tuf.roledb'.
    roleinfo = tuf.roledb.get_roleinfo('snapshot', repository_name)
    roleinfo['expires'] = snapshot_metadata['expires']
    roleinfo['version'] = snapshot_metadata['version']

    if _metadata_is_partially_loaded('snapshot', signable, repository_name):
      roleinfo['partial_loaded'] = True

    else:
      logger.debug('Snapshot was not partially loaded.')

    _log_warning_if_expires_soon(SNAPSHOT_FILENAME, roleinfo['expires'],
                                 SNAPSHOT_EXPIRES_WARN_SECONDS)

    tuf.roledb.update_roleinfo('snapshot', roleinfo, mark_role_as_dirty=False,
        repository_name=repository_name)

  except securesystemslib.exceptions.StorageError:
    raise tuf.exceptions.RepositoryError('The Snapshot file cannot be loaded: '
        + repr(snapshot_filename))

  # Load 'targets.json'.  A consistent snapshot of the Targets role must be
  # calculated if 'consistent_snapshot' is True.
  if consistent_snapshot:
    targets_version = snapshot_metadata['meta'][TARGETS_FILENAME]['version']
    dirname, basename = os.path.split(targets_filename)
    targets_filename = os.path.join(dirname, str(targets_version) + '.' + basename)

  try:
    signable = securesystemslib.util.load_json_file(targets_filename)
    tuf.formats.check_signable_object_format(signable)
    targets_metadata = signable['signed']

    for signature in signable['signatures']:
      repository.targets.add_signature(signature, mark_role_as_dirty=False)

    # Update 'targets.json' in 'tuf.roledb.py'
    roleinfo = tuf.roledb.get_roleinfo('targets', repository_name)
    roleinfo['paths'] = targets_metadata['targets']
    roleinfo['version'] = targets_metadata['version']
    roleinfo['expires'] = targets_metadata['expires']
    roleinfo['delegations'] = targets_metadata['delegations']

    if _metadata_is_partially_loaded('targets', signable, repository_name):
      roleinfo['partial_loaded'] = True

    else:
      logger.debug('Targets file was not partially loaded.')

    _log_warning_if_expires_soon(TARGETS_FILENAME, roleinfo['expires'],
                                 TARGETS_EXPIRES_WARN_SECONDS)

    tuf.roledb.update_roleinfo('targets', roleinfo, mark_role_as_dirty=False,
        repository_name=repository_name)

    # Add the keys specified in the delegations field of the Targets role.
    for key_metadata in six.itervalues(targets_metadata['delegations']['keys']):

      # The repo may have used hashing algorithms for the generated keyids
      # that doesn't match the client's set of hash algorithms.  Make sure
      # to only used the repo's selected hashing algorithms.
      hash_algorithms = securesystemslib.settings.HASH_ALGORITHMS
      securesystemslib.settings.HASH_ALGORITHMS = key_metadata['keyid_hash_algorithms']
      key_object, keyids = securesystemslib.keys.format_metadata_to_key(key_metadata)
      securesystemslib.settings.HASH_ALGORITHMS = hash_algorithms

      # Add 'key_object' to the list of recognized keys.  Keys may be shared,
      # so do not raise an exception if 'key_object' has already been loaded.
      # In contrast to the methods that may add duplicate keys, do not log
      # a warning as there may be many such duplicate key warnings.  The
      # repository maintainer should have also been made aware of the duplicate
      # key when it was added.
      try:
        for keyid in keyids: #pragma: no branch
          key_object['keyid'] = keyid
          tuf.keydb.add_key(key_object, keyid=None,
              repository_name=repository_name)

      except tuf.exceptions.KeyAlreadyExistsError:
        pass

  except securesystemslib.exceptions.StorageError:
    raise tuf.exceptions.RepositoryError('The Targets file can not be loaded: '
        + repr(targets_filename))

  return repository, consistent_snapshot




def _log_warning_if_expires_soon(rolename, expires_iso8601_timestamp,
    seconds_remaining_to_warn):
  """
  Non-public function that logs a warning if 'rolename' expires in
  'seconds_remaining_to_warn' seconds, or less.
  """

  # Metadata stores expiration datetimes in ISO8601 format.  Convert to
  # unix timestamp, subtract from current time.time() (also in POSIX time)
  # and compare against 'seconds_remaining_to_warn'.  Log a warning message
  # to console if 'rolename' expires soon.
  datetime_object = iso8601.parse_date(expires_iso8601_timestamp)
  expires_unix_timestamp = \
    tuf.formats.datetime_to_unix_timestamp(datetime_object)
  seconds_until_expires = expires_unix_timestamp - int(time.time())

  if seconds_until_expires <= seconds_remaining_to_warn:
    if seconds_until_expires <= 0:
      logger.warning(
          repr(rolename) + ' expired ' + repr(datetime_object.ctime() + ' (UTC).'))

    else:
      days_until_expires = seconds_until_expires / 86400
      logger.warning(repr(rolename) + ' expires ' + datetime_object.ctime() + ''
        ' (UTC).  ' + repr(days_until_expires) + ' day(s) until it expires.')

  else:
    pass





def import_rsa_privatekey_from_file(filepath, password=None):
  """
  <Purpose>
    Import the encrypted PEM file in 'filepath', decrypt it, and return the key
    object in 'securesystemslib.RSAKEY_SCHEMA' format.

  <Arguments>
    filepath:
      <filepath> file, an RSA encrypted PEM file.  Unlike the public RSA PEM
      key file, 'filepath' does not have an extension.

    password:
      The passphrase to decrypt 'filepath'.

  <Exceptions>
    securesystemslib.exceptions.FormatError, if the arguments are improperly
    formatted.

    securesystemslib.exceptions.CryptoError, if 'filepath' is not a valid
    encrypted key file.

  <Side Effects>
    The contents of 'filepath' is read, decrypted, and the key stored.

  <Returns>
    An RSA key object, conformant to 'securesystemslib.RSAKEY_SCHEMA'.
  """

  # Note: securesystemslib.interface.import_rsa_privatekey_from_file() does not
  # allow both 'password' and 'prompt' to be True, nor does it automatically
  # prompt for a password if the key file is encrypted and a password isn't
  # given.
  try:
    private_key = securesystemslib.interface.import_rsa_privatekey_from_file(
        filepath, password)

  # The user might not have given a password for an encrypted private key.
  # Prompt for a password for convenience.
  except securesystemslib.exceptions.CryptoError:
    if password is None:
      private_key = securesystemslib.interface.import_rsa_privatekey_from_file(
          filepath, password, prompt=True)

    else:
      raise

  return private_key







def import_ed25519_privatekey_from_file(filepath, password=None):
  """
  <Purpose>
    Import the encrypted ed25519 TUF key file in 'filepath', decrypt it, and
    return the key object in 'securesystemslib.ED25519KEY_SCHEMA' format.

    The TUF private key (may also contain the public part) is encrypted with
    AES 256 and CTR the mode of operation.  The password is strengthened with
    PBKDF2-HMAC-SHA256.

  <Arguments>
    filepath:
      <filepath> file, an RSA encrypted TUF key file.

    password:
      The password, or passphrase, to import the private key (i.e., the
      encrypted key file 'filepath' must be decrypted before the ed25519 key
      object can be returned.

  <Exceptions>
    securesystemslib.exceptions.FormatError, if the arguments are improperly
    formatted or the imported key object contains an invalid key type (i.e.,
    not 'ed25519').

    securesystemslib.exceptions.CryptoError, if 'filepath' cannot be decrypted.

    securesystemslib.exceptions.UnsupportedLibraryError, if 'filepath' cannot be
    decrypted due to an invalid configuration setting (i.e., invalid
    'tuf.settings.py' setting).

  <Side Effects>
    'password' is used to decrypt the 'filepath' key file.

  <Returns>
    An ed25519 key object of the form: 'securesystemslib.ED25519KEY_SCHEMA'.
  """

  # Note: securesystemslib.interface.import_ed25519_privatekey_from_file() does
  # not allow both 'password' and 'prompt' to be True, nor does it
  # automatically prompt for a password if the key file is encrypted and a
  # password isn't given.
  try:
    private_key = securesystemslib.interface.import_ed25519_privatekey_from_file(
        filepath, password)

  # The user might not have given a password for an encrypted private key.
  # Prompt for a password for convenience.
  except securesystemslib.exceptions.CryptoError:
    if password is None:
      private_key = securesystemslib.interface.import_ed25519_privatekey_from_file(
          filepath, password, prompt=True)

    else:
      raise

  return private_key



def get_delegated_roles_metadata_filenames(metadata_directory,
    consistent_snapshot, storage_backend=None):
  """
  Return a dictionary containing all filenames in 'metadata_directory'
  except the top-level roles.
  If multiple versions of a file exist because of a consistent snapshot,
  only the file with biggest version prefix is included.
  """

  filenames = {}
  metadata_files = sorted(storage_backend.list_folder(metadata_directory),
      reverse=True)

  # Iterate over role metadata files, sorted by their version-number prefix, with
  # more recent versions first, and only add the most recent version of any
  # (non top-level) metadata to the list of returned filenames. Note that there
  # should only be one version of each file, if consistent_snapshot is False.
  for metadata_role in metadata_files:
    metadata_path = os.path.join(metadata_directory, metadata_role)

    # Strip the version number if 'consistent_snapshot' is True,
    # or if 'metadata_role' is Root.
    # Example:  '10.django.json' --> 'django.json'
    consistent = \
      metadata_role.endswith('root.json') or consistent_snapshot == True
    metadata_name, junk = _strip_version_number(metadata_role,
      consistent)

    if metadata_name.endswith(METADATA_EXTENSION):
      extension_length = len(METADATA_EXTENSION)
      metadata_name = metadata_name[:-extension_length]

    else:
      logger.debug('Skipping file with unsupported metadata'
          ' extension: ' + repr(metadata_path))
      continue

    # Skip top-level roles, only interested in delegated roles.
    if metadata_name in tuf.roledb.TOP_LEVEL_ROLES:
      continue

    # Prevent reloading duplicate versions if consistent_snapshot is True
    if metadata_name not in filenames:
      filenames[metadata_name] = metadata_path

  return filenames



def get_top_level_metadata_filenames(metadata_directory):
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
    securesystemslib.exceptions.FormatError, if 'metadata_directory' is
    improperly formatted.

  <Side Effects>
    None.

  <Returns>
    A dictionary containing the expected filenames of the top-level
    metadata files, such as 'root.json' and 'snapshot.json'.
  """

  # Does 'metadata_directory' have the correct format?
  # Ensure the arguments have the appropriate number of objects and object
  # types, and that all dict keys are properly named.
  # Raise 'securesystemslib.exceptions.FormatError' if there is a mismatch.
  securesystemslib.formats.PATH_SCHEMA.check_match(metadata_directory)

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





def get_targets_metadata_fileinfo(filename, storage_backend, custom=None):
  """
  <Purpose>
    Retrieve the file information of 'filename'.  The object returned
    conforms to 'tuf.formats.TARGETS_FILEINFO_SCHEMA'.  The information
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

    storage_backend:
      An object which implements
      securesystemslib.storage.StorageBackendInterface.

  <Exceptions>
    securesystemslib.exceptions.FormatError, if 'filename' is improperly
    formatted.

  <Side Effects>
    The file is opened and information about the file is generated,
    such as file size and its hash.

  <Returns>
    A dictionary conformant to 'tuf.formats.TARGETS_FILEINFO_SCHEMA'.  This
    dictionary contains the length, hashes, and custom data about the
    'filename' metadata file.  SHA256 hashes are generated by default.
  """

  # Does 'filename' and 'custom' have the correct format?
  # Ensure the arguments have the appropriate number of objects and object
  # types, and that all dict keys are properly named.
  # Raise 'securesystemslib.exceptions.FormatError' if there is a mismatch.
  securesystemslib.formats.PATH_SCHEMA.check_match(filename)
  if custom is not None:
    tuf.formats.CUSTOM_SCHEMA.check_match(custom)

  # Note: 'filehashes' is a dictionary of the form
  # {'sha256': 1233dfba312, ...}.  'custom' is an optional
  # dictionary that a client might define to include additional
  # file information, such as the file's author, version/revision
  # numbers, etc.
  filesize, filehashes = securesystemslib.util.get_file_details(filename,
      tuf.settings.FILE_HASH_ALGORITHMS, storage_backend)

  return tuf.formats.make_targets_fileinfo(filesize, filehashes, custom=custom)





def get_metadata_versioninfo(rolename, repository_name):
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
      a 'tuf.exceptions.UnknownRoleError' exception is raised.

    repository_name:
      The name of the repository.  If not supplied, 'rolename' is added to the
      'default' repository.

  <Exceptions>
    securesystemslib.exceptions.FormatError, if 'rolename' is improperly
    formatted.

    tuf.exceptions.UnknownRoleError, if 'rolename' does not exist.

  <Side Effects>
    None.

  <Returns>
    A dictionary conformant to 'tuf.formats.VERSIONINFO_SCHEMA'.
    This dictionary contains the version  number of 'rolename'.
  """

  # Does 'rolename' have the correct format?
  # Ensure the arguments have the appropriate number of objects and object
  # types, and that all dict keys are properly named.
  tuf.formats.ROLENAME_SCHEMA.check_match(rolename)

  roleinfo = tuf.roledb.get_roleinfo(rolename, repository_name)
  versioninfo = {'version': roleinfo['version']}

  return versioninfo





def create_bin_name(low, high, prefix_len):
  """
  <Purpose>
    Create a string name of a delegated hash bin, where name will be a range of
    zero-padded (up to prefix_len) strings i.e. for low=00, high=07,
    prefix_len=3 the returned name would be '000-007'.

  <Arguments>
    low:
      The low end of the prefix range to be binned

    high:
      The high end of the prefix range to be binned

    prefix_len:
      The length of the prefix range components

  <Returns>
    A string bin name, with each end of the range zero-padded up to prefix_len
  """
  if low == high:
    return "{low:0{len}x}".format(low=low, len=prefix_len)

  return "{low:0{len}x}-{high:0{len}x}".format(low=low, high=high,
      len=prefix_len)





def get_bin_numbers(number_of_bins):
  """
  <Purpose>
    Given the desired number of bins (number_of_bins) calculate the prefix
    length (prefix_length), total number of prefixes (prefix_count) and the
    number of prefixes to be stored in each bin (bin_size).
    Example: number_of_bins = 32
      prefix_length = 2
      prefix_count = 256
      bin_size = 8
    That is, each of the 32 hashed bins are responsible for 8 hash prefixes,
    i.e. 00-07, 08-0f, ..., f8-ff.

  <Arguments>
    number_of_bins:
      The number of hashed bins in use

  <Returns>
    A tuple of three values:
      1. prefix_length: the length of each prefix
      2. prefix_count: the total number of prefixes in use
      3. bin_size: the number of hash prefixes to be stored in each bin
  """
  # Convert 'number_of_bins' to hexadecimal and determine the number of
  # hexadecimal digits needed by each hash prefix
  prefix_length = len("{:x}".format(number_of_bins - 1))
  # Calculate the total number of hash prefixes (e.g., 000 - FFF total values)
  prefix_count = 16 ** prefix_length
  # Determine how many prefixes to assign to each bin
  bin_size = prefix_count // number_of_bins

  # For simplicity, ensure that 'prefix_count' (16 ^ n) can be evenly
  # distributed over 'number_of_bins' (must be 2 ^ n).  Each bin will contain
  # (prefix_count / number_of_bins) hash prefixes.
  if prefix_count % number_of_bins != 0:
    # Note: x % y != 0 does not guarantee that y is not a power of 2 for
    # arbitrary x and y values. However, due to the relationship between
    # number_of_bins and prefix_count, it is true for them.
    raise securesystemslib.exceptions.Error('The "number_of_bins" argument'
        ' must be a power of 2.')

  return prefix_length, prefix_count, bin_size





def find_bin_for_target_hash(target_hash, number_of_bins):
  """
  <Purpose>
    For a given hashed filename, target_hash, calculate the name of a hashed bin
    into which this file would be delegated given number_of_bins bins are in
    use.

  <Arguments>
    target_hash:
      The hash of the target file's path

    number_of_bins:
      The number of hashed_bins in use

  <Returns>
    The name of the hashed bin target_hash would be binned into
  """

  prefix_length, _, bin_size = get_bin_numbers(number_of_bins)

  prefix = int(target_hash[:prefix_length], 16)

  low = prefix - (prefix % bin_size)
  high = (low + bin_size - 1)

  return create_bin_name(low, high, prefix_length)





def get_target_hash(target_filepath):
  """
  <Purpose>
    Compute the hash of 'target_filepath'. This is useful in conjunction with
    the "path_hash_prefixes" attribute in a delegated targets role, which
    tells us which paths a role is implicitly responsible for.

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
  tuf.formats.RELPATH_SCHEMA.check_match(target_filepath)

  digest_object = securesystemslib.hash.digest(algorithm=HASH_FUNCTION)
  digest_object.update(target_filepath.encode('utf-8'))
  return digest_object.hexdigest()




def generate_root_metadata(version, expiration_date, consistent_snapshot,
  repository_name='default'):
  """
  <Purpose>
    Create the root metadata.  'tuf.roledb.py' and 'tuf.keydb.py'
    are read and the information returned by these modules is used to generate
    the root metadata object.

  <Arguments>
    version:
      The metadata version number.  Clients use the version number to
      determine if the downloaded version is newer than the one currently
      trusted.

    expiration_date:
      The expiration date of the metadata file.  Conformant to
      'securesystemslib.formats.ISO8601_DATETIME_SCHEMA'.

    consistent_snapshot:
      Boolean.  If True, a file digest is expected to be prepended to the
      filename of any target file located in the targets directory.  Each digest
      is stripped from the target filename and listed in the snapshot metadata.

    repository_name:
      The name of the repository.  If not supplied, 'rolename' is added to the
      'default' repository.

  <Exceptions>
    securesystemslib.exceptions.FormatError, if the generated root metadata
    object could not be generated with the correct format.

    securesystemslib.exceptions.Error, if an error is encountered while
    generating the root metadata object (e.g., a required top-level role not
    found in 'tuf.roledb'.)

  <Side Effects>
    The contents of 'tuf.keydb.py' and 'tuf.roledb.py' are read.

  <Returns>
    A root metadata object, conformant to 'tuf.formats.ROOT_SCHEMA'.
  """

  # Do the arguments have the correct format?
  # Ensure the arguments have the appropriate number of objects and object
  # types, and that all dict keys are properly named.  Raise
  # 'securesystemslib.exceptions.FormatError' if any of the arguments are
  # improperly formatted.
  tuf.formats.METADATAVERSION_SCHEMA.check_match(version)
  securesystemslib.formats.ISO8601_DATETIME_SCHEMA.check_match(expiration_date)
  securesystemslib.formats.BOOLEAN_SCHEMA.check_match(consistent_snapshot)
  securesystemslib.formats.NAME_SCHEMA.check_match(repository_name)

  # The role and key dictionaries to be saved in the root metadata object.
  # Conformant to 'ROLEDICT_SCHEMA' and 'KEYDICT_SCHEMA', respectively.
  roledict = {}
  keydict = {}

  # Extract the role, threshold, and keyid information of the top-level roles,
  # which Root stores in its metadata.  The necessary role metadata is generated
  # from this information.
  for rolename in tuf.roledb.TOP_LEVEL_ROLES:

    # If a top-level role is missing from 'tuf.roledb.py', raise an exception.
    if not tuf.roledb.role_exists(rolename, repository_name):
      raise securesystemslib.exceptions.Error(repr(rolename) + ' not in'
          ' "tuf.roledb".')

    # Keep track of the keys loaded to avoid duplicates.
    keyids = []

    # Generate keys for the keyids listed by the role being processed.
    for keyid in tuf.roledb.get_role_keyids(rolename, repository_name):
      key = tuf.keydb.get_key(keyid, repository_name=repository_name)

      # If 'key' is an RSA key, it would conform to
      # 'securesystemslib.formats.RSAKEY_SCHEMA', and have the form:
      # {'keytype': 'rsa',
      #  'keyid': keyid,
      #  'keyval': {'public': '-----BEGIN RSA PUBLIC KEY----- ...',
      #             'private': '-----BEGIN RSA PRIVATE KEY----- ...'}}
      keyid = key['keyid']
      if keyid not in keydict:

        # This appears to be a new keyid.  Generate the key for it.
        if key['keytype'] in ['rsa', 'ed25519', 'ecdsa-sha2-nistp256']:
          keytype = key['keytype']
          keyval = key['keyval']
          scheme = key['scheme']
          keydict[keyid] = \
            securesystemslib.keys.format_keyval_to_metadata(keytype,
                scheme, keyval, private=False)

        # This is not a recognized key.  Raise an exception.
        else:
          raise securesystemslib.exceptions.Error('Unsupported keytype:'
          ' ' + key['keytype'])

      # Do we have a duplicate?
      if keyid in keyids:
        raise securesystemslib.exceptions.Error('Same keyid listed twice:'
          ' ' + keyid)

      # Add the loaded keyid for the role being processed.
      keyids.append(keyid)

    # Generate the authentication information Root establishes for each
    # top-level role.
    role_threshold = tuf.roledb.get_role_threshold(rolename, repository_name)
    role_metadata = tuf.formats.build_dict_conforming_to_schema(
        tuf.formats.ROLE_SCHEMA,
        keyids=keyids,
        threshold=role_threshold)
    roledict[rolename] = role_metadata

  # Use generalized build_dict_conforming_to_schema func to produce a dict that
  # contains all the appropriate information for this type of metadata,
  # checking that the result conforms to the appropriate schema.
  # TODO: Later, probably after the rewrite for TUF Issue #660, generalize
  #       further, upward, by replacing generate_targets_metadata,
  #       generate_root_metadata, etc. with one function that generates
  #       metadata, possibly rolling that upwards into the calling function.
  #       There are very few things that really need to be done differently.
  return tuf.formats.build_dict_conforming_to_schema(
      tuf.formats.ROOT_SCHEMA,
      version=version,
      expires=expiration_date,
      keys=keydict,
      roles=roledict,
      consistent_snapshot=consistent_snapshot)





def generate_targets_metadata(targets_directory, target_files, version,
    expiration_date, delegations=None, write_consistent_targets=False,
    use_existing_fileinfo=False, storage_backend=None):
  """
  <Purpose>
    Generate the targets metadata object. The targets in 'target_files' must
    exist at the same path they should on the repo.  'target_files' is a list
    of targets.  The 'custom' field of the targets metadata is not currently
    supported.

  <Arguments>
    targets_directory:
      The absolute path to a directory containing the target files and
      directories of the repository.

    target_files:
      The target files tracked by 'targets.json'.  'target_files' is a
      dictionary mapping target paths (relative to the targets directory) to
      a dict matching tuf.formats.LOOSE_FILEINFO_SCHEMA.  LOOSE_FILEINFO_SCHEMA
      can support multiple different value patterns:
      1) an empty dictionary - for when fileinfo should be generated
      2) a dictionary matching tuf.formats.CUSTOM_SCHEMA - for when fileinfo
         should be generated, with the supplied custom metadata attached
      3) a dictionary matching tuf.formats.FILEINFO_SCHEMA - for when full
         fileinfo is provided in conjunction with use_existing_fileinfo

    version:
      The metadata version number.  Clients use the version number to
      determine if the downloaded version is newer than the one currently
      trusted.

    expiration_date:
      The expiration date of the metadata file.  Conformant to
      'securesystemslib.formats.ISO8601_DATETIME_SCHEMA'.

    delegations:
      The delegations made by the targets role to be generated.  'delegations'
      must match 'tuf.formats.DELEGATIONS_SCHEMA'.

    write_consistent_targets:
      Boolean that indicates whether file digests should be prepended to the
      target files.
      NOTE: it is an error for write_consistent_targets to be True when
      use_existing_fileinfo is also True. We can not create consistent targets
      for a target file where the fileinfo isn't generated by tuf.

    use_existing_fileinfo:
      Boolean that indicates whether to use the complete fileinfo, including
      hashes, as already exists in the roledb (True) or whether to generate
      hashes (False).

    storage_backend:
      An object which implements
      securesystemslib.storage.StorageBackendInterface.

  <Exceptions>
    securesystemslib.exceptions.FormatError, if an error occurred trying to
    generate the targets metadata object.

    securesystemslib.exceptions.Error, if use_existing_fileinfo is False and
    any of the target files cannot be read.

    securesystemslib.exceptions.Error, if use_existing_fileinfo is True and
    some of the target files do not have corresponding hashes in the roledb.

    securesystemslib.exceptions.Error, if both of use_existing_fileinfo and
    write_consistent_targets are True.

  <Side Effects>
    If use_existing_fileinfo is False, the target files are read from storage
    and file information about them is generated.
    If 'write_consistent_targets' is True, each target in 'target_files' will be
    copied to a file with a digest prepended to its filename. For example, if
    'some_file.txt' is one of the targets of 'target_files', consistent targets
    <sha-2 hash>.some_file.txt, <sha-3 hash>.some_file.txt, etc., are created
    and the content of 'some_file.txt' will be copied into them.

  <Returns>
    A targets metadata object, conformant to
    'tuf.formats.TARGETS_SCHEMA'.
  """

  # Do the arguments have the correct format?
  # Ensure the arguments have the appropriate number of objects and object
  # types, and that all dict keys are properly named.
  # Raise 'securesystemslib.exceptions.FormatError' if there is a mismatch.
  securesystemslib.formats.PATH_SCHEMA.check_match(targets_directory)
  tuf.formats.PATH_FILEINFO_SCHEMA.check_match(target_files)
  tuf.formats.METADATAVERSION_SCHEMA.check_match(version)
  securesystemslib.formats.ISO8601_DATETIME_SCHEMA.check_match(expiration_date)
  securesystemslib.formats.BOOLEAN_SCHEMA.check_match(write_consistent_targets)
  securesystemslib.formats.BOOLEAN_SCHEMA.check_match(use_existing_fileinfo)

  if write_consistent_targets and use_existing_fileinfo:
    raise securesystemslib.exceptions.Error('Cannot support writing consistent'
        ' targets and using existing fileinfo.')

  if delegations is not None:
    tuf.formats.DELEGATIONS_SCHEMA.check_match(delegations)

  # Store the file attributes of targets in 'target_files'.  'filedict',
  # conformant to 'tuf.formats.FILEDICT_SCHEMA', is added to the
  # targets metadata object returned.
  filedict = {}

  if use_existing_fileinfo:
    # Use the provided fileinfo dicts, conforming to FILEINFO_SCHEMA, rather than
    # generating fileinfo
    for target, fileinfo in six.iteritems(target_files):

      # Ensure all fileinfo entries in target_files have a non-empty hashes dict
      if not fileinfo.get('hashes', None):
        raise securesystemslib.exceptions.Error('use_existing_hashes option set'
            ' but no hashes exist in roledb for ' + repr(target))

      # and a non-empty length
      if fileinfo.get('length', -1) < 0:
        raise securesystemslib.exceptions.Error('use_existing_hashes option set'
            ' but fileinfo\'s length is not set')

      filedict[target] = fileinfo

  else:
    # Generate the fileinfo dicts by accessing the target files on storage.
    # Default to accessing files on local storage.
    if storage_backend is None:
      storage_backend = securesystemslib.storage.FilesystemBackend()

    filedict = _generate_targets_fileinfo(target_files, targets_directory,
        write_consistent_targets, storage_backend)

  # Generate the targets metadata object.
  # Use generalized build_dict_conforming_to_schema func to produce a dict that
  # contains all the appropriate information for targets metadata,
  # checking that the result conforms to the appropriate schema.
  # TODO: Later, probably after the rewrite for TUF Issue #660, generalize
  #       further, upward, by replacing generate_targets_metadata,
  #       generate_root_metadata, etc. with one function that generates
  #       metadata, possibly rolling that upwards into the calling function.
  #       There are very few things that really need to be done differently.
  if delegations is not None:
    return tuf.formats.build_dict_conforming_to_schema(
        tuf.formats.TARGETS_SCHEMA,
        version=version,
        expires=expiration_date,
        targets=filedict,
        delegations=delegations)
  else:
    return tuf.formats.build_dict_conforming_to_schema(
        tuf.formats.TARGETS_SCHEMA,
        version=version,
        expires=expiration_date,
        targets=filedict)
  # TODO: As an alternative to the odd if/else above where we decide whether or
  #       not to include the delegations argument based on whether or not it is
  #       None, consider instead adding a check in
  #       build_dict_conforming_to_schema that skips a keyword if that keyword
  #       is optional in the schema and the value passed in is set to None....





def _generate_targets_fileinfo(target_files, targets_directory,
    write_consistent_targets, storage_backend):
  """
  Iterate over target_files and:
    * ensure they exist in the targets_directory
    * generate a fileinfo dict for the target file, including hashes
    * copy 'target_path' to 'digest_target' if write_consistent_targets
  add all generated fileinfo dicts to a dictionary mapping
  targetpath: fileinfo and return the dict.
  """

  filedict = {}

  # Generate the fileinfo of all the target files listed in 'target_files'.
  for target, fileinfo in six.iteritems(target_files):

    # The root-most folder of the targets directory should not be included in
    # target paths listed in targets metadata.
    # (e.g., 'targets/more_targets/somefile.txt' -> 'more_targets/somefile.txt')
    relative_targetpath = target

    # Note: join() discards 'targets_directory' if 'target' contains a leading
    # path separator (i.e., is treated as an absolute path).
    target_path = os.path.join(targets_directory, target.lstrip(os.sep))

    # Add 'custom' if it has been provided.  Custom data about the target is
    # optional and will only be included in metadata (i.e., a 'custom' field in
    # the target's fileinfo dictionary) if specified here.
    custom_data = fileinfo.get('custom', None)

    filedict[relative_targetpath] = \
        get_targets_metadata_fileinfo(target_path, storage_backend, custom_data)

    # Copy 'target_path' to 'digest_target' if consistent hashing is enabled.
    if write_consistent_targets:
      for target_digest in six.itervalues(filedict[relative_targetpath]['hashes']):
        dirname, basename = os.path.split(target_path)
        digest_filename = target_digest + '.' + basename
        digest_target = os.path.join(dirname, digest_filename)
        shutil.copyfile(target_path, digest_target)

  return filedict



def generate_snapshot_metadata(metadata_directory, version, expiration_date,
    storage_backend, consistent_snapshot=False,
    repository_name='default', use_length=False, use_hashes=False):
  """
  <Purpose>
    Create the snapshot metadata.  The minimum metadata must exist (i.e.,
    'root.json' and 'targets.json'). This function searches
    'metadata_directory' and the resulting snapshot file will list all the
    delegated roles found there.

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
      Conformant to 'securesystemslib.formats.ISO8601_DATETIME_SCHEMA'.

    storage_backend:
      An object which implements
      securesystemslib.storage.StorageBackendInterface.

    consistent_snapshot:
      Boolean.  If True, a file digest is expected to be prepended to the
      filename of any target file located in the targets directory.  Each digest
      is stripped from the target filename and listed in the snapshot metadata.

    repository_name:
      The name of the repository.  If not supplied, 'rolename' is added to the
      'default' repository.

    use_length:
      Whether to include the optional length attribute for targets
      metadata files in the snapshot metadata.
      Default is False to save bandwidth but without losing security
      from rollback attacks.
      Read more at section 5.6 from the Mercury paper:
      https://www.usenix.org/conference/atc17/technical-sessions/presentation/kuppusamy

    use_hashes:
      Whether to include the optional hashes attribute for targets
      metadata files in the snapshot metadata.
      Default is False to save bandwidth but without losing security
      from rollback attacks.
      Read more at section 5.6 from the Mercury paper:
      https://www.usenix.org/conference/atc17/technical-sessions/presentation/kuppusamy

  <Exceptions>
    securesystemslib.exceptions.FormatError, if the arguments are improperly
    formatted.

    securesystemslib.exceptions.Error, if an error occurred trying to generate
    the snapshot metadata object.

  <Side Effects>
    The 'root.json' and 'targets.json' files are read.

  <Returns>
    The snapshot metadata object, conformant to 'tuf.formats.SNAPSHOT_SCHEMA'.
  """

  # Do the arguments have the correct format?
  # This check ensures arguments have the appropriate number of objects and
  # object types, and that all dict keys are properly named.
  # Raise 'securesystemslib.exceptions.FormatError' if the check fails.
  securesystemslib.formats.PATH_SCHEMA.check_match(metadata_directory)
  tuf.formats.METADATAVERSION_SCHEMA.check_match(version)
  securesystemslib.formats.ISO8601_DATETIME_SCHEMA.check_match(expiration_date)
  securesystemslib.formats.BOOLEAN_SCHEMA.check_match(consistent_snapshot)
  securesystemslib.formats.NAME_SCHEMA.check_match(repository_name)
  securesystemslib.formats.BOOLEAN_SCHEMA.check_match(use_length)
  securesystemslib.formats.BOOLEAN_SCHEMA.check_match(use_hashes)

  # Snapshot's 'fileinfodict' shall contain the version number of Root,
  # Targets, and all delegated roles of the repository.
  fileinfodict = {}

  length, hashes = securesystemslib.util.get_file_details(
      os.path.join(metadata_directory, TARGETS_FILENAME),
      tuf.settings.FILE_HASH_ALGORITHMS, storage_backend)

  length = (use_length and length) or None
  hashes = (use_hashes and hashes) or None

  targets_role = TARGETS_FILENAME[:-len(METADATA_EXTENSION)]

  targets_file_version = get_metadata_versioninfo(targets_role,
      repository_name)

  # Make file info dictionary with make_metadata_fileinfo because
  # in the tuf spec length and hashes are optional for all
  # METAFILES in snapshot.json including the top-level targets file.
  fileinfodict[TARGETS_FILENAME] = tuf.formats.make_metadata_fileinfo(
      targets_file_version['version'], length, hashes)

  # Search the metadata directory and generate the versioninfo of all the role
  # files found there.  This information is stored in the 'meta' field of
  # 'snapshot.json'.

  metadata_files = sorted(storage_backend.list_folder(metadata_directory),
      reverse=True)
  for metadata_filename in metadata_files:
    # Strip the version number if 'consistent_snapshot' is True.
    # Example:  '10.django.json'  --> 'django.json'
    metadata_name, junk = _strip_version_number(metadata_filename,
        consistent_snapshot)

    # All delegated roles are added to the snapshot file.
    if metadata_filename.endswith(METADATA_EXTENSION):
      rolename = metadata_filename[:-len(METADATA_EXTENSION)]

      # Obsolete role files may still be found.  Ensure only roles loaded
      # in the roledb are included in the Snapshot metadata.  Since the
      # snapshot and timestamp roles are not listed in snapshot.json, do not
      # list these roles found in the metadata directory.
      if tuf.roledb.role_exists(rolename, repository_name) and \
          rolename not in tuf.roledb.TOP_LEVEL_ROLES:

        length = None
        hashes = None
        # We want to make sure we are calculating length and hashes only when
        # at least one of them is needed. Otherwise, for adoptors of tuf with
        # lots of delegations, this will cause unnecessary overhead.
        if use_length or use_hashes:
          length, hashes = securesystemslib.util.get_file_details(
              os.path.join(metadata_directory, metadata_filename),
              tuf.settings.FILE_HASH_ALGORITHMS)

          length = (use_length and length) or None
          hashes = (use_hashes and hashes) or None

        file_version = get_metadata_versioninfo(rolename,
            repository_name)

        fileinfodict[metadata_name] = tuf.formats.make_metadata_fileinfo(
            file_version['version'], length, hashes)

    else:
      logger.debug('Metadata file has an unsupported file'
          ' extension: ' + metadata_filename)

  # Generate the Snapshot metadata object.
  # Use generalized build_dict_conforming_to_schema func to produce a dict that
  # contains all the appropriate information for snapshot metadata,
  # checking that the result conforms to the appropriate schema.
  # TODO: Later, probably after the rewrite for TUF Issue #660, generalize
  #       further, upward, by replacing generate_targets_metadata,
  #       generate_root_metadata, etc. with one function that generates
  #       metadata, possibly rolling that upwards into the calling function.
  #       There are very few things that really need to be done differently.
  return tuf.formats.build_dict_conforming_to_schema(
      tuf.formats.SNAPSHOT_SCHEMA,
      version=version,
      expires=expiration_date,
      meta=fileinfodict)






def generate_timestamp_metadata(snapshot_file_path, version, expiration_date,
    storage_backend, repository_name, use_length=True, use_hashes=True):
  """
  <Purpose>
    Generate the timestamp metadata object.  The 'snapshot.json' file must
    exist.

  <Arguments>
    snapshot_file_path:
      Path to the required snapshot metadata file.  The timestamp role
      needs to the calculate the file size and hash of this file.

    version:
      The timestamp's version number.  Clients use the version number to
      determine if the downloaded version is newer than the one currently
      trusted.

    expiration_date:
      The expiration date of the metadata file, conformant to
      'securesystemslib.formats.ISO8601_DATETIME_SCHEMA'.

    storage_backend:
      An object which implements
      securesystemslib.storage.StorageBackendInterface.

    repository_name:
      The name of the repository.  If not supplied, 'rolename' is added to the
      'default' repository.

    use_length:
      Whether to include the optional length attribute of the snapshot
      metadata file in the timestamp metadata.
      Default is True.

    use_hashes:
      Whether to include the optional hashes attribute of the snapshot
      metadata file in the timestamp metadata.
      Default is True.

  <Exceptions>
    securesystemslib.exceptions.FormatError, if the generated timestamp metadata
    object cannot be formatted correctly, or one of the arguments is improperly
    formatted.

  <Side Effects>
    None.

  <Returns>
    A timestamp metadata object, conformant to 'tuf.formats.TIMESTAMP_SCHEMA'.
  """

  # Do the arguments have the correct format?
  # This check ensures arguments have the appropriate number of objects and
  # object types, and that all dict keys are properly named.
  # Raise 'securesystemslib.exceptions.FormatError' if the check fails.
  securesystemslib.formats.PATH_SCHEMA.check_match(snapshot_file_path)
  tuf.formats.METADATAVERSION_SCHEMA.check_match(version)
  securesystemslib.formats.ISO8601_DATETIME_SCHEMA.check_match(expiration_date)
  securesystemslib.formats.NAME_SCHEMA.check_match(repository_name)
  securesystemslib.formats.BOOLEAN_SCHEMA.check_match(use_length)
  securesystemslib.formats.BOOLEAN_SCHEMA.check_match(use_hashes)

  snapshot_fileinfo = {}

  length, hashes = securesystemslib.util.get_file_details(snapshot_file_path,
      tuf.settings.FILE_HASH_ALGORITHMS, storage_backend)

  length = (use_length and length) or None
  hashes = (use_hashes and hashes) or None

  snapshot_filename = os.path.basename(snapshot_file_path)
  # Retrieve the versioninfo of the Snapshot metadata file.
  snapshot_version = get_metadata_versioninfo('snapshot', repository_name)
  snapshot_fileinfo[snapshot_filename] = \
      tuf.formats.make_metadata_fileinfo(snapshot_version['version'],
          length, hashes)

  # Generate the timestamp metadata object.
  # Use generalized build_dict_conforming_to_schema func to produce a dict that
  # contains all the appropriate information for timestamp metadata,
  # checking that the result conforms to the appropriate schema.
  # TODO: Later, probably after the rewrite for TUF Issue #660, generalize
  #       further, upward, by replacing generate_targets_metadata,
  #       generate_root_metadata, etc. with one function that generates
  #       metadata, possibly rolling that upwards into the calling function.
  #       There are very few things that really need to be done differently.
  return tuf.formats.build_dict_conforming_to_schema(
      tuf.formats.TIMESTAMP_SCHEMA,
      version=version,
      expires=expiration_date,
      meta=snapshot_fileinfo)





def sign_metadata(metadata_object, keyids, filename, repository_name):
  """
  <Purpose>
    Sign a metadata object. If any of the keyids have already signed the file,
    the old signature is replaced.  The keys in 'keyids' must already be
    loaded in 'tuf.keydb'.

  <Arguments>
    metadata_object:
      The metadata object to sign.  For example, 'metadata' might correspond to
      'tuf.formats.ROOT_SCHEMA' or
      'tuf.formats.TARGETS_SCHEMA'.

    keyids:
      The keyids list of the signing keys.

    filename:
      The intended filename of the signed metadata object.
      For example, 'root.json' or 'targets.json'.  This function
      does NOT save the signed metadata to this filename.

    repository_name:
      The name of the repository.  If not supplied, 'rolename' is added to the
      'default' repository.

  <Exceptions>
    securesystemslib.exceptions.FormatError, if a valid 'signable' object could
    not be generated or the arguments are improperly formatted.

    securesystemslib.exceptions.Error, if an invalid keytype was found in the
    keystore.

  <Side Effects>
    None.

  <Returns>
    A signable object conformant to 'tuf.formats.SIGNABLE_SCHEMA'.
  """

  # Do the arguments have the correct format?
  # This check ensures arguments have the appropriate number of objects and
  # object types, and that all dict keys are properly named.
  # Raise 'securesystemslib.exceptions.FormatError' if the check fails.
  tuf.formats.ANYROLE_SCHEMA.check_match(metadata_object)
  securesystemslib.formats.KEYIDS_SCHEMA.check_match(keyids)
  securesystemslib.formats.PATH_SCHEMA.check_match(filename)
  securesystemslib.formats.NAME_SCHEMA.check_match(repository_name)

  # Make sure the metadata is in 'signable' format.  That is,
  # it contains a 'signatures' field containing the result
  # of signing the 'signed' field of 'metadata' with each
  # keyid of 'keyids'.
  signable = tuf.formats.make_signable(metadata_object)

  # Sign the metadata with each keyid in 'keyids'.  'signable' should have
  # zero signatures (metadata_object contained none).
  for keyid in keyids:

    # Load the signing key.
    key = tuf.keydb.get_key(keyid, repository_name=repository_name)
    # Generate the signature using the appropriate signing method.
    if key['keytype'] in SUPPORTED_KEY_TYPES:
      if 'private' in key['keyval']:
        signed = securesystemslib.formats.encode_canonical(signable['signed']).encode('utf-8')
        try:
          signature = securesystemslib.keys.create_signature(key, signed)
          signable['signatures'].append(signature)

        except Exception:
          logger.warning('Unable to create signature for keyid: ' + repr(keyid))

      else:
        logger.debug('Private key unset.  Skipping: ' + repr(keyid))

    else:
      raise securesystemslib.exceptions.Error('The keydb contains a key with'
        ' an invalid key type.' + repr(key['keytype']))

  # Raise 'securesystemslib.exceptions.FormatError' if the resulting 'signable'
  # is not formatted correctly.
  tuf.formats.check_signable_object_format(signable)

  return signable





def write_metadata_file(metadata, filename, version_number, consistent_snapshot,
    storage_backend):
  """
  <Purpose>
    If necessary, write the 'metadata' signable object to 'filename'.

  <Arguments>
    metadata:
      The object that will be saved to 'filename', conformant to
      'tuf.formats.SIGNABLE_SCHEMA'.

    filename:
      The filename of the metadata to be written (e.g., 'root.json').

    version_number:
      The version number of the metadata file to be written.  The version
      number is needed for consistent snapshots, which prepend the version
      number to 'filename'.

    consistent_snapshot:
      Boolean that determines whether the metadata file's digest should be
      prepended to the filename.

    storage_backend:
      An object which implements
      securesystemslib.storage.StorageBackendInterface.

  <Exceptions>
    securesystemslib.exceptions.FormatError, if the arguments are improperly
    formatted.

    securesystemslib.exceptions.Error, if the directory of 'filename' does not
    exist.

    Any other runtime (e.g., IO) exception.

  <Side Effects>
    The 'filename' file is created, or overwritten if it exists.

  <Returns>
    The filename of the written file.
  """

  # Do the arguments have the correct format?
  # This check ensures arguments have the appropriate number of objects and
  # object types, and that all dict keys are properly named.
  # Raise 'securesystemslib.exceptions.FormatError' if the check fails.
  tuf.formats.SIGNABLE_SCHEMA.check_match(metadata)
  securesystemslib.formats.PATH_SCHEMA.check_match(filename)
  tuf.formats.METADATAVERSION_SCHEMA.check_match(version_number)
  securesystemslib.formats.BOOLEAN_SCHEMA.check_match(consistent_snapshot)

  if storage_backend is None:
    storage_backend = securesystemslib.storage.FilesystemBackend()

  # Generate the actual metadata file content of 'metadata'.  Metadata is
  # saved as JSON and includes formatting, such as indentation and sorted
  # objects.  The new digest of 'metadata' is also calculated to help determine
  # if re-saving is required.
  file_content = _get_written_metadata(metadata)

  # We previously verified whether new metadata needed to be written (i.e., has
  # not been previously written or has changed).  It is now assumed that the
  # caller intends to write changes that have been marked as dirty.

  # The 'metadata' object is written to 'file_object'.  To avoid partial
  # metadata from being written, 'metadata' is first written to a temporary
  # location (i.e., 'file_object') and then moved to 'filename'.
  file_object = tempfile.TemporaryFile()

  # Serialize 'metadata' to the file-like object and then write 'file_object'
  # to disk.  The dictionary keys of 'metadata' are sorted and indentation is
  # used.
  file_object.write(file_content)

  if consistent_snapshot:
    dirname, basename = os.path.split(filename)
    basename = basename.split(METADATA_EXTENSION, 1)[0]
    version_and_filename = str(version_number) + '.' + basename + METADATA_EXTENSION
    written_consistent_filename = os.path.join(dirname, version_and_filename)

    # If we were to point consistent snapshots to 'written_filename', they
    # would always point to the current version.  Example: 1.root.json and
    # 2.root.json -> root.json.  If consistent snapshot is True, we should save
    # the consistent snapshot and point 'written_filename' to it.
    logger.debug('Creating a consistent file for ' + repr(filename))
    logger.debug('Saving ' + repr(written_consistent_filename))
    securesystemslib.util.persist_temp_file(file_object,
        written_consistent_filename, should_close=False)

  else:
    logger.debug('Not creating a consistent snapshot for ' + repr(filename))

  logger.debug('Saving ' + repr(filename))
  storage_backend.put(file_object, filename)

  file_object.close()

  return filename





def _log_status_of_top_level_roles(targets_directory, metadata_directory,
    repository_name, storage_backend):
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
  filenames = get_top_level_metadata_filenames(metadata_directory)
  root_filename = filenames[ROOT_FILENAME]
  targets_filename = filenames[TARGETS_FILENAME]
  snapshot_filename = filenames[SNAPSHOT_FILENAME]
  timestamp_filename = filenames[TIMESTAMP_FILENAME]

  # Verify that the top-level roles contain a valid number of public keys and
  # that their corresponding private keys have been loaded.
  for rolename in ['root', 'targets', 'snapshot', 'timestamp']:
    try:
      _check_role_keys(rolename, repository_name)

    except tuf.exceptions.InsufficientKeysError as e:
      logger.info(str(e))

  # Do the top-level roles contain a valid threshold of signatures?  Top-level
  # metadata is verified in Root -> Targets -> Snapshot -> Timestamp order.
  # Verify the metadata of the Root role.
  dirty_rolenames = tuf.roledb.get_dirty_roles(repository_name)

  root_roleinfo = tuf.roledb.get_roleinfo('root', repository_name)
  root_is_dirty = None
  if 'root' in dirty_rolenames:
    root_is_dirty = True

  else:
    root_is_dirty = False

  try:
    signable, root_filename = \
      _generate_and_write_metadata('root', root_filename, targets_directory,
          metadata_directory, storage_backend, repository_name=repository_name)
    _log_status('root', signable, repository_name)

  # 'tuf.exceptions.UnsignedMetadataError' raised if metadata contains an
  # invalid threshold of signatures.  log the valid/threshold message, where
  # valid < threshold.
  except tuf.exceptions.UnsignedMetadataError as e:
    _log_status('root', e.signable, repository_name)
    return

  finally:
    tuf.roledb.unmark_dirty(['root'], repository_name)
    tuf.roledb.update_roleinfo('root', root_roleinfo,
        mark_role_as_dirty=root_is_dirty, repository_name=repository_name)

  # Verify the metadata of the Targets role.
  targets_roleinfo = tuf.roledb.get_roleinfo('targets', repository_name)
  targets_is_dirty = None
  if 'targets' in dirty_rolenames:
    targets_is_dirty = True

  else:
    targets_is_dirty = False

  try:
    signable, targets_filename = \
      _generate_and_write_metadata('targets', targets_filename,
          targets_directory, metadata_directory, storage_backend,
          repository_name=repository_name)
    _log_status('targets', signable, repository_name)

  except tuf.exceptions.UnsignedMetadataError as e:
    _log_status('targets', e.signable, repository_name)
    return

  finally:
    tuf.roledb.unmark_dirty(['targets'], repository_name)
    tuf.roledb.update_roleinfo('targets', targets_roleinfo,
        mark_role_as_dirty=targets_is_dirty, repository_name=repository_name)

  # Verify the metadata of the snapshot role.
  snapshot_roleinfo = tuf.roledb.get_roleinfo('snapshot', repository_name)
  snapshot_is_dirty = None
  if 'snapshot' in dirty_rolenames:
    snapshot_is_dirty = True

  else:
    snapshot_is_dirty = False

  filenames = {'root': root_filename, 'targets': targets_filename}
  try:
    signable, snapshot_filename = \
      _generate_and_write_metadata('snapshot', snapshot_filename,
          targets_directory, metadata_directory, storage_backend, False,
          filenames, repository_name=repository_name)
    _log_status('snapshot', signable, repository_name)

  except tuf.exceptions.UnsignedMetadataError as e:
    _log_status('snapshot', e.signable, repository_name)
    return

  finally:
    tuf.roledb.unmark_dirty(['snapshot'], repository_name)
    tuf.roledb.update_roleinfo('snapshot', snapshot_roleinfo,
        mark_role_as_dirty=snapshot_is_dirty, repository_name=repository_name)

  # Verify the metadata of the Timestamp role.
  timestamp_roleinfo = tuf.roledb.get_roleinfo('timestamp', repository_name)
  timestamp_is_dirty = None
  if 'timestamp' in dirty_rolenames:
    timestamp_is_dirty = True

  else:
    timestamp_is_dirty = False

  filenames = {'snapshot': snapshot_filename}
  try:
    signable, timestamp_filename = \
      _generate_and_write_metadata('timestamp', timestamp_filename,
          targets_directory, metadata_directory, storage_backend,
          False, filenames, repository_name=repository_name)
    _log_status('timestamp', signable, repository_name)

  except tuf.exceptions.UnsignedMetadataError as e:
    _log_status('timestamp', e.signable, repository_name)
    return

  finally:
    tuf.roledb.unmark_dirty(['timestamp'], repository_name)
    tuf.roledb.update_roleinfo('timestamp', timestamp_roleinfo,
        mark_role_as_dirty=timestamp_is_dirty, repository_name=repository_name)



def _log_status(rolename, signable, repository_name):
  """
  Non-public function logs the number of (good/threshold) signatures of
  'rolename'.
  """

  status = tuf.sig.get_signature_status(signable, rolename, repository_name)

  logger.info(repr(rolename) + ' role contains ' + \
    repr(len(status['good_sigs'])) + ' / ' + repr(status['threshold']) + \
    ' signatures.')





def create_tuf_client_directory(repository_directory, client_directory):
  """
  <Purpose>
    Create client directory structure as 'tuf.client.updater' expects it.
    Metadata files downloaded from a remote TUF repository are saved to
    'client_directory'.
    The Root file must initially exist before an update request can be
    satisfied.  create_tuf_client_directory() ensures the minimum metadata
    is copied and that required directories ('previous' and 'current') are
    created in 'client_directory'.  Software updaters integrating TUF may
    use the client directory created as an initial copy of the repository's
    metadata.

  <Arguments>
    repository_directory:
      The path of the root repository directory.  The 'metadata' and 'targets'
      sub-directories should be available in 'repository_directory'.  The
      metadata files of 'repository_directory' are copied to 'client_directory'.

    client_directory:
      The path of the root client directory.  The 'current' and 'previous'
      sub-directories are created and will store the metadata files copied
      from 'repository_directory'.  'client_directory' will store metadata
      and target files downloaded from a TUF repository.

  <Exceptions>
    securesystemslib.exceptions.FormatError, if the arguments are improperly
    formatted.

    tuf.exceptions.RepositoryError, if the metadata directory in
    'client_directory' already exists.

  <Side Effects>
    Copies metadata files and directories from 'repository_directory' to
    'client_directory'.  Parent directories are created if they do not exist.

  <Returns>
    None.
  """

  # Do the arguments have the correct format?
  # This check ensures arguments have the appropriate number of objects and
  # object types, and that all dict keys are properly named.
  # Raise 'securesystemslib.exceptions.FormatError' if the check fails.
  securesystemslib.formats.PATH_SCHEMA.check_match(repository_directory)
  securesystemslib.formats.PATH_SCHEMA.check_match(client_directory)

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
  # is raised to avoid accidentally overwriting previous metadata.
  try:
    os.makedirs(client_metadata_directory)

  except OSError as e:
    if e.errno == errno.EEXIST:
      message = 'Cannot create a fresh client metadata directory: ' +\
        repr(client_metadata_directory) + '.  Already exists.'
      raise tuf.exceptions.RepositoryError(message)

    # Testing of non-errno.EEXIST exceptions have been verified on all
    # supported OSs.  An unexpected exception (the '/' directory exists, rather
    # than disallowed path) is possible on Travis, so the '#pragma: no branch'
    # below is included to prevent coverage failure.
    else: #pragma: no branch
      raise

  # Move all  metadata to the client's 'current' and 'previous' directories.
  # The root metadata file MUST exist in '{client_metadata_directory}/current'.
  # 'tuf.client.updater' expects the 'current' and 'previous' directories to
  # exist under 'metadata'.
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
