#!/usr/bin/env python

"""
<Program Name>
  repository_lib.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  June 1, 2014.

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
import tuf.exceptions
import tuf.keydb
import tuf.roledb
import tuf.sig
import tuf.log
import tuf.settings

import securesystemslib
import securesystemslib.interface
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

# The full list of supported TUF metadata extensions.
METADATA_EXTENSIONS = ['.json.gz', '.json']

# The supported extensions of roles listed in Snapshot metadata.
SNAPSHOT_ROLE_EXTENSIONS = ['.json']


def _generate_and_write_metadata(rolename, metadata_filename,
  targets_directory, metadata_directory, consistent_snapshot=False,
  filenames=None, allow_partially_signed=False, increment_version_number=True,
  repository_name='default'):
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
  signing_keyids = list(set(roleinfo['signing_keyids'] + previous_keyids))

  # Generate the appropriate role metadata for 'rolename'.
  if rolename == 'root':
    metadata = generate_root_metadata(roleinfo['version'], roleinfo['expires'],
        consistent_snapshot, repository_name)

    _log_warning_if_expires_soon(ROOT_FILENAME, roleinfo['expires'],
                                 ROOT_EXPIRES_WARN_SECONDS)



  elif rolename == 'snapshot':
    root_filename = ROOT_FILENAME[:-len(METADATA_EXTENSION)]
    targets_filename = TARGETS_FILENAME[:-len(METADATA_EXTENSION)]
    metadata = generate_snapshot_metadata(metadata_directory,
        roleinfo['version'], roleinfo['expires'], root_filename,
        targets_filename, consistent_snapshot, repository_name)


    _log_warning_if_expires_soon(SNAPSHOT_FILENAME, roleinfo['expires'],
        SNAPSHOT_EXPIRES_WARN_SECONDS)

  elif rolename == 'timestamp':
    snapshot_filename = filenames['snapshot']
    metadata = generate_timestamp_metadata(snapshot_filename, roleinfo['version'],
        roleinfo['expires'], repository_name)

    _log_warning_if_expires_soon(TIMESTAMP_FILENAME, roleinfo['expires'],
        TIMESTAMP_EXPIRES_WARN_SECONDS)

  # All other roles are either the top-level 'targets' role, or
  # a delegated role.
  else:
    # Only print a warning if the top-level 'targets' role expires soon.
    if rolename == 'targets':
      _log_warning_if_expires_soon(TARGETS_FILENAME, roleinfo['expires'],
          TARGETS_EXPIRES_WARN_SECONDS)

    metadata = generate_targets_metadata(targets_directory, roleinfo['paths'],
        roleinfo['version'], roleinfo['expires'], roleinfo['delegations'],
        consistent_snapshot)

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

  if rolename in ['root', 'targets', 'snapshot', 'timestamp'] and not allow_partially_signed:
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
          metadata['version'], consistent_snapshot)

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
          metadata['version'], consistent_snapshot=True)

    else:
      filename = write_metadata_file(signable, metadata_filename,
          metadata['version'], consistent_snapshot)

  return signable, filename





def _metadata_is_partially_loaded(rolename, signable, roleinfo, repository_name):
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
  status = tuf.sig.get_signature_status(signable, rolename, repository_name)

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
    securesystemslib.exceptions.Error, if 'directory' could not be validated.

    securesystemslib.exceptions.FormatError, if 'directory' is not properly
    formatted.

  <Side Effects>
    None.

  <Returns>
    The normalized absolutized path of 'directory'.
  """

  # Does 'directory' have the correct format?
  # Raise 'securesystemslib.exceptions.FormatError' if there is a mismatch.
  securesystemslib.formats.PATH_SCHEMA.check_match(directory)

  # Check if the directory exists.
  if not os.path.isdir(directory):
    raise securesystemslib.exceptions.Error(repr(directory) + ' directory does not exist.')

  directory = os.path.abspath(directory)

  return directory





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
    raise securesystemslib.exceptions.InsufficientKeysError(repr(rolename) + ' role contains'
      ' ' + repr(total_keyids) + ' / ' + repr(threshold) + ' public keys.')

  # Raise an exception for an invalid threshold of signing keys.
  if total_signatures == 0 and total_signing_keys < threshold:
    raise securesystemslib.exceptions.InsufficientKeysError(repr(rolename) + ' role contains'
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
    signed = signable['signed']
    keyid = signature['keyid']
    key = None

    # Remove 'signature' from 'signable' if the listed keyid does not exist
    # in 'tuf.keydb'.
    try:
      key = tuf.keydb.get_key(keyid, repository_name=repository_name)

    except securesystemslib.exceptions.UnknownKeyError:
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
    consistent_snapshot, repository_name):
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
  if os.path.exists(metadata_directory) and os.path.isdir(metadata_directory):
    for directory_path, junk_directories, files in os.walk(metadata_directory):

      # 'files' here is a list of target file names.
      for basename in files:

        # If we encounter 'root.json', skip it.  We don't ever delete root.json
        # files, since they should it always exist.
        if basename.endswith('root.json'):
          continue

        metadata_path = os.path.join(directory_path, basename)
        # Strip the metadata dirname and the leading path separator.
        # '{repository_directory}/metadata/django.json' -->
        # 'django.json'
        metadata_name = \
          metadata_path[len(metadata_directory):].lstrip(os.path.sep)

        # Strip the version number if 'consistent_snapshot' is True.  Example:
        # '10.django.json' --> 'django.json'.  Consistent and non-consistent
        # metadata might co-exist if write() and
        # write(consistent_snapshot=True) are mixed, so ensure only
        # '<version_number>.filename' metadata is stripped.
        embedded_version_number = None

        # Should we check if 'consistent_snapshot' is True? It might have been
        # set previously, but 'consistent_snapshot' can potentially be False
        # now.  We'll proceed with the understanding that 'metadata_name' can
        # have a prepended version number even though the repository is now
        # a non-consistent one.
        if metadata_name not in snapshot_metadata['meta']:
          metadata_name, embedded_version_number = \
            _strip_version_number(metadata_name, consistent_snapshot)

        else:
          logger.debug(repr(metadata_name) + ' found in the snapshot role.')



        # Strip filename extensions.  The role database does not include the
        # metadata extension.
        metadata_name_extension = metadata_name

        for metadata_extension in METADATA_EXTENSIONS: #pragma: no branch
          if metadata_name.endswith(metadata_extension):
            metadata_name = metadata_name[:-len(metadata_extension)]
            break

          else:
            logger.debug(repr(metadata_name) + ' does not match'
              ' supported extension ' + repr(metadata_extension))

        if metadata_name in ['root', 'targets', 'snapshot', 'timestamp']:
          return

        # Delete the metadata file if it does not exist in 'tuf.roledb'.
        # 'repository_tool.py' might have removed 'metadata_name,'
        # but its metadata file is not actually deleted yet.  Do it now.
        if not tuf.roledb.role_exists(metadata_name, repository_name):
          logger.info('Removing outdated metadata: ' + repr(metadata_path))
          os.remove(metadata_path)

        else:
          logger.debug('Not removing metadata: ' + repr(metadata_path))

        # TODO: Should we delete outdated consistent snapshots, or does it make
        # more sense for integrators to remove outdated consistent snapshots?

  else:
    logger.debug('Metadata directory does not exist: ' + repr(metadata_directory))




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
  # Example: '10.django.json'  --> 'django.json'
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
  if os.path.exists(root_filename):

    # Initialize the key and role metadata of the top-level roles.
    signable = securesystemslib.util.load_json_file(root_filename)
    tuf.formats.check_signable_object_format(signable)
    root_metadata = signable['signed']
    tuf.keydb.create_keydb_from_root_metadata(root_metadata, repository_name)
    tuf.roledb.create_roledb_from_root_metadata(root_metadata, repository_name)

    # Load Root's roleinfo and update 'tuf.roledb'.
    roleinfo = tuf.roledb.get_roleinfo('root', repository_name)
    roleinfo['signatures'] = []
    for signature in signable['signatures']:
      if signature not in roleinfo['signatures']:
        roleinfo['signatures'].append(signature)

      else:
        logger.debug('Found a Root signature that is already loaded:'
          ' ' + repr(signature))

    else:
      logger.debug('A compressed Root file was not found.')

    # By default, roleinfo['partial_loaded'] of top-level roles should be set
    # to False in 'create_roledb_from_root_metadata()'.  Update this field, if
    # necessary, now that we have its signable object.
    if _metadata_is_partially_loaded('root', signable, roleinfo, repository_name):
      roleinfo['partial_loaded'] = True

    else:
      logger.debug('Root was not partially loaded.')

    _log_warning_if_expires_soon(ROOT_FILENAME, roleinfo['expires'],
                                 ROOT_EXPIRES_WARN_SECONDS)

    tuf.roledb.update_roleinfo('root', roleinfo, mark_role_as_dirty=False,
        repository_name=repository_name)

    # Ensure the 'consistent_snapshot' field is extracted.
    consistent_snapshot = root_metadata['consistent_snapshot']

  else:
    raise securesystemslib.exceptions.RepositoryError('Cannot load the required'
      ' root file: ' + repr(root_filename))

  # Load 'timestamp.json'.  A Timestamp role file without a version number is
  # always written.
  if os.path.exists(timestamp_filename):
    signable = securesystemslib.util.load_json_file(timestamp_filename)
    timestamp_metadata = signable['signed']
    for signature in signable['signatures']:
      repository.timestamp.add_signature(signature, mark_role_as_dirty=False)

    # Load Timestamp's roleinfo and update 'tuf.roledb'.
    roleinfo = tuf.roledb.get_roleinfo('timestamp', repository_name)
    roleinfo['expires'] = timestamp_metadata['expires']
    roleinfo['version'] = timestamp_metadata['version']

    if _metadata_is_partially_loaded('timestamp', signable, roleinfo, repository_name):
      roleinfo['partial_loaded'] = True

    else:
      logger.debug('The Timestamp role was not partially loaded.')

    _log_warning_if_expires_soon(TIMESTAMP_FILENAME, roleinfo['expires'],
                                 TIMESTAMP_EXPIRES_WARN_SECONDS)

    tuf.roledb.update_roleinfo('timestamp', roleinfo, mark_role_as_dirty=False,
        repository_name=repository_name)

  else:
    logger.debug('Cannot load the Timestamp  file: ' + repr(timestamp_filename))

  # Load 'snapshot.json'.  A consistent snapshot.json must be calculated if
  # 'consistent_snapshot' is True.
  # The Snapshot and Root roles are both accessed by their hashes.
  if consistent_snapshot:
    snapshot_hashes = timestamp_metadata['meta'][SNAPSHOT_FILENAME]['hashes']
    snapshot_hash = random.choice(list(snapshot_hashes.values()))
    snapshot_version = timestamp_metadata['meta'][SNAPSHOT_FILENAME]['version']

    dirname, basename = os.path.split(snapshot_filename)
    basename = basename.split(METADATA_EXTENSION, 1)[0]
    snapshot_filename = os.path.join(dirname, str(snapshot_version) + '.' + basename + METADATA_EXTENSION)

  if os.path.exists(snapshot_filename):
    signable = securesystemslib.util.load_json_file(snapshot_filename)
    tuf.formats.check_signable_object_format(signable)
    snapshot_metadata = signable['signed']

    for signature in signable['signatures']:
      repository.snapshot.add_signature(signature, mark_role_as_dirty=False)

    # Load Snapshot's roleinfo and update 'tuf.roledb'.
    roleinfo = tuf.roledb.get_roleinfo('snapshot', repository_name)
    roleinfo['expires'] = snapshot_metadata['expires']
    roleinfo['version'] = snapshot_metadata['version']

    if _metadata_is_partially_loaded('snapshot', signable, roleinfo, repository_name):
      roleinfo['partial_loaded'] = True

    else:
      logger.debug('Snapshot was not partially loaded.')

    _log_warning_if_expires_soon(SNAPSHOT_FILENAME, roleinfo['expires'],
                                 SNAPSHOT_EXPIRES_WARN_SECONDS)

    tuf.roledb.update_roleinfo('snapshot', roleinfo, mark_role_as_dirty=False,
        repository_name=repository_name)

  else:
    logger.debug('The Snapshot file cannot be loaded: ' + repr(snapshot_filename))

  # Load 'targets.json'.  A consistent snapshot of the Targets role must be
  # calculated if 'consistent_snapshot' is True.
  if consistent_snapshot:
    targets_version = snapshot_metadata['meta'][TARGETS_FILENAME]['version']
    dirname, basename = os.path.split(targets_filename)
    targets_filename = os.path.join(dirname, str(targets_version) + '.' + basename)

  if os.path.exists(targets_filename):
    signable = securesystemslib.util.load_json_file(targets_filename)
    tuf.formats.check_signable_object_format(signable)
    targets_metadata = signable['signed']

    for signature in signable['signatures']:
      repository.targets.add_signature(signature, mark_role_as_dirty=False)

    # Update 'targets.json' in 'tuf.roledb.py'
    roleinfo = tuf.roledb.get_roleinfo('targets', repository_name)
    for filepath, fileinfo in six.iteritems(targets_metadata['targets']):
      roleinfo['paths'].update({filepath: fileinfo.get('custom', {})})
    roleinfo['version'] = targets_metadata['version']
    roleinfo['expires'] = targets_metadata['expires']
    roleinfo['delegations'] = targets_metadata['delegations']

    if _metadata_is_partially_loaded('targets', signable, roleinfo, repository_name):
      roleinfo['partial_loaded'] = True

    else:
      logger.debug('Targets file was not partially loaded.')

    _log_warning_if_expires_soon(TARGETS_FILENAME, roleinfo['expires'],
                                 TARGETS_EXPIRES_WARN_SECONDS)

    tuf.roledb.update_roleinfo('targets', roleinfo, mark_role_as_dirty=False,
        repository_name=repository_name)

    # Add the keys specified in the delegations field of the Targets role.
    for key_metadata in six.itervalues(targets_metadata['delegations']['keys']):
      key_object, keyids = securesystemslib.keys.format_metadata_to_key(key_metadata)

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

      except securesystemslib.exceptions.KeyAlreadyExistsError:
        pass

  else:
    logger.debug('The Targets file cannot be loaded: ' + repr(targets_filename))

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
    set in 'settings.RSA_CRYPTO_LIBRARY'.  PyCrypto currently supported.  The
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
    securesystemslib.exceptions.FormatError, if the arguments are improperly
    formatted.

  <Side Effects>
    Writes key files to '<filepath>' and '<filepath>.pub'.

  <Returns>
    None.
  """

  securesystemslib.interface.generate_and_write_rsa_keypair(
      filepath, bits, password)




def import_rsa_privatekey_from_file(filepath, password=None):
  """
  <Purpose>
    Import the encrypted PEM file in 'filepath', decrypt it, and return the key
    object in 'securesystemslib.RSAKEY_SCHEMA' format.

    Which cryptography library performs the cryptographic decryption is
    determined by the string set in 'settings.RSA_CRYPTO_LIBRARY'.  PyCrypto
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
    securesystemslib.exceptions.FormatError, if the arguments are improperly
    formatted.

    securesystemslib.exceptions.CryptoError, if 'filepath' is not a valid
    encrypted key file.

  <Side Effects>
    The contents of 'filepath' is read, decrypted, and the key stored.

  <Returns>
    An RSA key object, conformant to 'securesystemslib.RSAKEY_SCHEMA'.
  """

  return securesystemslib.interface.import_rsa_privatekey_from_file(
    filepath, password)





def import_rsa_publickey_from_file(filepath):
  """
  <Purpose>
    Import the RSA key stored in 'filepath'.  The key object returned is a TUF
    key, specifically 'securesystemslib.RSAKEY_SCHEMA'.  If the RSA PEM
    in 'filepath' contains a private key, it is discarded.

    Which cryptography library performs the cryptographic decryption is
    determined by the string set in 'settings.RSA_CRYPTO_LIBRARY'.  PyCrypto
    currently supported.  If the RSA PEM in 'filepath' contains a private key,
    it is discarded.

  <Arguments>
    filepath:
      <filepath>.pub file, an RSA PEM file.

  <Exceptions>
    securesystemslib.exceptions.FormatError, if 'filepath' is improperly formatted.

    securesystemslib.exceptions.Error, if a valid RSA key object cannot be
    generated.  This may be caused by an improperly formatted PEM file.

  <Side Effects>
    'filepath' is read and its contents extracted.

  <Returns>
    An RSA key object conformant to 'securesystemslib.RSAKEY_SCHEMA'.
  """

  return securesystemslib.interface.import_rsa_publickey_from_file(filepath)





def generate_and_write_ed25519_keypair(filepath, password=None):
  """
  <Purpose>
    Generate an Ed25519 key file, create an encrypted TUF key (using 'password'
    as the pass phrase), and store it in 'filepath'.  The public key portion of
    the generated ED25519 key is stored in <'filepath'>.pub.  Which cryptography
    library performs the cryptographic decryption is determined by the string
    set in 'settings.ED25519_CRYPTO_LIBRARY'.

    PyCrypto currently supported.  The Ed25519 private key is encrypted with
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
    securesystemslib.exceptions.FormatError, if the arguments are improperly
    formatted.

    securesystemslib.exceptions.CryptoError, if 'filepath' cannot be encrypted.

    securesystemslib.exceptions.UnsupportedLibraryError, if 'filepath' cannot be
    encrypted due to an invalid configuration setting (i.e., invalid
    'tuf.settings.py' setting).

  <Side Effects>
    Writes key files to '<filepath>' and '<filepath>.pub'.

  <Returns>
    None.
  """

  securesystemslib.interface.generate_and_write_ed25519_keypair(
      filepath, password)





def import_ed25519_publickey_from_file(filepath):
  """
  <Purpose>
    Load the ED25519 public key object (conformant to
    'securesystemslib.KEY_SCHEMA') stored in 'filepath'.  Return
    'filepath' in securesystemslib.ED25519KEY_SCHEMA format.

    If the TUF key object in 'filepath' contains a private key, it is discarded.

  <Arguments>
    filepath:
      <filepath>.pub file, a TUF public key file.

  <Exceptions>
    securesystemslib.exceptions.FormatError, if 'filepath' is improperly
    formatted or is an unexpected key type.

  <Side Effects>
    The contents of 'filepath' is read and saved.

  <Returns>
    An ED25519 key object conformant to
    'securesystemslib.ED25519KEY_SCHEMA'.
  """

  return securesystemslib.interface.import_ed25519_publickey_from_file(filepath)





def import_ed25519_privatekey_from_file(filepath, password=None):
  """
  <Purpose>
    Import the encrypted ed25519 TUF key file in 'filepath', decrypt it, and
    return the key object in 'securesystemslib.ED25519KEY_SCHEMA' format.

    Which cryptography library performs the cryptographic decryption is
    determined by the string set in 'settings.ED25519_CRYPTO_LIBRARY'.  PyCrypto
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

  return securesystemslib.interface.import_ed25519_privatekey_from_file(
      filepath, password)




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
    securesystemslib.exceptions.FormatError, if 'metadata_directory' is
    improperly formatted.

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
    securesystemslib.exceptions.FormatError, if 'filename' is improperly
    formatted.

    securesystemslib.exceptions.Error, if 'filename' doesn't exist.

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
  # Raise 'securesystemslib.exceptions.FormatError' if there is a mismatch.
  securesystemslib.formats.PATH_SCHEMA.check_match(filename)
  if custom is not None:
    tuf.formats.CUSTOM_SCHEMA.check_match(custom)

  if not os.path.isfile(filename):
    message = repr(filename) + ' is not a file.'
    raise securesystemslib.exceptions.Error(message)

  # Note: 'filehashes' is a dictionary of the form
  # {'sha256': 1233dfba312, ...}.  'custom' is an optional
  # dictionary that a client might define to include additional
  # file information, such as the file's author, version/revision
  # numbers, etc.
  filesize, filehashes = \
    securesystemslib.util.get_file_details(filename, securesystemslib.settings.HASH_ALGORITHMS)

  return tuf.formats.make_fileinfo(filesize, filehashes, custom=custom)





def get_metadata_versioninfo(rolename, repository_name):
  """
  <Purpose>
    Retrieve the version information of 'rolename'.  The object returned
    conforms to 'securesystemslib.VERSIONINFO_SCHEMA'.  The information
    generated for 'rolename' is stored in 'snapshot.json'.
    The versioninfo object returned has the form:

    versioninfo = {'version': 14}

  <Arguments>
    rolename:
      The metadata role whose versioninfo is needed.  It must exist, otherwise
      a 'securesystemslib.exceptions.UnknownRoleError' exception is raised.

    repository_name:
      The name of the repository.  If not supplied, 'rolename' is added to the
      'default' repository.

  <Exceptions>
    securesystemslib.exceptions.FormatError, if 'rolename' is improperly
    formatted.

    securesystemslib.exceptions.UnknownRoleError, if 'rolename' does not exist.

  <Side Effects>
    None.

  <Returns>
    A dictionary conformant to 'securesystemslib.VERSIONINFO_SCHEMA'.
    This dictionary contains the version  number of 'rolename'.
  """

  # Does 'rolename' have the correct format?
  # Ensure the arguments have the appropriate number of objects and object
  # types, and that all dict keys are properly named.
  tuf.formats.ROLENAME_SCHEMA.check_match(rolename)

  roleinfo = tuf.roledb.get_roleinfo(rolename, repository_name)
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

  return securesystemslib.util.get_target_hash(target_filepath)





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
  for rolename in ['root', 'targets', 'snapshot', 'timestamp']:

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
        if key['keytype'] in ['rsa', 'ed25519']:
          keytype = key['keytype']
          keyval = key['keyval']
          scheme = key['scheme']
          keydict[keyid] = \
            securesystemslib.keys.format_keyval_to_metadata(keytype,
                scheme, keyval, private=False)

        # This is not a recognized key.  Raise an exception.
        else:
          raise securesystemslib.exceptions.Error('Unsupported keytype:'
          ' ' + keyid)

      # Do we have a duplicate?
      if keyid in keyids:
        raise securesystemslib.exceptions.Error('Same keyid listed twice:'
          ' ' + keyid)

      # Add the loaded keyid for the role being processed.
      keyids.append(keyid)

    # Generate and store the role data belonging to the processed role.
    role_threshold = tuf.roledb.get_role_threshold(rolename, repository_name)
    role_metadata = tuf.formats.make_role_metadata(keyids, role_threshold)
    roledict[rolename] = role_metadata

  # Generate the root metadata object.
  root_metadata = tuf.formats.RootFile.make_metadata(version, expiration_date,
      keydict, roledict, consistent_snapshot)

  return root_metadata





def generate_targets_metadata(targets_directory, target_files, version,
                              expiration_date, delegations=None,
                              write_consistent_targets=False):
  """
  <Purpose>
    Generate the targets metadata object. The targets in 'target_files' must
    exist at the same path they should on the repo.  'target_files' is a list
    of targets.  The 'custom' field of the targets metadata is not currently
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
      'securesystemslib.formats.ISO8601_DATETIME_SCHEMA'.

    delegations:
      The delegations made by the targets role to be generated.  'delegations'
      must match 'tuf.formats.DELEGATIONS_SCHEMA'.

    write_consistent_targets:
      Boolean that indicates whether file digests should be prepended to the
      target files.

  <Exceptions>
    securesystemslib.exceptions.FormatError, if an error occurred trying to
    generate the targets metadata object.

    securesystemslib.exceptions.Error, if any of the target files cannot be read.

  <Side Effects>
    The target files are read and file information generated about them.  If
    'write_consistent_targets' is True, each target in 'target_files' will be
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
  securesystemslib.formats.PATH_FILEINFO_SCHEMA.check_match(target_files)
  tuf.formats.METADATAVERSION_SCHEMA.check_match(version)
  securesystemslib.formats.ISO8601_DATETIME_SCHEMA.check_match(expiration_date)
  securesystemslib.formats.BOOLEAN_SCHEMA.check_match(write_consistent_targets)

  if delegations is not None:
    tuf.formats.DELEGATIONS_SCHEMA.check_match(delegations)

  # Store the file attributes of targets in 'target_files'.  'filedict',
  # conformant to 'tuf.formats.FILEDICT_SCHEMA', is added to the
  # targets metadata object returned.
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
      raise securesystemslib.exceptions.Error(repr(target_path) + ' cannot'
        ' be read.  Unable to generate targets metadata.')

    # Add 'custom' if it has been provided.  Custom data about the target is
    # optional and will only be included in metadata (i.e., a 'custom' field in
    # the target's fileinfo dictionary) if specified here.
    custom_data = None
    if len(custom):
      custom_data = custom

    filedict[relative_targetpath] = \
      get_metadata_fileinfo(target_path, custom_data)

    # Copy 'target_path' to 'digest_target' if consistent hashing is enabled.
    if write_consistent_targets:
      for target_digest in six.itervalues(filedict[relative_targetpath]['hashes']):
        dirname, basename = os.path.split(target_path)
        digest_filename = target_digest + '.' + basename
        digest_target = os.path.join(dirname, digest_filename)
        shutil.copyfile(target_path, digest_target)

  # Generate the targets metadata object.
  targets_metadata = tuf.formats.TargetsFile.make_metadata(version,
                                                           expiration_date,
                                                           filedict,
                                                           delegations)

  return targets_metadata





def generate_snapshot_metadata(metadata_directory, version, expiration_date,
    root_filename, targets_filename, consistent_snapshot=False,
    repository_name='default'):
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

    repository_name:
      The name of the repository.  If not supplied, 'rolename' is added to the
      'default' repository.

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
  securesystemslib.formats.PATH_SCHEMA.check_match(root_filename)
  securesystemslib.formats.PATH_SCHEMA.check_match(targets_filename)
  securesystemslib.formats.BOOLEAN_SCHEMA.check_match(consistent_snapshot)
  securesystemslib.formats.NAME_SCHEMA.check_match(repository_name)

  metadata_directory = _check_directory(metadata_directory)

  # Snapshot's 'fileinfodict' shall contain the version number of Root,
  # Targets, and all delegated roles fo the repository.
  fileinfodict = {}
  fileinfodict[ROOT_FILENAME] = get_metadata_versioninfo(root_filename,
      repository_name)
  fileinfodict[TARGETS_FILENAME] = get_metadata_versioninfo(targets_filename,
      repository_name)

  # We previously also stored the compressed versions of roles in
  # snapshot.json, however, this is no longer needed as their hashes and
  # lengths are not used and their version numbers match the uncompressed role
  # files.

  # Search the metadata directory and generate the versioninfo of all the role
  # files found there.  This information is stored in the 'meta' field of
  # 'snapshot.json'.

  for metadata_filename in os.listdir(metadata_directory):
    # Strip the version number if 'consistent_snapshot' is True.
    # Example:  '10.django.json'  --> 'django.json'
    metadata_name, version_number_junk = \
      _strip_version_number(metadata_filename, consistent_snapshot)

    # All delegated roles are added to the snapshot file.
    for metadata_extension in SNAPSHOT_ROLE_EXTENSIONS:
      if metadata_filename.endswith(metadata_extension):
        rolename = metadata_filename[:-len(metadata_extension)]

        # Obsolete role files may still be found.  Ensure only roles loaded
        # in the roledb are included in the Snapshot metadata.  Since the
        # snapshot and timestamp roles are not listed in snapshot.json, do not
        # list these roles found in the metadata directory.
        if tuf.roledb.role_exists(rolename, repository_name) and \
            rolename not in ['root', 'snapshot', 'timestamp', 'targets']:
          fileinfodict[metadata_name] = get_metadata_versioninfo(rolename,
              repository_name)

      else:
        logger.debug('Metadata file has an unsupported file'
            ' extension: ' + metadata_filename)
        continue

  # Generate the Snapshot metadata object.
  snapshot_metadata = tuf.formats.SnapshotFile.make_metadata(version,
                                                             expiration_date,
                                                             fileinfodict)

  return snapshot_metadata





def generate_timestamp_metadata(snapshot_filename, version, expiration_date,
    repository_name):
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
      'securesystemslib.formats.ISO8601_DATETIME_SCHEMA'.

    repository_name:
      The name of the repository.  If not supplied, 'rolename' is added to the
      'default' repository.

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
  securesystemslib.formats.PATH_SCHEMA.check_match(snapshot_filename)
  tuf.formats.METADATAVERSION_SCHEMA.check_match(version)
  securesystemslib.formats.ISO8601_DATETIME_SCHEMA.check_match(expiration_date)
  securesystemslib.formats.NAME_SCHEMA.check_match(repository_name)

  # Retrieve the versioninfo of the Snapshot metadata file.
  snapshot_fileinfo = {}
  length, hashes = securesystemslib.util.get_file_details(snapshot_filename)
  snapshot_version = get_metadata_versioninfo('snapshot', repository_name)
  snapshot_fileinfo[SNAPSHOT_FILENAME] = \
    tuf.formats.make_fileinfo(length, hashes, version=snapshot_version['version'])

  # We previously saved the versioninfo of the compressed versions of
  # 'snapshot.json' in 'versioninfo'.  Since version numbers are now stored,
  # the version numbers of compressed roles do not change and can thus be
  # excluded.

  # Generate the timestamp metadata object.
  timestamp_metadata = tuf.formats.TimestampFile.make_metadata(version,
                                                               expiration_date,
                                                               snapshot_fileinfo)

  return timestamp_metadata





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
        signed = signable['signed']
        try:
          signature = securesystemslib.keys.create_signature(key, signed)
          signable['signatures'].append(signature)

        except Exception as e:
          logger.warning('Unable to create signature for keyid: ' + repr(keyid))

      else:
        logger.debug('Private key unset.  Skipping: ' + repr(keyid))

    else:
      raise securesystemslib.exceptions.Error('The keydb contains a key with'
        ' an invalid key type.')

  # Raise 'securesystemslib.exceptions.FormatError' if the resulting 'signable'
  # is not formatted correctly.
  tuf.formats.check_signable_object_format(signable)

  return signable





def write_metadata_file(metadata, filename, version_number, consistent_snapshot):
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

  <Exceptions>
    securesystemslib.exceptions.FormatError, if the arguments are improperly
    formatted.

    securesystemslib.exceptions.Error, if the directory of 'filename' does not
    exist.

    Any other runtime (e.g., IO) exception.

  <Side Effects>
    The 'filename' (or the compressed filename) file is created, or overwritten
    if it exists.

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

  # Verify the directory of 'filename', and convert 'filename' to its absolute
  # path so that temporary files are moved to their expected destinations.
  filename = os.path.abspath(filename)
  written_filename = filename
  _check_directory(os.path.dirname(filename))

  # Generate the actual metadata file content of 'metadata'.  Metadata is
  # saved as JSON and includes formatting, such as indentation and sorted
  # objects.  The new digest of 'metadata' is also calculated to help determine
  # if re-saving is required.
  file_content = _get_written_metadata(metadata)

  # We previously verified whether new metadata needed to be written (i.e., has
  # not been previously written or has changed).  It is now assumed that the
  # caller intends to write changes that have been marked as dirty.

  # The 'metadata' object is written to 'file_object', including compressed
  # versions.  To avoid partial metadata from being written, 'metadata' is
  # first written to a temporary location (i.e., 'file_object') and then
  # moved to 'filename'.
  file_object = securesystemslib.util.TempFile()

  # Serialize 'metadata' to the file-like object and then write
  # 'file_object' to disk.  The dictionary keys of 'metadata' are sorted
  # and indentation is used.  The 'securesystemslib.util.TempFile' file-like object is
  # automically closed after the final move.
  file_object.write(file_content)

  if consistent_snapshot:
    dirname, basename = os.path.split(written_filename)
    basename = basename.split(METADATA_EXTENSION, 1)[0]
    version_and_filename = str(version_number) + '.' + basename + METADATA_EXTENSION
    written_consistent_filename = os.path.join(dirname, version_and_filename)

    # If we were to point consistent snapshots to 'written_filename', they
    # would always point to the current version.  Example: 1.root.json and
    # 2.root.json -> root.json.  If consistent snapshot is True, we should save
    # the consistent snapshot and point 'written_filename' to it.
    logger.debug('Creating a consistent snapshot for ' + repr(written_filename))
    logger.debug('Saving ' + repr(written_consistent_filename))
    file_object.move(written_consistent_filename)

    # For GitHub issue #374 https://github.com/theupdateframework/tuf/issues/374
    # We provide the option of either (1) creating a link via os.link() to the
    # consistent file or (2) creating a copy of the consistent file and saving
    # to its expected filename (e.g., root.json).  The option of either
    # creating a copy or link should be configurable in tuf.settings.py.
    if (tuf.settings.CONSISTENT_METHOD == 'copy'):
      logger.debug('Pointing ' + repr(filename) + ' to the consistent snapshot.')
      shutil.copyfile(written_consistent_filename, written_filename)

    elif (tuf.settings.CONSISTENT_METHOD == 'hard_link'):
      logger.info('Hard linking ' + repr(written_consistent_filename))

      # 'written_filename' must not exist, otherwise os.link() complains.
      if os.path.exists(written_filename):
        os.remove(written_filename)

      else:
        logger.debug(repr(written_filename) + ' does not exist.')

      os.link(written_consistent_filename, written_filename)

    else:
      raise securesystemslib.exceptions.InvalidConfigurationError('The'
        ' consistent method specified in tuf.settings.py is not supported, try'
        ' either "copy" or "hard_link"')

  else:
    logger.debug('Not creating a consistent snapshot for ' + repr(written_filename))
    logger.debug('Saving ' + repr(written_filename))
    file_object.move(written_filename)

  return written_filename





def _log_status_of_top_level_roles(targets_directory, metadata_directory,
    repository_name):
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
      _check_role_keys(rolename, repository_name)

    except securesystemslib.exceptions.InsufficientKeysError as e:
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
          metadata_directory, repository_name=repository_name)
    _log_status('root', signable, repository_name)

  # 'tuf.exceptions.UnsignedMetadataError' raised if metadata contains an invalid threshold
  # of signatures.  log the valid/threshold message, where valid < threshold.
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
          targets_directory, metadata_directory, repository_name=repository_name)
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
          targets_directory, metadata_directory, False, filenames,
          repository_name=repository_name)
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
          targets_directory, metadata_directory, False, filenames,
          repository_name=repository_name)
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
    securesystemslib.exceptions.FormatError, if the arguments are improperly formatted.

    securesystemslib.exceptions.RepositoryError, if the metadata directory in 'client_directory'
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
  # is raised to avoid accidently overwritting previous metadata.
  try:
    os.makedirs(client_metadata_directory)

  except OSError as e:
    if e.errno == errno.EEXIST:
      message = 'Cannot create a fresh client metadata directory: ' +\
        repr(client_metadata_directory) + '.  Already exists.'
      raise securesystemslib.exceptions.RepositoryError(message)

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
