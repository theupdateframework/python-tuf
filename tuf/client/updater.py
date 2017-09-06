"""
<Program Name>
  updater.py

<Author>
  Geremy Condra
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  July 2012.  Based on a previous version of this module. (VLAD)

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  'updater.py' is intended to be the only TUF module that software update
  systems need to utilize.  It provides a single class representing an
  updater that includes methods to download, install, and verify
  metadata/target files in a secure manner.  Importing 'updater.py' and
  instantiating its main class is all that is required by the client prior
  to a TUF update request.  The importation and instantiation steps allow
  TUF to load all of the required metadata files and set the repository mirror
  information.

  An overview of the update process:

  1. The software update system instructs TUF to check for updates.

  2. TUF downloads and verifies timestamp.json.

  3. If timestamp.json indicates that snapshot.json has changed, TUF downloads
     and verifies snapshot.json.

  4. TUF determines which metadata files listed in snapshot.json differ from
     those described in the last snapshot.json that TUF has seen.  If root.json
     has changed, the update process starts over using the new root.json.

  5. TUF provides the software update system with a list of available files
     according to targets.json.

  6. The software update system instructs TUF to download a specific target
     file.

  7. TUF downloads and verifies the file and then makes the file available to
     the software update system.

<Example Client>

  # The client first imports the 'updater.py' module, the only module the
  # client is required to import.  The client will utilize a single class
  # from this module.
  import tuf.client.updater

  # The only other module the client interacts with is 'tuf.settings'.  The
  # client accesses this module solely to set the repository directory.
  # This directory will hold the files downloaded from a remote repository.
  tuf.settings.repositories_directory = 'local-repository'

  # Next, the client creates a dictionary object containing the repository
  # mirrors.  The client may download content from any one of these mirrors.
  # In the example below, a single mirror named 'mirror1' is defined.  The
  # mirror is located at 'http://localhost:8001', and all of the metadata
  # and targets files can be found in the 'metadata' and 'targets' directory,
  # respectively.  If the client wishes to only download target files from
  # specific directories on the mirror, the 'confined_target_dirs' field
  # should be set.  In the example, the client has chosen '', which is
  # interpreted as no confinement.  In other words, the client can download
  # targets from any directory or subdirectories.  If the client had chosen
  # 'targets1/', they would have been confined to the '/targets/targets1/'
  # directory on the 'http://localhost:8001' mirror.
  repository_mirrors = {'mirror1': {'url_prefix': 'http://localhost:8001',
                                    'metadata_path': 'metadata',
                                    'targets_path': 'targets',
                                    'confined_target_dirs': ['']}}

  # The updater may now be instantiated.  The Updater class of 'updater.py'
  # is called with two arguments.  The first argument assigns a name to this
  # particular updater and the second argument the repository mirrors defined
  # above.
  updater = tuf.client.updater.Updater('updater', repository_mirrors)

  # The client next calls the refresh() method to ensure it has the latest
  # copies of the metadata files.
  updater.refresh()

  # The target file information for all the repository targets is determined.
  targets = updater.all_targets()

  # Among these targets, determine the ones that have changed since the client's
  # last refresh().  A target is considered updated if it does not exist in
  # 'destination_directory' (current directory) or the target located there has
  # changed.
  destination_directory = '.'
  updated_targets = updater.updated_targets(targets, destination_directory)

  # Lastly, attempt to download each target among those that have changed.
  # The updated target files are saved locally to 'destination_directory'.
  for target in updated_targets:
    updater.download_target(target, destination_directory)
"""

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import errno
import logging
import os
import shutil
import time
import random
import fnmatch

import tuf
import tuf.download
import tuf.formats
import tuf.settings
import tuf.keydb
import tuf.log
import tuf.mirrors
import tuf.roledb
import tuf.sig
import tuf.exceptions

import securesystemslib.hash
import securesystemslib.keys
import securesystemslib.util
import six
import iso8601

# See 'log.py' to learn how logging is handled in TUF.
logger = logging.getLogger('tuf.client.updater')

# Disable 'iso8601' logger messages to prevent 'iso8601' from clogging the
# log file.
iso8601_logger = logging.getLogger('iso8601')
iso8601_logger.disabled = True

# Metadata includes the specification version number that it follows.
# All downloaded metadata must be equal to our supported major version of 1.
# For example, "1.4.3" and "1.0.0" are supported.  "2.0.0" is not supported.
SUPPORTED_MAJOR_VERSION = 1

class Updater(object):
  """
  <Purpose>
    Provide a class that can download target files securely.  The updater
    keeps track of currently and previously trusted metadata, target files
    available to the client, target file attributes such as file size and
    hashes, key and role information, metadata signatures, and the ability
    to determine when the download of a file should be permitted.

  <Updater Attributes>
    self.metadata:
      Dictionary holding the currently and previously trusted metadata.

      Example: {'current': {'root': ROOT_SCHEMA,
                            'targets':TARGETS_SCHEMA, ...},
                'previous': {'root': ROOT_SCHEMA,
                             'targets':TARGETS_SCHEMA, ...}}

    self.metadata_directory:
      The directory where trusted metadata is stored.

    self.versioninfo:
      A cache of version numbers for the roles available on the repository.

      Example: {'targets.json': {'version': 128}, ...}

    self.mirrors:
      The repository mirrors from which metadata and targets are available.
      Conformant to 'tuf.formats.MIRRORDICT_SCHEMA'.

    self.repository_name:
      The name of the updater instance.

  <Updater Methods>
    refresh():
      This method downloads, verifies, and loads metadata for the top-level
      roles in a specific order (i.e., timestamp -> snapshot -> root -> targets)
      The expiration time for downloaded metadata is also verified.

      The metadata for delegated roles are not refreshed by this method, but by
      the target methods (e.g., all_targets(), targets_of_role(),
      get_one_valid_targetinfo()).  The refresh() method should be called by
      the client before any target requests.

    all_targets():
      Returns the target information for the 'targets' and delegated roles.
      Prior to extracting the target information, this method attempts a file
      download of all the target metadata that have changed.

    targets_of_role('targets'):
      Returns the target information for the targets of a specified role.
      Like all_targets(), delegated metadata is updated if it has changed.

    get_one_valid_targetinfo(file_path):
      Returns the target information for a specific file identified by its file
      path.  This target method also downloads the metadata of updated targets.

    updated_targets(targets, destination_directory):
      After the client has retrieved the target information for those targets
      they are interested in updating, they would call this method to determine
      which targets have changed from those saved locally on disk.  All the
      targets that have changed are returns in a list.  From this list, they
      can request a download by calling 'download_target()'.

    download_target(target, destination_directory):
      This method performs the actual download of the specified target.  The
      file is saved to the 'destination_directory' argument.

    remove_obsolete_targets(destination_directory):
      Any files located in 'destination_directory' that were previously
      served by the repository but have since been removed, can be deleted
      from disk by the client by calling this method.

    Note: The methods listed above are public and intended for the software
    updater integrating TUF with this module.  All other methods that may begin
    with a single leading underscore are non-public and only used internally.
    updater.py is not subclassed in TUF, nor is it designed to be subclassed,
    so double leading underscores is not used.
    http://www.python.org/dev/peps/pep-0008/#method-names-and-instance-variables
  """

  def __init__(self, repository_name, repository_mirrors):
    """
    <Purpose>
      Constructor.  Instantiating an updater object causes all the metadata
      files for the top-level roles to be read from disk, including the key
      and role information for the delegated targets of 'targets'.  The actual
      metadata for delegated roles is not loaded in __init__.  The metadata
      for these delegated roles, including nested delegated roles, are
      loaded, updated, and saved to the 'self.metadata' store by the target
      methods, like all_targets() and targets_of_role().

      The initial set of metadata files are provided by the software update
      system utilizing TUF.

      In order to use an updater, the following directories must already
      exist locally:

            {tuf.settings.repositories_directory}/{repository_name}/metadata/current
            {tuf.settings.repositories_directory}/{repository_name}/metadata/previous

      and, at a minimum, the root metadata file must exist:

            {tuf.settings.repositories_directory}/{repository_name}/metadata/current/root.json

    <Arguments>
      repository_name:
        The name of the repository.

      repository_mirrors:
        A dictionary holding repository mirror information, conformant to
        'tuf.formats.MIRRORDICT_SCHEMA'.  This dictionary holds
        information such as the directory containing the metadata and target
        files, the server's URL prefix, and the target content directories the
        client should be confined to.

        repository_mirrors = {'mirror1': {'url_prefix': 'http://localhost:8001',
                                          'metadata_path': 'metadata',
                                          'targets_path': 'targets',
                                          'confined_target_dirs': ['']}}

    <Exceptions>
      securesystemslib.exceptions.FormatError:
        If the arguments are improperly formatted.

      tuf.exceptions.RepositoryError:
        If there is an error with the updater's repository files, such
        as a missing 'root.json' file.

    <Side Effects>
      Th metadata files (e.g., 'root.json', 'targets.json') for the top- level
      roles are read from disk and stored in dictionaries.  In addition, the
      key and roledb modules are populated with 'repository_name' entries.

    <Returns>
      None.
    """

    # Do the arguments have the correct format?
    # These checks ensure the arguments have the appropriate
    # number of objects and object types and that all dict
    # keys are properly named.
    # Raise 'securesystemslib.exceptions.FormatError' if there is a mistmatch.
    securesystemslib.formats.NAME_SCHEMA.check_match(repository_name)
    tuf.formats.MIRRORDICT_SCHEMA.check_match(repository_mirrors)

    # Save the validated arguments.
    self.repository_name = repository_name
    self.mirrors = repository_mirrors

    # Store the trusted metadata read from disk.
    self.metadata = {}

    # Store the currently trusted/verified metadata.
    self.metadata['current'] = {}

    # Store the previously trusted/verified metadata.
    self.metadata['previous'] = {}

    # Store the version numbers of roles available on the repository.  The dict
    # keys are paths, and the dict values versioninfo data. This information
    # can help determine whether a metadata file has changed and needs to be
    # re-downloaded.
    self.versioninfo = {}

    # Store the file information of the root and snapshot roles.  The dict keys
    # are paths, the dict values fileinfo data. This information can help
    # determine whether a metadata file has changed and so needs to be
    # re-downloaded.
    self.fileinfo = {}

    # Store the location of the client's metadata directory.
    self.metadata_directory = {}

    # Store the 'consistent_snapshot' of the Root role.  This setting
    # determines if metadata and target files downloaded from remote
    # repositories include the digest.
    self.consistent_snapshot = False

    # Ensure the repository metadata directory has been set.
    if tuf.settings.repositories_directory is None:
      raise tuf.exceptions.RepositoryError('The TUF update client'
        ' module must specify the directory containing the local repository'
        ' files.  "tuf.settings.repositories_directory" MUST be set.')

    # Set the path for the current set of metadata files.
    repositories_directory = tuf.settings.repositories_directory
    repository_directory = os.path.join(repositories_directory, self.repository_name)
    current_path = os.path.join(repository_directory, 'metadata', 'current')

    # Ensure the current path is valid/exists before saving it.
    if not os.path.exists(current_path):
      raise tuf.exceptions.RepositoryError('Missing'
        ' ' + repr(current_path) + '.  This path must exist and, at a minimum,'
        ' contain the Root metadata file.')

    self.metadata_directory['current'] = current_path

    # Set the path for the previous set of metadata files.
    previous_path = os.path.join(repository_directory, 'metadata', 'previous')

    # Ensure the previous path is valid/exists.
    if not os.path.exists(previous_path):
      raise tuf.exceptions.RepositoryError('Missing ' + repr(previous_path) + '.'
        '  This path MUST exist.')

    self.metadata_directory['previous'] = previous_path

    # Load current and previous metadata.
    for metadata_set in ['current', 'previous']:
      for metadata_role in ['root', 'targets', 'snapshot', 'timestamp']:
        self._load_metadata_from_file(metadata_set, metadata_role)

    # Raise an exception if the repository is missing the required 'root'
    # metadata.
    if 'root' not in self.metadata['current']:
      raise tuf.exceptions.RepositoryError('No root of trust!'
        ' Could not find the "root.json" file.')





  def __str__(self):
    """
      The string representation of an Updater object.
    """

    return self.repository_name





  def _load_metadata_from_file(self, metadata_set, metadata_role):
    """
    <Purpose>
      Non-public method that loads current or previous metadata if there is a
      local file.  If the expected file belonging to 'metadata_role' (e.g.,
      'root.json') cannot be loaded, raise an exception.  The extracted metadata
      object loaded from file is saved to the metadata store (i.e.,
      self.metadata).

    <Arguments>
      metadata_set:
        The string 'current' or 'previous', depending on whether one wants to
        load the currently or previously trusted metadata file.

      metadata_role:
        The name of the metadata. This is a role name and should
        not end in '.json'.  Examples: 'root', 'targets', 'unclaimed'.

    <Exceptions>
      securesystemslib.exceptions.FormatError:
        If the role object loaded for 'metadata_role' is improperly formatted.

      securesystemslib.exceptions.Error:
        If there was an error importing a delegated role of 'metadata_role'
        or the 'metadata_set' is not one currently supported.

    <Side Effects>
      If the metadata is loaded successfully, it is saved to the metadata
      store.  If 'metadata_role' is 'root', the role and key databases
      are reloaded.  If 'metadata_role' is a target metadata, all its
      delegated roles are refreshed.

    <Returns>
      None.
    """

    # Ensure we have a valid metadata set.
    if metadata_set not in ['current', 'previous']:
      raise securesystemslib.exceptions.Error('Invalid metadata set: ' + repr(metadata_set))

    # Save and construct the full metadata path.
    metadata_directory = self.metadata_directory[metadata_set]
    metadata_filename = metadata_role + '.json'
    metadata_filepath = os.path.join(metadata_directory, metadata_filename)

    # Ensure the metadata path is valid/exists, else ignore the call.
    if os.path.exists(metadata_filepath):
      # Load the file.  The loaded object should conform to
      # 'tuf.formats.SIGNABLE_SCHEMA'.
      try:
        metadata_signable = securesystemslib.util.load_json_file(metadata_filepath)

      # Although the metadata file may exist locally, it may not
      # be a valid json file.  On the next refresh cycle, it will be
      # updated as required.  If Root if cannot be loaded from disk
      # successfully, an exception should be raised by the caller.
      except securesystemslib.exceptions.Error:
        return

      tuf.formats.check_signable_object_format(metadata_signable)

      # Extract the 'signed' role object from 'metadata_signable'.
      metadata_object = metadata_signable['signed']

      # Save the metadata object to the metadata store.
      self.metadata[metadata_set][metadata_role] = metadata_object

      # If 'metadata_role' is 'root' or targets metadata, the key and role
      # databases must be rebuilt.  If 'root', ensure self.consistent_snaptshots
      # is updated.
      if metadata_set == 'current':
        if metadata_role == 'root':
          self._rebuild_key_and_role_db()
          self.consistent_snapshot = metadata_object['consistent_snapshot']

        elif metadata_object['_type'] == 'targets':
          # TODO: Should we also remove the keys of the delegated roles?
          self._import_delegations(metadata_role)





  def _rebuild_key_and_role_db(self):
    """
    <Purpose>
      Non-public method that rebuilds the key and role databases from the
      currently trusted 'root' metadata object extracted from 'root.json'.
      This private method is called when a new/updated 'root' metadata file is
      loaded.  This method will only store the role information of the
      top-level roles (i.e., 'root', 'targets', 'snapshot', 'timestamp').

    <Arguments>
      None.

    <Exceptions>
      securesystemslib.exceptions.FormatError:
        If the 'root' metadata is improperly formatted.

      securesystemslib.exceptions.Error:
        If there is an error loading a role contained in the 'root'
        metadata.

    <Side Effects>
      The key and role databases are reloaded for the top-level roles.

    <Returns>
      None.
    """

    # Clobbering this means all delegated metadata files are rendered outdated
    # and will need to be reloaded.  However, reloading the delegated metadata
    # files is avoided here because fetching target information with methods
    # like all_targets() and get_one_valid_targetinfo() always cause a refresh
    # of these files.  The metadata files for delegated roles are also not
    # loaded when the repository is first instantiated.  Due to this setup,
    # reloading delegated roles is not required here.
    tuf.keydb.create_keydb_from_root_metadata(self.metadata['current']['root'],
        self.repository_name)
    tuf.roledb.create_roledb_from_root_metadata(self.metadata['current']['root'],
        self.repository_name)





  def _import_delegations(self, parent_role):
    """
    <Purpose>
      Non-public method that imports all the roles delegated by 'parent_role'.

    <Arguments>
      parent_role:
        The role whose delegations will be imported.

    <Exceptions>
      securesystemslib.exceptions.FormatError:
        If a key attribute of a delegated role's signing key is
        improperly formatted.

      securesystemslib.exceptions.Error:
        If the signing key of a delegated role cannot not be loaded.

    <Side Effects>
      The key and role databases are modified to include the newly loaded roles
      delegated by 'parent_role'.

    <Returns>
      None.
    """

    current_parent_metadata = self.metadata['current'][parent_role]

    if 'delegations' not in current_parent_metadata:
      return

    # This could be quite slow with a large number of delegations.
    keys_info = current_parent_metadata['delegations'].get('keys', {})
    roles_info = current_parent_metadata['delegations'].get('roles', [])

    logger.debug('Adding roles delegated from ' + repr(parent_role) + '.')

    # Iterate the keys of the delegated roles of 'parent_role' and load them.
    for keyid, keyinfo in six.iteritems(keys_info):
      if keyinfo['keytype'] in ['rsa', 'ed25519']:

        # We specify the keyid to ensure that it's the correct keyid
        # for the key.
        try:
          key, keyids = securesystemslib.keys.format_metadata_to_key(keyinfo)
          for keyid in keyids:
            key['keyid'] = keyid
            tuf.keydb.add_key(key, keyid=None, repository_name=self.repository_name)

        except securesystemslib.exceptions.KeyAlreadyExistsError:
          pass

        except (securesystemslib.exceptions.FormatError, securesystemslib.exceptions.Error):
          logger.exception('Invalid key for keyid: ' + repr(keyid) + '.')
          logger.error('Aborting role delegation for parent role ' + parent_role + '.')
          raise

      else:
        logger.warning('Invalid key type for ' + repr(keyid) + '.')
        continue

    # Add the roles to the role database.
    for roleinfo in roles_info:
      try:
        # NOTE: tuf.roledb.add_role will take care of the case where rolename
        # is None.
        rolename = roleinfo.get('name')
        logger.debug('Adding delegated role: ' + str(rolename) + '.')
        tuf.roledb.add_role(rolename, roleinfo, self.repository_name)

      except tuf.exceptions.RoleAlreadyExistsError:
        logger.warning('Role already exists: ' + rolename)

      except:
        logger.exception('Failed to add delegated role: ' + repr(rolename) + '.')
        raise





  def refresh(self, unsafely_update_root_if_necessary=True):
    """
    <Purpose>
      Update the latest copies of the metadata for the top-level roles. The
      update request process follows a specific order to ensure the metadata
      files are securely updated:
      timestamp -> snapshot -> root (if necessary) -> targets.

      Delegated metadata is not refreshed by this method. After this method is
      called, the use of target methods (e.g., all_targets(),
      targets_of_role(), or get_one_valid_targetinfo()) will update delegated
      metadata, when required.  Calling refresh() ensures that top-level
      metadata is up-to-date, so that the target methods can refer to the
      latest available content. Thus, refresh() should always be called by the
      client before any requests of target file information.

      The expiration time for downloaded metadata is also verified, including
      local metadata that the repository claims is up to date.

      If the refresh fails for any reason, then unless
      'unsafely_update_root_if_necessary' is set, refresh will be retried once
      after first attempting to update the root metadata file. Only after this
      check will the exceptions listed here potentially be raised.

    <Arguments>
      unsafely_update_root_if_necessary:
        Boolean that indicates whether to unsafely update the Root metadata if
        any of the top-level metadata cannot be downloaded successfully.  The
        Root role is unsafely updated if its current version number is unknown.

    <Exceptions>
      tuf.exceptions.NoWorkingMirrorError:
        If the metadata for any of the top-level roles cannot be updated.

      tuf.exceptions.ExpiredMetadataError:
         If any of the top-level metadata is expired (whether a new version was
         downloaded expired or no new version was found and the existing
         version is now expired).

    <Side Effects>
      Updates the metadata files of the top-level roles with the latest
      information.

    <Returns>
      None.
    """

    # Do the arguments have the correct format?
    # This check ensures the arguments have the appropriate
    # number of objects and object types, and that all dict
    # keys are properly named.
    # Raise 'securesystemslib.exceptions.FormatError' if the check fail.
    securesystemslib.formats.BOOLEAN_SCHEMA.check_match(unsafely_update_root_if_necessary)

    # The Timestamp role does not have signed metadata about it; otherwise we
    # would need an infinite regress of metadata. Therefore, we use some
    # default, but sane, upper file length for its metadata.
    DEFAULT_TIMESTAMP_UPPERLENGTH = tuf.settings.DEFAULT_TIMESTAMP_REQUIRED_LENGTH

    # The Root role may be updated without knowing its version number if
    # top-level metadata cannot be safely downloaded (e.g., keys may have been
    # revoked, thus requiring a new Root file that includes the updated keys)
    # and 'unsafely_update_root_if_necessary' is True.
    # We use some default, but sane, upper file length for its metadata.
    DEFAULT_ROOT_UPPERLENGTH = tuf.settings.DEFAULT_ROOT_REQUIRED_LENGTH

    # Update the top-level metadata.  The _update_metadata_if_changed() and
    # _update_metadata() calls below do NOT perform an update if there
    # is insufficient trusted signatures for the specified metadata.
    # Raise 'tuf.exceptions.NoWorkingMirrorError' if an update fails.
    root_metadata = self.metadata['current']['root']

    try:
      self._ensure_not_expired(root_metadata, 'root')

    except tuf.exceptions.ExpiredMetadataError:
      # Raise 'tuf.exceptions.NoWorkingMirrorError' if a valid (not
      # expired, properly signed, and valid metadata) 'root.json' cannot be
      # installed.
      if unsafely_update_root_if_necessary:
        logger.info('Expired Root metadata was loaded from disk.'
          '  Try to update it now.' )

      # The caller explicitly requested not to unsafely fetch an expired Root.
      else:
        logger.info('An expired Root metadata was loaded and must be updated.')
        raise

    # TODO: How should the latest root metadata be verified?  According to the
    # currently trusted root keys?  What if all of the currently trusted
    # root keys have since been revoked by the latest metadata?  Alternatively,
    # do we blindly trust the downloaded root metadata here?
    self._update_root_metadata(root_metadata)

    # Use default but sane information for timestamp metadata, and do not
    # require strict checks on its required length.
    self._update_metadata('timestamp', DEFAULT_TIMESTAMP_UPPERLENGTH)
    # TODO: After fetching snapshot.json, we should either verify the root
    # fileinfo referenced there matches what was fetched earlier in
    # _update_root_metadata() or make another attempt to download root.json.
    self._update_metadata_if_changed('snapshot',
                                     referenced_metadata='timestamp')
    self._update_metadata_if_changed('targets')



  def _update_root_metadata(self, current_root_metadata):
    """
    <Purpose>
      The root file must be signed by the current root threshold and keys as
      well as the previous root threshold and keys. The update process for root
      files means that each intermediate root file must be downloaded, to build
      a chain of trusted root keys from keys already trusted by the client:

        1.root -> 2.root -> 3.root

      3.root must be signed by the threshold and keys of 2.root, and 2.root
      must be signed by the threshold and keys of 1.root.

    <Arguments>
      current_root_metadata:
        The currently held version of root.

    <Side Effects>
      Updates the root metadata files with the latest information.

    <Returns>
      None.
    """

    # Retrieve the latest, remote root.json.
    latest_root_metadata_file = \
      self._get_metadata_file('root', 'root.json',
        tuf.settings.DEFAULT_ROOT_REQUIRED_LENGTH, None)
    latest_root_metadata = \
      securesystemslib.util.load_json_string(latest_root_metadata_file.read().decode('utf-8'))


    next_version = current_root_metadata['version'] + 1
    latest_version = latest_root_metadata['signed']['version']

    # update from the next version of root up to (and including) the latest
    # version.  For example:
    # current = version 1
    # latest = version 3
    # update from 1.root.json to 3.root.json.
    for version in range(next_version, latest_version + 1):
      # Temporarily set consistent snapshot. Will be updated to whatever is set
      # in the latest root.json after running through the intermediates with
      # _update_metadata().
      self.consistent_snapshot = True
      self._update_metadata('root', tuf.settings.DEFAULT_ROOT_REQUIRED_LENGTH,
          version=version)



  def _check_hashes(self, file_object, trusted_hashes):
    """
    <Purpose>
      Non-public method that verifies multiple secure hashes of the downloaded
      file 'file_object'.  If any of these fail it raises an exception.  This is
      to conform with the TUF spec, which support clients with different hashing
      algorithms. The 'hash.py' module is used to compute the hashes of
      'file_object'.

    <Arguments>
      file_object:
        A 'securesystemslib.util.TempFile' file-like object.  'file_object' ensures that a
        read() without a size argument properly reads the entire file.

      trusted_hashes:
        A dictionary with hash-algorithm names as keys and hashes as dict values.
        The hashes should be in the hexdigest format.  Should be Conformant to
        'securesystemslib.formats.HASHDICT_SCHEMA'.

    <Exceptions>
      securesystemslib.exceptions.BadHashError, if the hashes don't match.

    <Side Effects>
      Hash digest object is created using the 'securesystemslib.hash' module.

    <Returns>
      None.
    """

    # Verify each trusted hash of 'trusted_hashes'.  If all are valid, simply
    # return.
    for algorithm, trusted_hash in six.iteritems(trusted_hashes):
      digest_object = securesystemslib.hash.digest(algorithm)
      digest_object.update(file_object.read())
      computed_hash = digest_object.hexdigest()

      # Raise an exception if any of the hashes are incorrect.
      if trusted_hash != computed_hash:
        raise securesystemslib.exceptions.BadHashError(trusted_hash, computed_hash)
      else:
        logger.info('The file\'s ' + algorithm + ' hash is correct: ' + trusted_hash)





  def _hard_check_file_length(self, file_object, trusted_file_length):
    """
    <Purpose>
      Non-public method that ensures the length of 'file_object' is strictly
      equal to 'trusted_file_length'.  This is a deliberately redundant
      implementation designed to complement
      tuf.download._check_downloaded_length().

    <Arguments>
      file_object:
        A 'securesystemslib.util.TempFile' file-like object.  'file_object'
        ensures that a read() without a size argument properly reads the entire
        file.

      trusted_file_length:
        A non-negative integer that is the trusted length of the file.

    <Exceptions>
      tuf.exceptions.DownloadLengthMismatchError, if the lengths do not match.

    <Side Effects>
      Reads the contents of 'file_object' and logs a message if 'file_object'
      matches the trusted length.

    <Returns>
      None.
    """

    # Read the entire contents of 'file_object', a 'securesystemslib.util.TempFile' file-like
    # object that ensures the entire file is read.
    observed_length = len(file_object.read())

    # Return and log a message if the length 'file_object' is equal to
    # 'trusted_file_length', otherwise raise an exception.  A hard check
    # ensures that a downloaded file strictly matches a known, or trusted,
    # file length.
    if observed_length != trusted_file_length:
      raise tuf.exceptions.DownloadLengthMismatchError(trusted_file_length,
                                            observed_length)
    else:
      logger.debug('Observed length ('+str(observed_length)+\
                   ') == trusted length ('+str(trusted_file_length)+')')





  def _soft_check_file_length(self, file_object, trusted_file_length):
    """
    <Purpose>
      Non-public method that checks the trusted file length of a
      'securesystemslib.util.TempFile' file-like object. The length of the file
      must be less than or equal to the expected length. This is a deliberately
      redundant implementation designed to complement
      tuf.download._check_downloaded_length().

    <Arguments>
      file_object:
        A 'securesystemslib.util.TempFile' file-like object.  'file_object'
        ensures that a read() without a size argument properly reads the entire
        file.

      trusted_file_length:
        A non-negative integer that is the trusted length of the file.

    <Exceptions>
      tuf.exceptions.DownloadLengthMismatchError, if the lengths do
      not match.

    <Side Effects>
      Reads the contents of 'file_object' and logs a message if 'file_object'
      is less than or equal to the trusted length.

    <Returns>
      None.
    """

    # Read the entire contents of 'file_object', a
    # 'securesystemslib.util.TempFile' file-like object that ensures the entire
    # file is read.
    observed_length = len(file_object.read())

    # Return and log a message if 'file_object' is less than or equal to
    # 'trusted_file_length', otherwise raise an exception.  A soft check
    # ensures that an upper bound restricts how large a file is downloaded.
    if observed_length > trusted_file_length:
      raise tuf.exceptions.DownloadLengthMismatchError(trusted_file_length,
                                            observed_length)
    else:
      logger.debug('Observed length ('+str(observed_length)+\
                   ') <= trusted length ('+str(trusted_file_length)+')')





  def _get_target_file(self, target_filepath, file_length, file_hashes):
    """
    <Purpose>
      Non-public method that safely (i.e., the file length and hash are strictly
      equal to the trusted) downloads a target file up to a certain length, and
      checks its hashes thereafter.

    <Arguments>
      target_filepath:
        The target filepath (relative to the repository targets directory)
        obtained from TUF targets metadata.

      file_length:
        The expected compressed length of the target file. If the file is not
        compressed, then it will simply be its uncompressed length.

      file_hashes:
        The expected hashes of the target file.

    <Exceptions>
      tuf.exceptions.NoWorkingMirrorError:
        The target could not be fetched. This is raised only when all known
        mirrors failed to provide a valid copy of the desired target file.

    <Side Effects>
      The target file is downloaded from all known repository mirrors in the
      worst case. If a valid copy of the target file is found, it is stored in
      a temporary file and returned.

    <Returns>
      A 'securesystemslib.util.TempFile' file-like object containing the target.
    """

    # Define a callable function that is passed as an argument to _get_file()
    # and called.  The 'verify_target_file' function ensures the file length
    # and hashes of 'target_filepath' are strictly equal to the trusted values.
    def verify_target_file(target_file_object):

      # Every target file must have its length and hashes inspected.
      self._hard_check_file_length(target_file_object, file_length)
      self._check_hashes(target_file_object, file_hashes)

    if self.consistent_snapshot:
      target_digest = random.choice(list(file_hashes.values()))
      dirname, basename = os.path.split(target_filepath)
      target_filepath = os.path.join(dirname, target_digest + '.' + basename)

    return self._get_file(target_filepath, verify_target_file,
        'target', file_length, download_safely=True)





  def _verify_uncompressed_metadata_file(self, metadata_file_object,
                                         metadata_role):
    """
    <Purpose>
      Non-public method that verifies an uncompressed metadata file.  An
      exception is raised if 'metadata_file_object is invalid.  There is no
      return value.

    <Arguments>
      metadata_file_object:
        A 'securesystemslib.util.TempFile' instance containing the metadata file.
        'metadata_file_object' ensures the entire file is returned with read().

      metadata_role:
        The role name of the metadata (e.g., 'root', 'targets',
        'unclaimed').

    <Exceptions>
      securesystemslib.exceptions.FormatError:
        In case the metadata file is valid JSON, but not valid TUF metadata.

      tuf.exceptions.InvalidMetadataJSONError:
        In case the metadata file is not valid JSON.

      tuf.exceptions.ReplayedMetadataError:
        In case the downloaded metadata file is older than the current one.

      tuf.exceptions.RepositoryError:
        In case the repository is somehow inconsistent; e.g. a parent has not
        delegated to a child (contrary to expectations).

      tuf.SignatureError:
        In case the metadata file does not have a valid signature.

    <Side Effects>
      The content of 'metadata_file_object' is read and loaded.

    <Returns>
      None.
    """

    metadata = metadata_file_object.read().decode('utf-8')

    try:
      metadata_signable = securesystemslib.util.load_json_string(metadata)

    except Exception as exception:
      raise tuf.exceptions.InvalidMetadataJSONError(exception)

    else:
      # Ensure the loaded 'metadata_signable' is properly formatted.  Raise
      # 'securesystemslib.exceptions.FormatError' if not.
      tuf.formats.check_signable_object_format(metadata_signable)

    # Is 'metadata_signable' expired?
    self._ensure_not_expired(metadata_signable['signed'], metadata_role)

    # We previously verified version numbers in this function, but have since
    # moved version number verification to the functions that retrieve
    # metadata.

    # Verify the signature on the downloaded metadata object.

    valid = tuf.sig.verify(metadata_signable, metadata_role, self.repository_name)

    if not valid:
      raise securesystemslib.exceptions.BadSignatureError(metadata_role)





  def _get_metadata_file(self, metadata_role, remote_filename,
    upperbound_filelength, expected_version):
    """
    <Purpose>
      Non-public method that tries downloading, up to a certain length, a
      metadata file from a list of known mirrors. As soon as the first valid
      copy of the file is found, the downloaded file is returned and the
      remaining mirrors are skipped.

    <Arguments>
      metadata_role:
        The role name of the metadata (e.g., 'root', 'targets', 'unclaimed').

      remote_filename:
        The relative file path (on the remove repository) of 'metadata_role'.

      upperbound_filelength:
        The expected length, or upper bound, of the metadata file to be
        downloaded.

      expected_version:
        The expected and required version number of the 'metadata_role' file
        downloaded.  'expected_version' is an integer.

    <Exceptions>
      tuf.exceptions.NoWorkingMirrorError:
        The metadata could not be fetched. This is raised only when all known
        mirrors failed to provide a valid copy of the desired metadata file.

    <Side Effects>
      The file is downloaded from all known repository mirrors in the worst
      case. If a valid copy of the file is found, it is stored in a temporary
      file and returned.

    <Returns>
      A 'securesystemslib.util.TempFile' file-like object containing the metadata.
    """

    file_mirrors = tuf.mirrors.get_list_of_mirrors('meta', remote_filename,
                                                   self.mirrors)
    # file_mirror (URL): error (Exception)
    file_mirror_errors = {}
    file_object = None

    for file_mirror in file_mirrors:
      try:
        file_object = tuf.download.unsafe_download(file_mirror,
                                                   upperbound_filelength)

        # Verify 'file_object' according to the callable function.
        # 'file_object' is also verified if decompressed above (i.e., the
        # uncompressed version).
        metadata_signable = \
          securesystemslib.util.load_json_string(file_object.read().decode('utf-8'))

        # Determine if the specification version number is supported.  It is
        # assumed that "spec_version" is in (major.minor.fix) format, (for
        # example: "1.4.3") and that releases with the same major version
        # number maintain backwards compatibility.  Consequently, if the major
        # version number of new metadata equals our expected major version
        # number, the new metadata is safe to parse.
        try:
          spec_version_parsed = metadata_signable['signed']['spec_version'].split('.')
          if int(spec_version_parsed[0]) != SUPPORTED_MAJOR_VERSION:
            raise securesystemslib.exceptions.BadVersionNumberError('Downloaded'
              ' metadata that specifies an unsupported spec_version.  Supported'
              ' major version number: ' + repr(SUPPORTED_MAJOR_VERSION))

        except (ValueError, TypeError):
          raise securesystemslib.exceptions.FormatError('Improperly'
            ' formatted spec_version, which must be in major.minor.fix format')

        # If the version number is unspecified, ensure that the version number
        # downloaded is greater than the currently trusted version number for
        # 'metadata_role'.
        version_downloaded = metadata_signable['signed']['version']

        if expected_version is not None:
          # Verify that the downloaded version matches the version expected by
          # the caller.
          if version_downloaded != expected_version:
            raise securesystemslib.exceptions.BadVersionNumberError('Downloaded'
              ' version number: ' + repr(version_downloaded) + '.  Version'
              ' number MUST be: ' + repr(expected_version))

        # The caller does not know which version to download.  Verify that the
        # downloaded version is at least greater than the one locally available.
        else:
          # Verify that the version number of the locally stored
          # 'timestamp.json', if available, is less than what was downloaded.
          # Otherwise, accept the new timestamp with version number
          # 'version_downloaded'.

          try:
            current_version = \
              self.metadata['current'][metadata_role]['version']

            if version_downloaded < current_version:
              raise tuf.exceptions.ReplayedMetadataError(metadata_role, version_downloaded,
                                              current_version)

          except KeyError:
            logger.info(metadata_role + ' not available locally.')

        self._verify_uncompressed_metadata_file(file_object, metadata_role)

      except Exception as exception:
        # Remember the error from this mirror, and "reset" the target file.
        logger.exception('Update failed from ' + file_mirror + '.')
        file_mirror_errors[file_mirror] = exception
        file_object = None

      else:
        break

    if file_object:
      return file_object

    else:
      logger.error('Failed to update ' + repr(remote_filename) + ' from all'
        ' mirrors: ' + repr(file_mirror_errors))
      raise tuf.exceptions.NoWorkingMirrorError(file_mirror_errors)



  def _verify_root_chain_link(self, role, current, next):
    if role != 'root':
      return True

    current_role = current['roles'][role]

    # Verify next metadata with current keys/threshold
    valid = tuf.sig.verify(next, role, self.repository_name,
                           current_role['threshold'], current_role['keyids'])

    if not valid:
      raise securesystemslib.exceptions.BadSignatureError('Root is not signed'
          ' by previous threshold of keys.')





  def _get_file(self, filepath, verify_file_function, file_type,
    file_length, download_safely=True):
    """
    <Purpose>
      Non-public method that tries downloading, up to a certain length, a
      metadata or target file from a list of known mirrors. As soon as the first
      valid copy of the file is found, the rest of the mirrors will be skipped.

    <Arguments>
      filepath:
        The relative metadata or target filepath.

      verify_file_function:
        A callable function that expects a 'securesystemslib.util.TempFile'
        file-like object and raises an exception if the file is invalid.
        Target files and uncompressed versions of metadata may be verified with
        'verify_file_function'.

      file_type:
        Type of data needed for download, must correspond to one of the strings
        in the list ['meta', 'target'].  'meta' for metadata file type or
        'target' for target file type.  It should correspond to the
        'securesystemslib.formats.NAME_SCHEMA' format.

      file_length:
        The expected length, or upper bound, of the target or metadata file to
        be downloaded.

      download_safely:
        A boolean switch to toggle safe or unsafe download of the file.

    <Exceptions>
      tuf.exceptions.NoWorkingMirrorError:
        The metadata could not be fetched. This is raised only when all known
        mirrors failed to provide a valid copy of the desired metadata file.

    <Side Effects>
      The file is downloaded from all known repository mirrors in the worst
      case. If a valid copy of the file is found, it is stored in a temporary
      file and returned.

    <Returns>
      A 'securesystemslib.util.TempFile' file-like object containing the metadata
      or target.
    """

    file_mirrors = tuf.mirrors.get_list_of_mirrors(file_type, filepath,
                                                   self.mirrors)
    # file_mirror (URL): error (Exception)
    file_mirror_errors = {}
    file_object = None

    for file_mirror in file_mirrors:
      try:
        # TODO: Instead of the more fragile 'download_safely' switch, unroll
        # the function into two separate ones: one for "safe" download, and the
        # other one for "unsafe" download? This should induce safer and more
        # readable code.
        if download_safely:
          file_object = tuf.download.safe_download(file_mirror,
                                                   file_length)
        else:
          file_object = tuf.download.unsafe_download(file_mirror,
                                                     file_length)

        # Verify 'file_object' according to the callable function.
        # 'file_object' is also verified if decompressed above (i.e., the
        # uncompressed version).
        verify_file_function(file_object)

      except Exception as exception:
        # Remember the error from this mirror, and "reset" the target file.
        logger.exception('Update failed from ' + file_mirror + '.')
        file_mirror_errors[file_mirror] = exception
        file_object = None

      else:
        break

    if file_object:
      return file_object

    else:
      logger.error('Failed to update {0} from all mirrors: {1}'.format(
                   filepath, file_mirror_errors))
      raise tuf.exceptions.NoWorkingMirrorError(file_mirror_errors)





  def _update_metadata(self, metadata_role, upperbound_filelength, version=None):
    """
    <Purpose>
      Non-public method that downloads, verifies, and 'installs' the metadata
      belonging to 'metadata_role'.  Calling this method implies the metadata
      has been updated by the repository and thus needs to be re-downloaded.
      The current and previous metadata stores are updated if the newly
      downloaded metadata is successfully downloaded and verified.

    <Arguments>
      metadata_role:
        The name of the metadata. This is a role name and should not end
        in '.json'.  Examples: 'root', 'targets', 'targets/linux/x86'.

      upperbound_filelength:
        The expected length, or upper bound, of the metadata file to be
        downloaded.

      version:
        The expected and required version number of the 'metadata_role' file
        downloaded.  'expected_version' is an integer.

    <Exceptions>
      tuf.exceptions.NoWorkingMirrorError:
        The metadata cannot be updated. This is not specific to a single
        failure but rather indicates that all possible ways to update the
        metadata have been tried and failed.

    <Side Effects>
      The metadata file belonging to 'metadata_role' is downloaded from a
      repository mirror.  If the metadata is valid, it is stored in the
      metadata store.

    <Returns>
      None.
    """

    # Construct the metadata filename as expected by the download/mirror modules.
    metadata_filename = metadata_role + '.json'
    metadata_filename = metadata_filename

    # Attempt a file download from each mirror until the file is downloaded and
    # verified.  If the signature of the downloaded file is valid, proceed,
    # otherwise log a warning and try the next mirror.  'metadata_file_object'
    # is the file-like object returned by 'download.py'.  'metadata_signable'
    # is the object extracted from 'metadata_file_object'.  Metadata saved to
    # files are regarded as 'signable' objects, conformant to
    # 'tuf.formats.SIGNABLE_SCHEMA'.
    #
    # Some metadata (presently timestamp) will be downloaded "unsafely", in the
    # sense that we can only estimate its true length and know nothing about
    # its version.  This is because not all metadata will have other metadata
    # for it; otherwise we will have an infinite regress of metadata signing
    # for each other. In this case, we will download the metadata up to the
    # best length we can get for it, not request a specific version, but
    # perform the rest of the checks (e.g., signature verification).

    remote_filename = metadata_filename
    filename_version = ''

    if self.consistent_snapshot and version:
      filename_version = version
      dirname, basename = os.path.split(remote_filename)
      remote_filename = os.path.join(dirname, str(filename_version) + '.' + basename)

    metadata_file_object = \
      self._get_metadata_file(metadata_role, remote_filename,
        upperbound_filelength, version)

    # The metadata has been verified. Move the metadata file into place.
    # First, move the 'current' metadata file to the 'previous' directory
    # if it exists.
    current_filepath = os.path.join(self.metadata_directory['current'],
                                    metadata_filename)
    current_filepath = os.path.abspath(current_filepath)
    securesystemslib.util.ensure_parent_dir(current_filepath)

    previous_filepath = os.path.join(self.metadata_directory['previous'],
                                     metadata_filename)
    previous_filepath = os.path.abspath(previous_filepath)

    if os.path.exists(current_filepath):
      # Previous metadata might not exist, say when delegations are added.
      securesystemslib.util.ensure_parent_dir(previous_filepath)
      shutil.move(current_filepath, previous_filepath)

    # Next, move the verified updated metadata file to the 'current' directory.
    # Note that the 'move' method comes from securesystemslib.util's TempFile class.
    # 'metadata_file_object' is an instance of securesystemslib.util.TempFile.
    metadata_signable = \
      securesystemslib.util.load_json_string(metadata_file_object.read().decode('utf-8'))

    metadata_file_object.move(current_filepath)

    # Extract the metadata object so we can store it to the metadata store.
    # 'current_metadata_object' set to 'None' if there is not an object
    # stored for 'metadata_role'.
    updated_metadata_object = metadata_signable['signed']
    current_metadata_object = self.metadata['current'].get(metadata_role)

    self._verify_root_chain_link(metadata_role, current_metadata_object,
                                      metadata_signable)

    # Finally, update the metadata and fileinfo stores, and rebuild the
    # key and role info for the top-level roles if 'metadata_role' is root.
    # Rebuilding the the key and role info is required if the newly-installed
    # root metadata has revoked keys or updated any top-level role information.
    logger.debug('Updated ' + repr(current_filepath) + '.')
    self.metadata['previous'][metadata_role] = current_metadata_object
    self.metadata['current'][metadata_role] = updated_metadata_object
    self._update_versioninfo(metadata_filename)

    # Ensure the role and key information of the top-level roles is also updated
    # according to the newly-installed Root metadata.
    if metadata_role == 'root':
      self._rebuild_key_and_role_db()
      self.consistent_snapshot = updated_metadata_object['consistent_snapshot']





  def _update_metadata_if_changed(self, metadata_role,
    referenced_metadata='snapshot'):
    """
    <Purpose>
      Non-public method that updates the metadata for 'metadata_role' if it has
      changed.  With the exception of the 'timestamp' role, all the top-level
      roles are updated by this method.  The 'timestamp' role is always
      downloaded from a mirror without first checking if it has been updated; it
      is updated in refresh() by calling _update_metadata('timestamp').  This
      method is also called for delegated role metadata, which are referenced by
      'snapshot'.

      If the metadata needs to be updated but an update cannot be obtained,
      this method will delete the file (with the exception of the root
      metadata, which never gets removed without a replacement).

      Due to the way in which metadata files are updated, it is expected that
      'referenced_metadata' is not out of date and trusted.  The refresh()
      method updates the top-level roles in 'timestamp -> snapshot ->
      root -> targets' order.  For delegated metadata, the parent role is
      updated before the delegated role.  Taking into account that
      'referenced_metadata' is updated and verified before 'metadata_role',
      this method determines if 'metadata_role' has changed by checking
      the 'meta' field of the newly updated 'referenced_metadata'.

    <Arguments>
      metadata_role:
        The name of the metadata. This is a role name and should not end
        in '.json'.  Examples: 'root', 'targets', 'unclaimed'.

      referenced_metadata:
        This is the metadata that provides the role information for
        'metadata_role'.  For the top-level roles, the 'snapshot' role
        is the referenced metadata for the 'root', and 'targets' roles.
        The 'timestamp' metadata is always downloaded regardless.  In
        other words, it is updated by calling _update_metadata('timestamp')
        and not by this method.  The referenced metadata for 'snapshot'
        is 'timestamp'.  See refresh().

    <Exceptions>
      tuf.exceptions.NoWorkingMirrorError:
        If 'metadata_role' could not be downloaded after determining that it had
        changed.

      tuf.exceptions.RepositoryError:
        If the referenced metadata is missing.

    <Side Effects>
      If it is determined that 'metadata_role' has been updated, the metadata
      store (i.e., self.metadata) is updated with the new metadata and the
      affected stores modified (i.e., the previous metadata store is updated).
      If the metadata is 'targets' or a delegated targets role, the role
      database is updated with the new information, including its delegated
      roles.

    <Returns>
      None.
    """

    metadata_filename = metadata_role + '.json'
    expected_versioninfo = None
    expected_fileinfo = None

    # Ensure the referenced metadata has been loaded.  The 'root' role may be
    # updated without having 'snapshot' available.
    if referenced_metadata not in self.metadata['current']:
      raise tuf.exceptions.RepositoryError('Cannot update'
        ' ' + repr(metadata_role) + ' because ' + referenced_metadata + ' is'
        ' missing.')

    # The referenced metadata has been loaded.  Extract the new versioninfo for
    # 'metadata_role' from it.
    else:
      logger.debug(repr(metadata_role) + ' referenced in ' +
        repr(referenced_metadata)+ '.  ' + repr(metadata_role) +
        ' may be updated.')

    # Simply return if the metadata for 'metadata_role' has not been updated,
    # according to the uncompressed metadata provided by the referenced
    # metadata.  The metadata is considered updated if its version number is
    # strictly greater than its currently trusted version number.
    expected_versioninfo = self.metadata['current'][referenced_metadata] \
                                        ['meta'] \
                                        [metadata_filename]

    if not self._versioninfo_has_been_updated(metadata_filename,
                                              expected_versioninfo):
      logger.info(repr(metadata_filename) + ' up-to-date.')

      # Since we have not downloaded a new version of this metadata, we should
      # check to see if our local version is stale and notify the user if so.
      # This raises tuf.exceptions.ExpiredMetadataError if the metadata we have
      # is expired. Resolves issue #322.
      self._ensure_not_expired(self.metadata['current'][metadata_role],
                               metadata_role)

      # TODO: If 'metadata_role' is root or snapshot, we should verify that
      # root's hash matches what's in snapshot, and that snapshot hash matches
      # what's listed in timestamp.json.

      return

    logger.debug('Metadata ' + repr(metadata_filename) + ' has changed.')

    # The file lengths of metadata are unknown, only their version numbers are
    # known.  Set an upper limit for the length of the downloaded file for each
    # expected role.  Note: The Timestamp role is not updated via this
    # function.
    if metadata_role == 'snapshot':
      upperbound_filelength = tuf.settings.DEFAULT_SNAPSHOT_REQUIRED_LENGTH

    elif metadata_role == 'root':
      upperbound_filelength = tuf.settings.DEFAULT_ROOT_REQUIRED_LENGTH

    # The metadata is considered Targets (or delegated Targets metadata).
    else:
      upperbound_filelength = tuf.settings.DEFAULT_TARGETS_REQUIRED_LENGTH

    try:
      self._update_metadata(metadata_role, upperbound_filelength,
          expected_versioninfo['version'])

    except:
      # The current metadata we have is not current but we couldn't get new
      # metadata. We shouldn't use the old metadata anymore.  This will get rid
      # of in-memory knowledge of the role and delegated roles, but will leave
      # delegated metadata files as current files on disk.
      #
      # TODO: Should we get rid of the delegated metadata files?  We shouldn't
      # need to, but we need to check the trust implications of the current
      # implementation.
      self._delete_metadata(metadata_role)
      logger.error('Metadata for ' + repr(metadata_role) + ' cannot be updated.')
      raise

    else:
      # We need to import the delegated roles of 'metadata_role', since its
      # list of delegations might have changed from what was previously
      # loaded..
      # TODO: Should we remove the keys of the delegated roles?
      self._import_delegations(metadata_role)





  def _versioninfo_has_been_updated(self, metadata_filename, new_versioninfo):
    """
    <Purpose>
      Non-public method that determines whether the current versioninfo of
      'metadata_filename' is less than 'new_versioninfo' (i.e., the version
      number has been incremented).  The 'new_versioninfo' argument should be
      extracted from the latest copy of the metadata that references
      'metadata_filename'.  Example: 'root.json' would be referenced by
      'snapshot.json'.

      'new_versioninfo' should only be 'None' if this is for updating
      'root.json' without having 'snapshot.json' available.

    <Arguments>
      metadadata_filename:
        The metadata filename for the role.  For the 'root' role,
        'metadata_filename' would be 'root.json'.

      new_versioninfo:
        A dict object representing the new file information for
        'metadata_filename'.  'new_versioninfo' may be 'None' when
        updating 'root' without having 'snapshot' available.  This
        dict conforms to 'securesystemslib.formats.VERSIONINFO_SCHEMA' and has
        the form:

        {'version': 288}

    <Exceptions>
      None.

    <Side Effects>
      If there is no versioninfo currently loaded for 'metadata_filename', try
      to load it.

    <Returns>
      Boolean.  True if the versioninfo has changed, False otherwise.
    """

    # If there is no versioninfo currently stored for 'metadata_filename',
    # try to load the file, calculate the versioninfo, and store it.
    if metadata_filename not in self.versioninfo:
      self._update_versioninfo(metadata_filename)

    # Return true if there is no versioninfo for 'metadata_filename'.
    # 'metadata_filename' is not in the 'self.versioninfo' store
    # and it doesn't exist in the 'current' metadata location.
    if self.versioninfo[metadata_filename] is None:
      return True

    current_versioninfo = self.versioninfo[metadata_filename]

    if new_versioninfo['version'] > current_versioninfo['version']:
      return True

    else:
      return False





  def _update_versioninfo(self, metadata_filename):
    """
    <Purpose>
      Non-public method that updates the 'self.versioninfo' entry for the
      metadata belonging to 'metadata_filename'.  If the current metadata for
      'metadata_filename' cannot be loaded, set its 'versioninfo' to 'None' to
      signal that it is not in 'self.versioninfo' AND it also doesn't exist
      locally.

    <Arguments>
      metadata_filename:
        The metadata filename for the role.  For the 'root' role,
        'metadata_filename' would be 'root.json'.

    <Exceptions>
      None.

    <Side Effects>
      The version number of 'metadata_filename' is calculated and stored in its
      corresponding entry in 'self.versioninfo'.

    <Returns>
      None.
    """

    # In case we delayed loading the metadata and didn't do it in
    # __init__ (such as with delegated metadata), then get the version
    # info now.

    # Save the path to the current metadata file for 'metadata_filename'.
    current_filepath = os.path.join(self.metadata_directory['current'],
                                    metadata_filename)
    # If the path is invalid, simply return and leave versioninfo unset.
    if not os.path.exists(current_filepath):
      self.versioninfo[metadata_filename] = None
      return

    # Extract the version information from the trusted snapshot role and save
    # it to the 'self.versioninfo' store.
    if metadata_filename == 'timestamp.json':
      trusted_versioninfo = \
        self.metadata['current']['timestamp']['version']

    # When updating snapshot.json, the client either (1) has a copy of
    # snapshot.json, or (2) is in the process of obtaining it by first
    # downloading timestamp.json.  Note: Clients are allowed to have only
    # root.json initially, and perform a refresh of top-level metadata to
    # obtain the remaining roles.
    elif metadata_filename == 'snapshot.json':

      # Verify the version number of the currently trusted snapshot.json in
      # snapshot.json itself.  Checking the version number specified in
      # timestamp.json may be greater than the version specified in the
      # client's copy of snapshot.json.
      try:
        timestamp_version_number = self.metadata['current']['snapshot']['version']
        trusted_versioninfo = tuf.formats.make_versioninfo(timestamp_version_number)

      except KeyError:
        trusted_versioninfo = \
          self.metadata['current']['timestamp']['meta']['snapshot.json']

    else:

      try:
        # The metadata file names in 'self.metadata' exclude the role
        # extension.  Strip the '.json' extension when checking if
        # 'metadata_filename' currently exists.
        targets_version_number = \
          self.metadata['current'][metadata_filename[:-len('.json')]]['version']
        trusted_versioninfo = \
          tuf.formats.make_versioninfo(targets_version_number)

      except KeyError:
        trusted_versioninfo = \
          self.metadata['current']['snapshot']['meta'][metadata_filename]

    self.versioninfo[metadata_filename] = trusted_versioninfo





  def _fileinfo_has_changed(self, metadata_filename, new_fileinfo):
    """
    <Purpose>
      Non-public method that determines whether the current fileinfo of
      'metadata_filename' differs from 'new_fileinfo'.  The 'new_fileinfo'
      argument should be extracted from the latest copy of the metadata that
      references 'metadata_filename'.  Example: 'root.json' would be referenced
      by 'snapshot.json'.

      'new_fileinfo' should only be 'None' if this is for updating 'root.json'
      without having 'snapshot.json' available.

    <Arguments>
      metadadata_filename:
        The metadata filename for the role.  For the 'root' role,
        'metadata_filename' would be 'root.json'.

      new_fileinfo:
        A dict object representing the new file information for
        'metadata_filename'.  'new_fileinfo' may be 'None' when
        updating 'root' without having 'snapshot' available.  This
        dict conforms to 'tuf.formats.FILEINFO_SCHEMA' and has
        the form:

        {'length': 23423
         'hashes': {'sha256': adfbc32343..}}

    <Exceptions>
      None.

    <Side Effects>
      If there is no fileinfo currently loaded for 'metada_filename',
      try to load it.

    <Returns>
      Boolean.  True if the fileinfo has changed, false otherwise.
    """

    # If there is no fileinfo currently stored for 'metadata_filename',
    # try to load the file, calculate the fileinfo, and store it.
    if metadata_filename not in self.fileinfo:
      self._update_fileinfo(metadata_filename)

    # Return true if there is no fileinfo for 'metadata_filename'.
    # 'metadata_filename' is not in the 'self.fileinfo' store
    # and it doesn't exist in the 'current' metadata location.
    if self.fileinfo[metadata_filename] is None:
      return True

    current_fileinfo = self.fileinfo[metadata_filename]

    if current_fileinfo['length'] != new_fileinfo['length']:
      return True

    # Now compare hashes. Note that the reason we can't just do a simple
    # equality check on the fileinfo dicts is that we want to support the
    # case where the hash algorithms listed in the metadata have changed
    # without having that result in considering all files as needing to be
    # updated, or not all hash algorithms listed can be calculated on the
    # specific client.
    for algorithm, hash_value in six.iteritems(new_fileinfo['hashes']):
      # We're only looking for a single match. This isn't a security
      # check, we just want to prevent unnecessary downloads.
      if algorithm in current_fileinfo['hashes']:
        if hash_value == current_fileinfo['hashes'][algorithm]:
          return False

    return True





  def _update_fileinfo(self, metadata_filename):
    """
    <Purpose>
      Non-public method that updates the 'self.fileinfo' entry for the metadata
      belonging to 'metadata_filename'.  If the 'current' metadata for
      'metadata_filename' cannot be loaded, set its fileinfo' to 'None' to
      signal that it is not in the 'self.fileinfo' AND it also doesn't exist
      locally.

    <Arguments>
      metadata_filename:
        The metadata filename for the role.  For the 'root' role,
        'metadata_filename' would be 'root.json'.

    <Exceptions>
      None.

    <Side Effects>
      The file details of 'metadata_filename' is calculated and
      stored in 'self.fileinfo'.

    <Returns>
      None.
    """

    # In case we delayed loading the metadata and didn't do it in
    # __init__ (such as with delegated metadata), then get the file
    # info now.

    # Save the path to the current metadata file for 'metadata_filename'.
    current_filepath = os.path.join(self.metadata_directory['current'],
                                    metadata_filename)
    # If the path is invalid, simply return and leave fileinfo unset.
    if not os.path.exists(current_filepath):
      self.fileinfo[metadata_filename] = None
      return

    # Extract the file information from the actual file and save it
    # to the fileinfo store.
    file_length, hashes = securesystemslib.util.get_file_details(current_filepath)
    metadata_fileinfo = tuf.formats.make_fileinfo(file_length, hashes)
    self.fileinfo[metadata_filename] = metadata_fileinfo







  def _move_current_to_previous(self, metadata_role):
    """
    <Purpose>
      Non-public method that moves the current metadata file for 'metadata_role'
      to the previous directory.

    <Arguments>
      metadata_role:
        The name of the metadata. This is a role name and should not end
        in '.json'.  Examples: 'root', 'targets', 'targets/linux/x86'.

    <Exceptions>
      None.

    <Side Effects>
     The metadata file for 'metadata_role' is removed from 'current'
     and moved to the 'previous' directory.

    <Returns>
      None.
    """

    # Get the 'current' and 'previous' full file paths for 'metadata_role'
    metadata_filepath = metadata_role + '.json'
    previous_filepath = os.path.join(self.metadata_directory['previous'],
                                     metadata_filepath)
    current_filepath = os.path.join(self.metadata_directory['current'],
                                    metadata_filepath)

    # Remove the previous path if it exists.
    if os.path.exists(previous_filepath):
      os.remove(previous_filepath)

    # Move the current path to the previous path.
    if os.path.exists(current_filepath):
      securesystemslib.util.ensure_parent_dir(previous_filepath)
      os.rename(current_filepath, previous_filepath)





  def _delete_metadata(self, metadata_role):
    """
    <Purpose>
      Non-public method that removes all (current) knowledge of 'metadata_role'.
      The metadata belonging to 'metadata_role' is removed from the current
      'self.metadata' store and from the role database. The 'root.json' role
      file is never removed.

    <Arguments>
      metadata_role:
        The name of the metadata. This is a role name and should not end
        in '.json'.  Examples: 'root', 'targets', 'targets/linux/x86'.

    <Exceptions>
      None.

    <Side Effects>
      The role database is modified and the metadata for 'metadata_role'
      removed from the 'self.metadata' store.

    <Returns>
      None.
    """

    # The root metadata role is never deleted without a replacement.
    if metadata_role == 'root':
      return

    # Get rid of the current metadata file.
    self._move_current_to_previous(metadata_role)

    # Remove knowledge of the role.
    if metadata_role in self.metadata['current']:
      del self.metadata['current'][metadata_role]
    tuf.roledb.remove_role(metadata_role, self.repository_name)





  def _ensure_not_expired(self, metadata_object, metadata_rolename):
    """
    <Purpose>
      Non-public method that raises an exception if the current specified
      metadata has expired.

    <Arguments>
      metadata_object:
        The metadata that should be expired, a 'tuf.formats.ANYROLE_SCHEMA'
        object.

      metadata_rolename:
        The name of the metadata. This is a role name and should not end
        in '.json'.  Examples: 'root', 'targets', 'targets/linux/x86'.

    <Exceptions>
      tuf.exceptions.ExpiredMetadataError:
        If 'metadata_rolename' has expired.

    <Side Effects>
      None.

    <Returns>
      None.
    """

    # Extract the expiration time.
    expires = metadata_object['expires']

    # If the current time has surpassed the expiration date, raise an
    # exception.  'expires' is in
    # 'securesystemslib.formats.ISO8601_DATETIME_SCHEMA' format (e.g.,
    # '1985-10-21T01:22:00Z'.)  Convert it to a unix timestamp and compare it
    # against the current time.time() (also in Unix/POSIX time format, although
    # with microseconds attached.)
    current_time = int(time.time())

    # Generate a user-friendly error message if 'expires' is less than the
    # current time (i.e., a local time.)
    expires_datetime = iso8601.parse_date(expires)
    expires_timestamp = tuf.formats.datetime_to_unix_timestamp(expires_datetime)

    if expires_timestamp < current_time:
      message = 'Metadata '+repr(metadata_rolename)+' expired on ' + \
        expires_datetime.ctime() + ' (UTC).'
      logger.error(message)

      raise tuf.exceptions.ExpiredMetadataError(message)





  def all_targets(self):
    """
    <Purpose>
      Get a list of the target information for all the trusted targets on the
      repository.  This list also includes all the targets of delegated roles.
      Targets of the list returned are ordered according the trusted order of
      the delegated roles, where parent roles come before children.  The list
      conforms to 'tuf.formats.TARGETINFOS_SCHEMA' and has the form:

      [{'filepath': 'a/b/c.txt',
        'fileinfo': {'length': 13323,
                     'hashes': {'sha256': dbfac345..}}
       ...]

    <Arguments>
      None.

    <Exceptions>
      tuf.exceptions.RepositoryError:
        If the metadata for the 'targets' role is missing from
        the 'snapshot' metadata.

      tuf.exceptions.UnknownRoleError:
        If one of the roles could not be found in the role database.

    <Side Effects>
      The metadata for target roles is updated and stored.

    <Returns>
     A list of targets, conformant to
     'tuf.formats.TARGETINFOS_SCHEMA'.
    """

    # Load the most up-to-date targets of the 'targets' role and all
    # delegated roles.
    self._refresh_targets_metadata(refresh_all_delegated_roles=True)

    # Fetch the targets for the 'targets' role.
    all_targets = self._targets_of_role('targets', skip_refresh=True)

    # Fetch the targets of the delegated roles.  get_rolenames returns
    # all roles available on the repository.
    delegated_targets = []
    for role in tuf.roledb.get_rolenames(self.repository_name):
      if role in ['root', 'snapshot', 'targets', 'timestamp']:
        continue

      else:
        delegated_targets.extend(self._targets_of_role(role, skip_refresh=True))

    all_targets.extend(delegated_targets)

    return all_targets





  def _refresh_targets_metadata(self, rolename='targets',
    refresh_all_delegated_roles=False):
    """
    <Purpose>
      Non-public method that refreshes the targets metadata of 'rolename'.  If
      'refresh_all_delegated_roles' is True, include all the delegations that
      follow 'rolename'.  The metadata for the 'targets' role is updated in
      refresh() by the _update_metadata_if_changed('targets') call, not here.
      Delegated roles are not loaded when the repository is first initialized.
      They are loaded from disk, updated if they have changed, and stored to
      the 'self.metadata' store by this method.  This method is called by the
      target methods, like all_targets() and targets_of_role().

    <Arguments>
      rolename:
        This is a delegated role name and should not end in '.json'.  Example:
        'unclaimed'.

      refresh_all_delegated_roles:
         Boolean indicating if all the delegated roles available in the
         repository (via snapshot.json) should be refreshed.

    <Exceptions>
      tuf.exceptions.RepositoryError:
        If the metadata file for the 'targets' role is missing from the
        'snapshot' metadata.

    <Side Effects>
      The metadata for the delegated roles are loaded and updated if they
      have changed.  Delegated metadata is removed from the role database if
      it has expired.

    <Returns>
      None.
    """

    roles_to_update = []

    if rolename + '.json' in self.metadata['current']['snapshot']['meta']:
      roles_to_update.append(rolename)

    if refresh_all_delegated_roles:

      for role in six.iterkeys(self.metadata['current']['snapshot']['meta']):
        # snapshot.json keeps track of root.json, targets.json, and delegated
        # roles (e.g., django.json, unclaimed.json).  Remove the 'targets' role
        # because it gets updated when the targets.json file is updated in
        # _update_metadata_if_changed('targets') and root.
        if role.endswith('.json'):
          role = role[:-len('.json')]
          if role not in ['root', 'targets', rolename]:
            roles_to_update.append(role)

        else:
          continue

    # If there is nothing to refresh, we are done.
    if not roles_to_update:
      return

    logger.debug('Roles to update: ' + repr(roles_to_update) + '.')

    # Iterate 'roles_to_update', and load and update its metadata file if it
    # has changed.
    for rolename in roles_to_update:
      self._load_metadata_from_file('previous', rolename)
      self._load_metadata_from_file('current', rolename)

      self._update_metadata_if_changed(rolename)





  def _targets_of_role(self, rolename, targets=None, skip_refresh=False):
    """
    <Purpose>
      Non-public method that returns the target information of all the targets
      of 'rolename'.  The returned information is a list conformant to
      'tuf.formats.TARGETINFOS_SCHEMA', and has the form:

      [{'filepath': 'a/b/c.txt',
        'fileinfo': {'length': 13323,
                     'hashes': {'sha256': dbfac345..}}
       ...]

    <Arguments>
      rolename:
        This is a role name and should not end in '.json'.  Examples: 'targets',
        'unclaimed'.

      targets:
        A list of targets containing target information, conformant to
        'tuf.formats.TARGETINFOS_SCHEMA'.

      skip_refresh:
        A boolean indicating if the target metadata for 'rolename'
        should be refreshed.

    <Exceptions>
      tuf.exceptions.UnknownRoleError:
        If 'rolename' is not found in the role database.

    <Side Effects>
      The metadata for 'rolename' is refreshed if 'skip_refresh' is False.

    <Returns>
      A list of dict objects containing the target information of all the
      targets of 'rolename'.  Conformant to
      'tuf.formats.TARGETINFOS_SCHEMA'.
    """

    if targets is None:
      targets = []

    targets_of_role = list(targets)
    logger.debug('Getting targets of role: ' + repr(rolename) + '.')

    if not tuf.roledb.role_exists(rolename, self.repository_name):
      raise tuf.exceptions.UnknownRoleError(rolename)

    # We do not need to worry about the target paths being trusted because
    # this is enforced before any new metadata is accepted.
    if not skip_refresh:
      self._refresh_targets_metadata(rolename)

    # Do we have metadata for 'rolename'?
    if rolename not in self.metadata['current']:
      logger.debug('No metadata for ' + repr(rolename) + '.'
        '  Unable to determine targets.')
      return []

    # Get the targets specified by the role itself.
    for filepath, fileinfo in six.iteritems(self.metadata['current'][rolename].get('targets', [])):
      new_target = {}
      new_target['filepath'] = filepath
      new_target['fileinfo'] = fileinfo

      targets_of_role.append(new_target)

    return targets_of_role





  def targets_of_role(self, rolename='targets'):
    """
    <Purpose>
      Return a list of trusted targets directly specified by 'rolename'.
      The returned information is a list conformant to
      'tuf.formats.TARGETINFOS_SCHEMA', and has the form:

      [{'filepath': 'a/b/c.txt',
        'fileinfo': {'length': 13323,
                     'hashes': {'sha256': dbfac345..}}
       ...]

      The metadata of 'rolename' is updated if out of date, including the
      metadata of its parent roles (i.e., the minimum roles needed to set the
      chain of trust).

    <Arguments>
      rolename:
        The name of the role whose list of targets are wanted.
        The name of the role should start with 'targets'.

    <Exceptions>
      securesystemslib.exceptions.FormatError:
        If 'rolename' is improperly formatted.

      tuf.exceptions.RepositoryError:
        If the metadata of 'rolename' cannot be updated.

      tuf.exceptions.UnknownRoleError:
        If 'rolename' is not found in the role database.

    <Side Effects>
      The metadata of updated delegated roles are downloaded and stored.

    <Returns>
      A list of targets, conformant to
      'tuf.formats.TARGETINFOS_SCHEMA'.
    """

    # Does 'rolename' have the correct format?
    # Raise 'securesystemslib.exceptions.FormatError' if there is a mismatch.
    securesystemslib.formats.RELPATH_SCHEMA.check_match(rolename)

    if not tuf.roledb.role_exists(rolename, self.repository_name):
      raise tuf.exceptions.UnknownRoleError(rolename)

    self._refresh_targets_metadata(rolename)

    return self._targets_of_role(rolename, skip_refresh=True)





  def get_one_valid_targetinfo(self, target_filepath):
    """
    <Purpose>
      Return the target information of 'target_filepath', and update its
      corresponding metadata, if necessary.

    <Arguments>
      target_filepath:
        The path to the target file on the repository. This will be relative to
        the 'targets' (or equivalent) directory on a given mirror.

    <Exceptions>
      securesystemslib.exceptions.FormatError:
        If 'target_filepath' is improperly formatted.

      tuf.exceptions.UnknownTargetError:
        If 'target_filepath' was not found.

      Any other unforeseen runtime exception.

    <Side Effects>
      The metadata for updated delegated roles are downloaded and stored.

    <Returns>
      The target information for 'target_filepath', conformant to
      'tuf.formats.TARGETINFO_SCHEMA'.
    """

    # Does 'target_filepath' have the correct format?
    # Raise 'securesystemslib.exceptions.FormatError' if there is a mismatch.
    securesystemslib.formats.RELPATH_SCHEMA.check_match(target_filepath)

    # 'target_filepath' might contain URL encoding escapes.
    # http://docs.python.org/2/library/urllib.html#urllib.unquote
    target_filepath = six.moves.urllib.parse.unquote(target_filepath)

    if not target_filepath.startswith('/'):
      target_filepath = '/' + target_filepath

    # Get target by looking at roles in order of priority tags.
    target = self._preorder_depth_first_walk(target_filepath)

    # Raise an exception if the target information could not be retrieved.
    if target is None:
      logger.error(target_filepath + ' not found.')
      raise tuf.exceptions.UnknownTargetError(target_filepath + ' not found.')

    # Otherwise, return the found target.
    else:
      return target





  def _preorder_depth_first_walk(self, target_filepath):
    """
    <Purpose>
      Non-public method that interrogates the tree of target delegations in
      order of appearance (which implicitly order trustworthiness), and returns
      the matching target found in the most trusted role.

    <Arguments>
      target_filepath:
        The path to the target file on the repository. This will be relative to
        the 'targets' (or equivalent) directory on a given mirror.

    <Exceptions>
      securesystemslib.exceptions.FormatError:
        If 'target_filepath' is improperly formatted.

      tuf.exceptions.RepositoryError:
        If 'target_filepath' is not found.

    <Side Effects>
      The metadata for updated delegated roles are downloaded and stored.

    <Returns>
      The target information for 'target_filepath', conformant to
      'tuf.formats.TARGETINFO_SCHEMA'.
    """

    target = None
    current_metadata = self.metadata['current']
    role_names = ['targets']
    visited_role_names = set()
    number_of_delegations = tuf.settings.MAX_NUMBER_OF_DELEGATIONS

    # Ensure the client has the most up-to-date version of 'targets.json'.
    # Raise 'tuf.exceptions.NoWorkingMirrorError' if the changed metadata cannot be
    # successfully downloaded and 'tuf.exceptions.RepositoryError' if the referenced
    # metadata is missing.  Target methods such as this one are called after
    # the top-level metadata have been refreshed (i.e., updater.refresh()).
    self._update_metadata_if_changed('targets')

    # Preorder depth-first traversal of the graph of target delegations.
    while target is None and number_of_delegations > 0 and len(role_names) > 0:

      # Pop the role name from the top of the stack.
      role_name = role_names.pop(-1)

      # Skip any visited current role to prevent cycles.
      if role_name in visited_role_names:
        logger.debug('Skipping visited current role ' + repr(role_name))
        continue

      # The metadata for 'role_name' must be downloaded/updated before its
      # targets, delegations, and child roles can be inspected.
      # self.metadata['current'][role_name] is currently missing.
      # _refresh_targets_metadata() does not refresh 'targets.json', it
      # expects _update_metadata_if_changed() to have already refreshed it,
      # which this function has checked above.
      self._refresh_targets_metadata(role_name, refresh_all_delegated_roles=False)

      role_metadata = current_metadata[role_name]
      targets = role_metadata['targets']
      delegations = role_metadata.get('delegations', {})
      child_roles = delegations.get('roles', [])
      target = self._get_target_from_targets_role(role_name, targets,
                                                  target_filepath)
      # After preorder check, add current role to set of visited roles.
      visited_role_names.add(role_name)

      # And also decrement number of visited roles.
      number_of_delegations -= 1

      if target is None:

        child_roles_to_visit = []
        # NOTE: This may be a slow operation if there are many delegated roles.
        for child_role in child_roles:
          child_role_name = self._visit_child_role(child_role, target_filepath)
          if child_role['terminating'] and child_role_name is not None:
            logger.debug('Adding child role ' + repr(child_role_name))
            logger.debug('Not backtracking to other roles.')
            role_names = []
            child_roles_to_visit.append(child_role_name)
            break

          elif child_role_name is None:
            logger.debug('Skipping child role ' + repr(child_role_name))

          else:
            logger.debug('Adding child role ' + repr(child_role_name))
            child_roles_to_visit.append(child_role_name)

        # Push 'child_roles_to_visit' in reverse order of appearance onto
        # 'role_names'.  Roles are popped from the end of the 'role_names'
        # list.
        child_roles_to_visit.reverse()
        role_names.extend(child_roles_to_visit)

      else:
        logger.debug('Found target in current role ' + repr(role_name))

    if target is None and number_of_delegations == 0 and len(role_names) > 0:
      logger.debug(repr(len(role_names)) + ' roles left to visit, ' +
                   'but allowed to visit at most ' +
                   repr(tuf.settings.MAX_NUMBER_OF_DELEGATIONS) + ' delegations.')

    return target





  def _get_target_from_targets_role(self, role_name, targets, target_filepath):
    """
    <Purpose>
      Non-public method that determines whether the targets role with the given
      'role_name' has the target with the name 'target_filepath'.

    <Arguments>
      role_name:
        The name of the targets role that we are inspecting.

      targets:
        The targets of the Targets role with the name 'role_name'.

      target_filepath:
        The path to the target file on the repository. This will be relative to
        the 'targets' (or equivalent) directory on a given mirror.

    <Exceptions>
      None.

    <Side Effects>
      None.

    <Returns>
      The target information for 'target_filepath', conformant to
      'tuf.formats.TARGETINFO_SCHEMA'.
    """

    target = None

    # Does the current role name have our target?
    logger.debug('Asking role ' + repr(role_name) + ' about target ' +\
      repr(target_filepath))

    for filepath, fileinfo in six.iteritems(targets):
      if filepath == target_filepath:
        logger.debug('Found target ' + target_filepath + ' in role ' + role_name)
        target = {'filepath': filepath, 'fileinfo': fileinfo}
        break

      else:
        logger.debug('No target ' + target_filepath + ' in role ' + role_name)

    return target






  def _visit_child_role(self, child_role, target_filepath):
    """
    <Purpose>
      Non-public method that determines whether the given 'target_filepath'
      is an allowed path of 'child_role'.

      Ensure that we explore only delegated roles trusted with the target.  The
      metadata for 'child_role' should have been refreshed prior to this point,
      however, the paths/targets that 'child_role' signs for have not been
      verified (as intended).  The paths/targets that 'child_role' is allowed
      to specify in its metadata depends on the delegating role, and thus is
      left to the caller to verify.  We verify here that 'target_filepath'
      is an allowed path according to the delegated 'child_role'.

      TODO: Should the TUF spec restrict the repository to one particular
      algorithm?  Should we allow the repository to specify in the role
      dictionary the algorithm used for these generated hashed paths?

    <Arguments>
      child_role:
        The delegation targets role object of 'child_role', containing its
        paths, path_hash_prefixes, keys, and so on.

      target_filepath:
        The path to the target file on the repository. This will be relative to
        the 'targets' (or equivalent) directory on a given mirror.

    <Exceptions>
      None.

    <Side Effects>
      None.

    <Returns>
      If 'child_role' has been delegated the target with the name
      'target_filepath', then we return the role name of 'child_role'.

      Otherwise, we return None.
    """

    child_role_name = child_role['name']
    child_role_paths = child_role.get('paths')
    child_role_path_hash_prefixes = child_role.get('path_hash_prefixes')

    if child_role_path_hash_prefixes is not None:
      target_filepath_hash = self._get_target_hash(target_filepath)
      for child_role_path_hash_prefix in child_role_path_hash_prefixes:
        if target_filepath_hash.startswith(child_role_path_hash_prefix):
          return child_role_name

        else:
          continue

    elif child_role_paths is not None:
      # Is 'child_role_name' allowed to sign for 'target_filepath'?
      for child_role_path in child_role_paths:
        # A child role path may be an explicit path or pattern (Unix
        # shell-style wildcards).  The child role 'child_role_name' is returned
        # if 'target_filepath' is equal to or matches 'child_role_path'.
        # Explicit filepaths are also considered matches.
        if fnmatch.fnmatch(target_filepath, child_role_path):
         logger.debug('Child role ' + repr(child_role_name) + ' is allowed to'
            ' sign for ' + repr(target_filepath))

         return child_role_name

        else:
          logger.debug('The given target path' + repr(target_filepath) + ' is'
              ' not an allowed trusted path of ' + repr(child_role_path))

          continue

    else:
      # 'role_name' should have been validated when it was downloaded.
      # The 'paths' or 'path_hash_prefixes' fields should not be missing,
      # so we raise a format error here in case they are both missing.
      raise securesystemslib.exceptions.FormatError(repr(child_role_name) + ' '
          'has neither a "paths" nor "path_hash_prefixes".  At least'
          ' one of these attributes must be present.')

    return None



  def _get_target_hash(self, target_filepath, hash_function='sha256'):
    """
    <Purpose>
      Non-public method that computes the hash of 'target_filepath'. This is
      useful in conjunction with the "path_hash_prefixes" attribute in a
      delegated targets role, which tells us which paths it is implicitly
      responsible for.

    <Arguments>
      target_filepath:
        The path to the target file on the repository. This will be relative to
        the 'targets' (or equivalent) directory on a given mirror.

      hash_function:
        The algorithm used by the repository to generate the hashes of the
        target filepaths.  The repository may optionally organize targets into
        hashed bins to ease target delegations and role metadata management.
        The use of consistent hashing allows for a uniform distribution of
        targets into bins.

    <Exceptions>
      None.

    <Side Effects>
      None.

    <Returns>
      The hash of 'target_filepath'.
    """

    # Calculate the hash of the filepath to determine which bin to find the
    # target.  The client currently assumes the repository (i.e., repository
    # tool) uses 'hash_function' to generate hashes and UTF-8.
    digest_object = securesystemslib.hash.digest(hash_function)
    encoded_target_filepath = target_filepath.encode('utf-8')
    digest_object.update(encoded_target_filepath)
    target_filepath_hash = digest_object.hexdigest()

    return target_filepath_hash





  def remove_obsolete_targets(self, destination_directory):
    """
    <Purpose>
      Remove any files that are in 'previous' but not 'current'.  This makes it
      so if you remove a file from a repository, it actually goes away.  The
      targets for the 'targets' role and all delegated roles are checked.

    <Arguments>
      destination_directory:
        The directory containing the target files tracked by TUF.

    <Exceptions>
      securesystemslib.exceptions.FormatError:
        If 'destination_directory' is improperly formatted.

      tuf.exceptions.RepositoryError:
        If an error occurred removing any files.

    <Side Effects>
      Target files are removed from disk.

    <Returns>
      None.
    """

    # Does 'destination_directory' have the correct format?
    # Raise 'securesystemslib.exceptions.FormatError' if there is a mismatch.
    securesystemslib.formats.PATH_SCHEMA.check_match(destination_directory)

    # Iterate the rolenames and verify whether the 'previous' directory
    # contains a target no longer found in 'current'.
    for role in tuf.roledb.get_rolenames(self.repository_name):
      if role.startswith('targets'):
        if role in self.metadata['previous'] and self.metadata['previous'][role] != None:
          for target in self.metadata['previous'][role]['targets']:
            if target not in self.metadata['current'][role]['targets']:
              # 'target' is only in 'previous', so remove it.
              logger.warning('Removing obsolete file: ' + repr(target) + '.')

              # Remove the file if it hasn't been removed already.
              destination = \
                os.path.join(destination_directory, target.lstrip(os.sep))
              try:
                os.remove(destination)

              except OSError as e:
                # If 'filename' already removed, just log it.
                if e.errno == errno.ENOENT:
                  logger.info('File ' + repr(destination) + ' was already'
                    ' removed.')

                else:
                  logger.error(str(e))

            else:
              logger.debug('Skipping: ' + repr(target) + '.  It is still'
                ' a current target.')
        else:
          logger.debug('Skipping: ' + repr(role) + '.  Not in the previous'
            ' metadata')





  def updated_targets(self, targets, destination_directory):
    """
    <Purpose>
      Return the targets in 'targets' that have changed.  Targets are considered
      changed if they do not exist at 'destination_directory' or the target
      located there has mismatched file properties.

      The returned information is a list conformant to
      'tuf.formats.TARGETINFOS_SCHEMA' and has the form:

      [{'filepath': 'a/b/c.txt',
        'fileinfo': {'length': 13323,
                     'hashes': {'sha256': dbfac345..}}
       ...]

    <Arguments>
      targets:
        A list of target files.  Targets that come earlier in the list are
        chosen over duplicates that may occur later.

      destination_directory:
        The directory containing the target files.

    <Exceptions>
      securesystemslib.exceptions.FormatError:
        If the arguments are improperly formatted.

    <Side Effects>
      The files in 'targets' are read and their hashes computed.

    <Returns>
      A list of targets, conformant to
      'tuf.formats.TARGETINFOS_SCHEMA'.
    """

    # Do the arguments have the correct format?
    # Raise 'securesystemslib.exceptions.FormatError' if there is a mismatch.
    tuf.formats.TARGETINFOS_SCHEMA.check_match(targets)
    securesystemslib.formats.PATH_SCHEMA.check_match(destination_directory)

    # Keep track of the target objects and filepaths of updated targets.
    # Return 'updated_targets' and use 'updated_targetpaths' to avoid
    # duplicates.
    updated_targets = []
    updated_targetpaths = []

    for target in targets:
      # Prepend 'destination_directory' to the target's relative filepath (as
      # stored in metadata.)  Verify the hash of 'target_filepath' against
      # each hash listed for its fileinfo.  Note: join() discards
      # 'destination_directory' if 'filepath' contains a leading path separator
      # (i.e., is treated as an absolute path).
      filepath = target['filepath']
      if filepath[0] == '/':
        filepath = filepath[1:]
      target_filepath = os.path.join(destination_directory, filepath)

      if target_filepath in updated_targetpaths:
        continue

      # Try one of the algorithm/digest combos for a mismatch.  We break
      # as soon as we find a mismatch.
      for algorithm, digest in six.iteritems(target['fileinfo']['hashes']):
        digest_object = None
        try:
          digest_object = securesystemslib.hash.digest_filename(target_filepath,
            algorithm=algorithm)

        # This exception would occur if the target does not exist locally.
        except IOError:
          updated_targets.append(target)
          updated_targetpaths.append(target_filepath)
          break

        # The file does exist locally, check if its hash differs.
        if digest_object.hexdigest() != digest:
          updated_targets.append(target)
          updated_targetpaths.append(target_filepath)
          break

    return updated_targets





  def download_target(self, target, destination_directory):
    """
    <Purpose>
      Download 'target' and verify it is trusted.

      This will only store the file at 'destination_directory' if the
      downloaded file matches the description of the file in the trusted
      metadata.

    <Arguments>
      target:
        The target to be downloaded.  Conformant to
        'tuf.formats.TARGETINFO_SCHEMA'.

      destination_directory:
        The directory to save the downloaded target file.

    <Exceptions>
      securesystemslib.exceptions.FormatError:
        If 'target' is not properly formatted.

      tuf.exceptions.NoWorkingMirrorError:
        If a target could not be downloaded from any of the mirrors.

        Although expected to be rare, there might be OSError exceptions (except
        errno.EEXIST) raised when creating the destination directory (if it
        doesn't exist).

    <Side Effects>
      A target file is saved to the local system.

    <Returns>
      None.
    """

    # Do the arguments have the correct format?
    # This check ensures the arguments have the appropriate
    # number of objects and object types, and that all dict
    # keys are properly named.
    # Raise 'securesystemslib.exceptions.FormatError' if the check fail.
    tuf.formats.TARGETINFO_SCHEMA.check_match(target)
    securesystemslib.formats.PATH_SCHEMA.check_match(destination_directory)

    # Extract the target file information.
    target_filepath = target['filepath']
    trusted_length = target['fileinfo']['length']
    trusted_hashes = target['fileinfo']['hashes']

    # '_get_target_file()' checks every mirror and returns the first target
    # that passes verification.
    target_file_object = self._get_target_file(target_filepath, trusted_length,
                                               trusted_hashes)

    # We acquired a target file object from a mirror.  Move the file into place
    # (i.e., locally to 'destination_directory').  Note: join() discards
    # 'destination_directory' if 'target_path' contains a leading path
    # separator (i.e., is treated as an absolute path).
    destination = os.path.join(destination_directory,
                               target_filepath.lstrip(os.sep))
    destination = os.path.abspath(destination)
    target_dirpath = os.path.dirname(destination)

    # When attempting to create the leaf directory of 'target_dirpath', ignore
    # any exceptions raised if the root directory already exists.  All other
    # exceptions potentially thrown by os.makedirs() are re-raised.
    # Note: os.makedirs can raise OSError if the leaf directory already exists
    # or cannot be created.
    try:
      os.makedirs(target_dirpath)

    except OSError as e:
      if e.errno == errno.EEXIST:
        pass

      else:
        raise

    target_file_object.move(destination)
