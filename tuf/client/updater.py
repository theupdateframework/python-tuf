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

  2. TUF downloads and verifies timestamp.txt.

  3. If timestamp.txt indicates that release.txt has changed, TUF downloads and
  verifies release.txt.

  4. TUF determines which metadata files listed in release.txt differ from those
  described in the last release.txt that TUF has seen.  If root.txt has changed,
  the update process starts over using the new root.txt.

  5. TUF provides the software update system with a list of available files
  according to targets.txt.

  6. The software update system instructs TUF to download a specific target
  file.

  7. TUF downloads and verifies the file and then makes the file available to
  the software update system.

<Example Client>

  # The client first imports the 'updater.py' module, the only module the
  # client is required to import.  The client will utilize a single class
  # from this module.
  import tuf.client.updater

  # The only other module the client interacts with is 'tuf.conf'.  The
  # client accesses this module solely to set the repository directory.
  # This directory will hold the files downloaded from a remote repository.
  tuf.conf.repository_directory = 'local-repository'
 
  # Next, the client creates a dictionary object containing the repository
  # mirrors.  The client may download content from any one of these mirrors.
  # In the example below, a single mirror named 'mirror1' is defined.  The
  # mirror is located at 'http://localhost:8001', and all of the metadata
  # and targets files can be found in the 'metadata' and 'targets' directory,
  # respectively.  If the client wishes to only download target files from
  # specific directories on the mirror, the 'confined_target_paths' field
  # should be set.  In the example, the client has chosen '', which is
  # interpreted as no confinement.  In other words, the client can download
  # targets from any directory or subdirectories.  If the client had chosen
  # 'targets1', they would have been confined to the '/targets/targets1/'
  # directory on the 'http://localhost:8001' mirror. 
  repository_mirrors = {'mirror1': {'url_prefix': 'http://localhost:8001',
                                    'metadata_path': 'metadata',
                                    'targets_path': 'targets',
                                    'confined_target_paths': ['']}}

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

import os
import time
import logging
import shutil
import errno

import tuf.formats
import tuf.keydb
import tuf.roledb
import tuf.mirrors
import tuf.download
import tuf.conf
import tuf.log
import tuf.sig
import tuf.util

logger = logging.getLogger('tuf')


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
      Example: {'current': {'root': ROOTROLE_SCHEMA,
                            'targets':TARGETSROLE_SCHEMA, ...},
                'previous': {'root': ROOTROLE_SCHEMA,
                             'targets':TARGETSROLE_SCHEMA, ...}}
    
    self.metadata_directory:
      The directory where trusted metadata is stored.
      
    self.fileinfo:
      A cache of lengths and hashes of stored metadata files.
      Example: {'root.txt': {'length': 13323,
                             'hashes': {'sha256': dbfac345..}},
                ...}

    self.mirrors:
      The repository mirrors from which metadata and targets are available.
      Conformant to 'tuf.formats.MIRRORDICT_SCHEMA'.
    
    self.name:
      The name of the updater instance.
 
  <Updater Methods>
    refresh():
      This method downloads, verifies, and loads metadata for the top-level
      roles in a specific order (i.e., timestamp -> release -> root -> targets)
      The expiration time for downloaded metadata is also verified.
      
      The metadata for delegated roles are not refreshed by this method, but by
      the target methods (e.g., all_targets(), targets_of_role(), target()).
      The refresh() method should be called by the client before any target
      requests.
    
    all_targets():
      Returns the target information for the 'targets' and delegated roles.
      Prior to extracting the target information, this method attempts a file
      download of all the target metadata that have changed.
    
    targets_of_role('targets'):
      Returns the target information for the targets of a specified role.
      Like all_targets(), delegated metadata is updated if it has changed.
    
    target(file_path):
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

  """

  def __init__(self, updater_name, repository_mirrors):
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
            
            {tuf.conf.repository_directory}/metadata/current
            {tuf.conf.repository_directory}/metadata/previous
      
      and, at a minimum, the root metadata file must exist:

            {tuf.conf.repository_directory}/metadata/current/root.txt
    
    <Arguments>
      updater_name:
        The name of the updater.
      
      repository_mirrors:
        A dictionary holding repository mirror information, conformant to
        'tuf.formats.MIRRORDICT_SCHEMA'.  This dictionary holds information
        such as the directory containing the metadata and target files, the
        server's URL prefix, and the target content directories the client
        should be confined to.
            
        repository_mirrors = {'mirror1': {'url_prefix': 'http://localhost:8001',
                                          'metadata_path': 'metadata',
                                          'targets_path': 'targets',
                                          'confined_target_paths': ['']}}
    
    <Exceptions>
      tuf.FormatError:
        If the arguments are improperly formatted. 
      
      tuf.RepositoryError:
        If there is an error with the updater's repository files, such
        as a missing 'root.txt' file.

    <Side Effects>
      Th metadata files (e.g., 'root.txt', 'targets.txt') for the top-
      level roles are read from disk and stored in dictionaries.

    <Returns>
      None.

    """
  
    # Do the arguments have the correct format?
    # These checks ensure the arguments have the appropriate
    # number of objects and object types and that all dict
    # keys are properly named.
    # Raise 'tuf.FormatError' if there is a mistmatch.
    tuf.formats.NAME_SCHEMA.check_match(updater_name)
    tuf.formats.MIRRORDICT_SCHEMA.check_match(repository_mirrors)
   
    # Save the validated arguments.
    self.name = updater_name
    self.mirrors = repository_mirrors

    # Store the trusted metadata read from disk.
    self.metadata = {}
    
    # Store the currently trusted/verified metadata.
    self.metadata['current'] = {} 
    
    # Store the previously trusted/verified metadata.
    self.metadata['previous'] = {}

    # Store the file information of all the metadata files.  The dict keys are
    # paths, the dict values fileinfo data. This information can help determine
    # whether a metadata file has changed and so needs to be re-downloaded.
    self.fileinfo = {}
    
    # Store the location of the client's metadata directory.
    self.metadata_directory = {}
    
    # Ensure the repository metadata directory has been set.
    if tuf.conf.repository_directory is None:
      message = 'The TUF update client module must specify the directory' \
                ' containing the local repository files.' \
                '  "tuf.conf.repository_directory" MUST be set.'
      raise tuf.RepositoryError(message)

    # Set the path for the current set of metadata files.  
    repository_directory = tuf.conf.repository_directory
    current_path = os.path.join(repository_directory, 'metadata', 'current')
    
    # Ensure the current path is valid/exists before saving it.
    if not os.path.exists(current_path):
      message = 'Missing '+repr(current_path)+'.  This path must exist and, ' \
                'at a minimum, contain the root metadata file.' 
      raise tuf.RepositoryError(message)
    self.metadata_directory['current'] = current_path
    
    # Set the path for the previous set of metadata files. 
    previous_path = os.path.join(repository_directory, 'metadata', 'previous') 
   
    # Ensure the previous path is valid/exists.
    if not os.path.exists(previous_path):
      message = 'Missing '+repr(previous_path)+'.  This path must exist.'
      raise tuf.RepositoryError(message)
    self.metadata_directory['previous'] = previous_path
    
    # Load current and previous metadata.
    for metadata_set in ['current', 'previous']:
      for metadata_role in ['root', 'targets', 'release', 'timestamp']:
        self._load_metadata_from_file(metadata_set, metadata_role)
      
    # Raise an exception if the repository is missing the required 'root'
    # metadata.
    if 'root' not in self.metadata['current']:
      message = 'No root of trust! Could not find the "root.txt" file.'
      raise tuf.RepositoryError(message)




  def __str__(self):
    """
      The string representation of an Updater object.
    
    """
    
    return self.name





  def _load_metadata_from_file(self, metadata_set, metadata_role):
    """
    <Purpose>
      Load current or previous metadata if there is a local file.  If the 
      expected file belonging to 'metadata_role' (e.g., 'root.txt') cannot
      be loaded, raise an exception.  The extracted metadata object loaded
      from file is saved to the metadata store (i.e., self.metadata).
        
    <Arguments>        
      metadata_set:
        The string 'current' or 'previous', depending on whether one wants to
        load the currently or previously trusted metadata file.
            
      metadata_role:
        The name of the metadata. This is a role name and should
        not end in '.txt'.  Examples: 'root', 'targets', 'targets/linux/x86'.

    <Exceptions>
      tuf.RepositoryError:
        If the metadata could not be loaded or the extracted data is not a 
        valid metadata object.

      tuf.FormatError:
        If role information belonging to a delegated role of 'metadata_role'
        is improperly formatted.

      tuf.Error:
        If there was an error importing a delegated role of 'metadata_role'
        or the metadata set is not one currently supported.
    
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
      raise tuf.Error('Invalid metadata set: '+repr(metadata_set))

    # Save and construct the full metadata path.
    metadata_directory = self.metadata_directory[metadata_set]
    metadata_filename = metadata_role + '.txt'
    metadata_filepath = os.path.join(metadata_directory, metadata_filename)
    
    # Ensure the metadata path is valid/exists, else ignore the call. 
    if os.path.exists(metadata_filepath):
      # Load the file.  The loaded object should conform to
      # 'tuf.formats.SIGNABLE_SCHEMA'.
      metadata_signable = tuf.util.load_json_file(metadata_filepath)

      # Ensure the loaded json object is properly formatted.
      try: 
        tuf.formats.check_signable_object_format(metadata_signable)
      except tuf.FormatError, e:
        raise RepositoryError('Invalid format: '+repr(metadata_filepath)+'.')

      # Extract the 'signed' role object from 'metadata_signable'.
      metadata_object = metadata_signable['signed']
   
      # Save the metadata object to the metadata store.
      self.metadata[metadata_set][metadata_role] = metadata_object
   
      # We need to rebuild the key and role databases if 
      # metadata object is 'root' or target metadata.
      if metadata_set == 'current':
        if metadata_role == 'root':
          self._rebuild_key_and_role_db()
        elif metadata_object['_type'] == 'Targets':
          tuf.roledb.remove_delegated_roles(metadata_role)
          self._import_delegations(metadata_role)





  def _rebuild_key_and_role_db(self):
    """
    <Purpose>
      Rebuild the key and role databases from the currently trusted
      'root' metadata object extracted from 'root.txt'.  This private
      function is called when a new/updated 'root' metadata file is loaded.
      This function will only store the role information for the top-level
      roles (i.e., 'root', 'targets', 'release', 'timestamp').

    <Arguments>
      None.

    <Exceptions>
      tuf.FormatError:
        If the 'root' metadata is improperly formatted.

      tuf.Error:
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
    # like all_targets() and target() always cause a refresh of these files.
    # The metadata files for delegated roles are also not loaded when the
    # repository is first instantiated.  Due to this setup, reloading delegated
    # roles is not required here.
    tuf.keydb.create_keydb_from_root_metadata(self.metadata['current']['root'])
    tuf.roledb.create_roledb_from_root_metadata(self.metadata['current']['root'])





  def _import_delegations(self, parent_role):
    """
    <Purpose>
      Import all the roles delegated by 'parent_role'.
    
    <Arguments>
      parent_role:
        The role whose delegations will be imported.
        
    <Exceptions>
      tuf.FormatError:
        If a key attribute of a delegated role's signing key is
        improperly formatted.

      tuf.Error:
        If the signing key of a delegated role cannot not be loaded.

    <Side Effects>
      The key and role database is modified to include the newly
      loaded roles delegated by 'parent_role'.

    <Returns>
      None.
          
    """
        
    current_parent_metadata = self.metadata['current'][parent_role]
  
    if 'delegations' not in current_parent_metadata:
      return

    # This could be quite slow with a huge number of delegations.
    keys_info = current_parent_metadata['delegations'].get('keys', {})
    roles_info = current_parent_metadata['delegations'].get('roles', {})

    logger.debug('Adding roles delegated from '+repr(parent_role)+'.')
   
    # Iterate through the keys of the delegated roles of 'parent_role'
    # and load them.
    for keyid, keyinfo in keys_info.items():
      if keyinfo['keytype'] == 'rsa': 
        rsa_key = tuf.rsa_key.create_from_metadata_format(keyinfo)
      
        # We specify the keyid to ensure that it's the correct keyid
        # for the key.
        try:
          tuf.keydb.add_rsakey(rsa_key, keyid)
        except tuf.KeyAlreadyExistsError:
          pass
        except (tuf.FormatError, tuf.Error), e:
          logger.exception('Failed to add keyid: '+repr(keyid)+'.')
          logger.error('Aborting role delegation for parent role '+parent_role+'.')
          raise
      else:
        logger.warn('Invalid key type for '+repr(keyid)+'.')
        continue

      # Add the roles to the role database.
      for rolename, roleinfo in roles_info.items():
        logger.debug('Adding delegated role: '+repr(rolename)+'.')
        try:
          tuf.roledb.add_role(rolename, roleinfo)
        except tuf.RoleAlreadyExistsError, e:
          pass
        except (tuf.FormatError, tuf.InvalidNameError), e:
          logger.exception('Failed to add delegated role: '+rolename+'.')





  def refresh(self):
    """
    <Purpose>
      Update the latest copies of the metadata for the top-level roles.
      The update request process follows a specific order to ensure the
      metadata files are securely updated.
        
      The client would call refresh() prior to requesting target file
      information.  Calling refresh() ensures target methods, like
      all_targets() and target(), refer to the latest available content.
      The latest copies for delegated metadata are downloaded and updated
      by the target methods.

    <Arguments>
      None.

    <Exceptions>
      tuf.RepositoryError:
        If the metadata for any of the top-level roles cannot be updated.

      tuf.ExpiredMetadataError:
        If any metadata has expired.
        
    <Side Effects>
      Updates the metadata files for the top-level roles with the
      latest information.

    <Returns>
      None.
    
    """
        
    # Update the top-level metadata.  The _update_metadata_if_changed() and
    # _update_metadata() calls below do NOT perform an update if there
    # is insufficient trusted signatures for the specified metadata.
    # Raise 'tuf.RepositoryError' if an update fails.
    self._update_metadata('timestamp')

    self._update_metadata_if_changed('release', referenced_metadata='timestamp')

    self._update_metadata_if_changed('root')

    self._update_metadata_if_changed('targets')

    # Updated the top-level metadata (which all had valid signatures), however,
    # have they expired?  Raise 'tuf.ExpiredMetadataError' if any of the metadata
    # has expired.
    for metadata_role in ['timestamp', 'root', 'release', 'targets']:
      self._ensure_not_expired(metadata_role)





  def _update_metadata(self, metadata_role, compression=None):
    """
    <Purpose>
      Download, verify, and 'install' the metadata belonging to 'metadata_role'.
      Calling this function implies the metadata has been updated by the
      repository and thus needs to be re-downloaded.  The current and previous
      metadata stores are updated if the newly downloaded metadata is
      successfully downloaded and verified.
   
    <Arguments>
      metadata_role:
        The name of the metadata. This is a role name and should not end
        in '.txt'.  Examples: 'root', 'targets', 'targets/linux/x86'.
      
      compression:
        A string designating the compression type of 'metadata_role'.
        The 'release' metadata file may be optionally downloaded and stored in
        compressed form.  Currently, only metadata files compressed with 'gzip'
        are considered.  Any other string is ignored.

    <Exceptions>
      tuf.RepositoryError:
        The metadata could not be updated. This is not specific to a single
        failure but rather indicates that all possible ways to update the
        metadata have been tried and failed.

    <Side Effects>
      The metadata file belonging to 'metadata_role' is downloaded from a
      repository mirror.  If the metadata is valid, it is stored to the 
      metadata store.

    <Returns>
      None.
    
    """
    
    # Construct the metadata filename as expected by the download/mirror modules.
    metadata_filename = metadata_role + '.txt'
   
    # The 'release' metadata file may be compressed.  Add the appropriate
    # extension to 'metadata_filename'. 
    if compression == 'gzip':
      metadata_filename = metadata_filename + '.gz'

    # Reference to the 'get_list_of_mirrors' function.
    get_mirrors = tuf.mirrors.get_list_of_mirrors

    # Reference to the 'download_url_to_tempfileobj' function.
    download_file = tuf.download.download_url_to_tempfileobj

    # Attempt a file download from each mirror until the file is downloaded and
    # verified.  If the signature of the downloaded file is valid, proceed,
    # otherwise log a warning and try the next mirror.  'metadata_file_object'
    # is the file-like object returned by 'download.py'.  'metadata_signable'
    # is the object extracted from 'metadata_file_object'.  Metadata saved to
    # files are regarded as 'signable' objects, conformant to
    # 'tuf.formats.SIGNABLE_SCHEMA'.
    metadata_file_object = None
    metadata_signable = None
    for mirror_url in get_mirrors('meta', metadata_filename, self.mirrors):
      try:
        metadata_file_object = download_file(mirror_url)
      except tuf.DownloadError, e:
        logger.warn('Download failed from '+mirror_url+'.')
        continue
      if compression:
        metadata_file_object.decompress_temp_file_object(compression)

      # Read and load the downloaded file.
      metadata_signable = tuf.util.load_json_string(metadata_file_object.read())

      # Verify the signature on the downloaded metadata object.
      try:
        valid = tuf.sig.verify(metadata_signable, metadata_role)
      except (tuf.UnknownRoleError, tuf.FormatError, tuf.Error), e:
        message = 'Unable to verify '+repr(metadata_filename)+':'+str(e)
        logger.warn(message)
        metedata_signable = None
        continue
      if valid:
        logger.debug('Good signature on '+mirror_url+'.')
        break
      else:
        logger.warn('Bad signature on '+mirror_url+'.')
        metadata_signable = None
        continue
    
    # Raise an exception if a valid metadata signable could not be downloaded
    # from any of the mirrors.
    if metadata_signable is None:
      raise tuf.RepositoryError('Unable to update '+repr(metadata_filename)+'.')

    # Ensure the loaded 'metadata_signable' is properly formatted.
    try:
      tuf.formats.check_signable_object_format(metadata_signable)
    except tuf.FormatError, e:
      message = 'Unable to load '+repr(metadata_filename)+' after update: '+str(e)
      raise tuf.RepositoryError(message)

    # Reject the metadata if any specified targets are not allowed.
    if metadata_signable['signed']['_type'] == 'Targets':
      self._ensure_all_targets_allowed(metadata_role, metadata_signable['signed'])

    # The metadata has been verified. Move the metadata file into place.
    # First, move the 'current' metadata file to the 'previous' directory
    # if it exists.
    current_filepath = os.path.join(self.metadata_directory['current'],
                                    metadata_filename)
    current_filepath = os.path.abspath(current_filepath)
    tuf.util.ensure_parent_dir(current_filepath)
    
    previous_filepath = os.path.join(self.metadata_directory['previous'],
                                     metadata_filename)
    previous_filepath = os.path.abspath(previous_filepath)
    if os.path.exists(current_filepath):
      shutil.move(current_filepath, previous_filepath)

    # Next, move the verified updated metadata file to the 'current' directory.
    # Note that the 'move' method comes from tuf.util's TempFile class.
    # 'metadata_file_object' is an instance of tuf.util.TempFile.
    metadata_file_object.move(current_filepath)
    
    # Extract the metadata object so we can store it to the metadata store.
    # 'current_metadata_object' set to 'None' if there is not an object
    # stored for 'metadata_role'.
    updated_metadata_object = metadata_signable['signed']
    current_metadata_object = self.metadata['current'].get(metadata_role)

    # Finally, update the metadata store.
    logger.debug('Updated '+current_filepath+'.')
    self.metadata['previous'][metadata_role] = current_metadata_object
    self.metadata['current'][metadata_role] = updated_metadata_object





  def _update_metadata_if_changed(self, metadata_role, referenced_metadata='release'):
    """
    <Purpose>
      Update the metadata for 'metadata_role' if it has changed.  With the
      exception of the 'timestamp' role, all the top-level roles are updated
      by this function.  The 'timestamp' role is always downloaded from a mirror
      without first checking if it has been updated; it is updated in refresh()
      by calling _update_metadata('timestamp').  This function is also called for
      delegated role metadata, which are referenced by 'release'.
        
      If the metadata needs to be updated but an update cannot be obtained,
      this function will delete the file (with the exception of the root
      metadata, which never gets removed without a replacement).

      Due to the way in which metadata files are updated, it is expected that
      'referenced_metadata' is not out of date and trusted.  The refresh()
      method updates the top-level roles in 'timestamp -> release ->
      root -> targets' order.  For delegated metadata, the parent role is
      updated before the delegated role.  Taking into account that
      'referenced_metadata' is updated and verified before 'metadata_role',
      this function determines if 'metadata_role' has changed by checking
      the 'meta' field of the newly updated 'referenced_metadata'.

    <Arguments>
      metadata_role:
        The name of the metadata. This is a role name and should not end
        in '.txt'.  Examples: 'root', 'targets', 'targets/linux/x86'.

      referenced_metadata:
        This is the metadata that provides the role information for
        'metadata_role'.  For the top-level roles, the 'release' role
        is the referenced metadata for the 'root', and 'targets' roles.
        The 'timestamp' metadata is always downloaded regardless.  In
        other words, it is updated by calling _update_metadata('timestamp')
        and not by this function.  The referenced metadata for 'release'
        is 'timestamp'.  See refresh().
        
    <Exceptions>
      tuf.MetadataNotAvailableError:
        If 'metadata_role' could not be downloaded after determining
        that it had changed.
        
      tuf.RepositoryError:
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
        
    metadata_filename = metadata_role + '.txt'

    # Need to ensure the referenced metadata has been loaded.
    # The 'root' role may be updated without having 'release'
    # available.  
    if referenced_metadata not in self.metadata['current']:
      if metadata_role == 'root':
        new_fileinfo = None
      else:
        message = 'Cannot update '+repr(metadata_role)+' because ' \
                  +referenced_metadata+' is missing.'
        raise tuf.RepositoryError(message)
    # The referenced metadata has been loaded.  Extract the new
    # fileinfo for 'metadata_role' from it. 
    else:
      new_fileinfo = self.metadata['current'][referenced_metadata] \
                                  ['meta'][metadata_filename]

    # Simply return if the fileinfo has not changed according to the
    # fileinfo provided by the referenced metadata.
    if not self._fileinfo_has_changed(metadata_filename, new_fileinfo):
      return

    logger.info('Metadata '+repr(metadata_filename)+' has changed.')

    # There might be a compressed version of the 'release' metadata
    # that may be downloaded.  Check the 'meta' field of
    # 'referenced_metadata' to see if it is listed. 
    compression = None
    if metadata_role == 'release':
      gzip_path = metadata_filename + '.gz'
      if gzip_path in self.metadata['current'][referenced_metadata]['meta']:
        compression = 'gzip'
    try:
      self._update_metadata(metadata_role, compression=compression)
    except tuf.RepositoryError, e:
      # The current metadata we have is not current but we couldn't
      # get new metadata. We shouldn't use the old metadata anymore.
      # This will get rid of in-memory knowledge of the role and
      # delegated roles, but will leave delegated metadata files as
      # current files on disk.
      # TODO: Should we get rid of the delegated metadata files?
      # We shouldn't need to, but we need to check the trust
      # implications of the current implementation.
      self._delete_metadata(metadata_role)
      message = 'Metadata for '+repr(metadata_role)+' could not be updated: '
      raise tuf.MetadataNotAvailableError(message+str(e))

    # We need to remove delegated roles because the delegated roles
    # may not be trusted anymore.
    if metadata_role == 'targets' or metadata_role.startswith('targets/'):
      logger.debug('Removing delegated roles of '+repr(metadata_role)+'.')
      tuf.roledb.remove_delegated_roles(metadata_role)
      self._import_delegations(metadata_role)





  def _ensure_all_targets_allowed(self, metadata_role, metadata_object):
    """
    <Purpose>
      Ensure the delegated targets of 'metadata_role' are allowed; this is
      determined by inspecting the delegations field of the parent role
      of 'metadata_role'.  If a target specified by 'metadata_object'
      is not found in the parent role's delegations field, raise an
      exception.
   
    <Arguments>
      metadata_role:
        The name of the metadata. This is a role name and should not end
        in '.txt'.  Examples: 'root', 'targets', 'targets/linux/x86'.
      
      metadata_object:
        The metadata role object for 'metadata_role'.  This is the object
        saved to the metadata store and stored in the 'signed' field of a
        'signable' object (metadata roles are saved to metadata files as a
        'signable' object).

    <Exceptions>
      tuf.RepositoryError:
        If the targets of 'metadata_role' are not allowed according to
        the parent's metadata file.
    
    <Side Effects>
      None.

    <Returns>
      None.
    
    """
    
    # Return if 'metadata_role' is 'targets'.  'targets' is not
    # a delegated role.
    if metadata_role == 'targets':
      return
 
    # The targets of delegated roles are stored in the parent's
    # metadata file.  Retrieve the parent role of 'metadata_role'
    # to confirm 'metadata_role' contains valid targets.
    parent_role = tuf.roledb.get_parent_rolename(metadata_role)

    # Iterate through the targets of 'metadata_role' and confirm
    # these targets with the paths listed in the parent role.
    for target_filepath in metadata_object['targets'].keys():
      if target_filepath not in self.metadata['current'][parent_role] \
                                             ['delegations']['roles'] \
                                             [metadata_role]['paths']:
        
        message = 'Role '+repr(metadata_role)+' specifies target '+ \
                  target_filepath+' which is not an allowed path according '+ \
                  'to the delegations set by '+repr(parent_role)+'.'
        raise tuf.RepositoryError(message)
    




  def _fileinfo_has_changed(self, metadata_filename, new_fileinfo):
    """
    <Purpose>
      Determine whether the current fileinfo of 'metadata_filename'
      differs from 'new_fileinfo'.  The 'new_fileinfo' argument
      should be extracted from the latest copy of the metadata
      that references 'metadata_filename'.  Example: 'root.txt'
      would be referenced by 'release.txt'.
        
      'new_fileinfo' should only be 'None' if this is for updating
      'root.txt' without having 'release.txt' available.

    <Arguments>
      metadadata_filename:
        The metadata filename for the role.  For the 'root' role,
        'metadata_filename' would be 'root.txt'.

      new_fileinfo:
        A dict object representing the new file information for
        'metadata_filename'.  'new_fileinfo' may be 'None' when
        updating 'root' without having 'release' available.  This
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
    if self.fileinfo.get(metadata_filename) is None:
      return True

    # 'new_fileinfo' should only be 'None' if updating 'root.txt'
    # without having 'release.txt'.
    if new_fileinfo is None:
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
    for algorithm, hash_value in new_fileinfo['hashes'].items():
      # We're only looking for a single match. This isn't a security
      # check, we just want to prevent unnecessary downloads.
      if hash_value == current_fileinfo['hashes'][algorithm]:
        return False

    return True





  def _update_fileinfo(self, metadata_filename):
    """
    <Purpose>
      Update the 'self.fileinfo' entry for the metadata belonging to
      'metadata_filename'.  If the 'current' metadata for 'metadata_filename'
      cannot be loaded, set the its fileinfo' to 'None' to  signal that
      it is not in the 'self.fileinfo' AND it also doesn't exist locally.

    <Arguments>
      metadata_filename:
        The metadata filename for the role.  For the 'root' role,
        'metadata_filename' would be 'root.txt'.

    <Exceptions>
      None.

    <Side Effects>
      The file details of 'metadata_filename' is calculated and
      stored to the 'self.fileinfo' store.

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
      self.fileinfo[current_filepath] = None
      return
   
    # Extract the file information from the actual file and save it
    # to the fileinfo store.
    file_length, hashes = tuf.util.get_file_details(current_filepath)
    metadata_fileinfo = tuf.formats.make_fileinfo(file_length, hashes)
    self.fileinfo[metadata_filename] = metadata_fileinfo
  
 



  def _move_current_to_previous(self, metadata_role):
    """
    <Purpose>
      Move the current metadata file for 'metadata_role' to the previous
      directory.

    <Arguments>
      metadata_role:
        The name of the metadata. This is a role name and should not end
        in '.txt'.  Examples: 'root', 'targets', 'targets/linux/x86'.
    
    <Exceptions>
      None.

    <Side Effects>
     The metadata file for 'metadata_role' is removed from 'current'
     and moved to the 'previous' directory.

    <Returns>
      None.

    """

    # Get the 'current' and 'previous' full file paths for 'metadata_role'
    metadata_filepath = metadata_role + '.txt'
    previous_filepath = os.path.join(self.metadata_directory['previous'],
                                     metadata_filepath)
    current_filepath = os.path.join(self.metadata_directory['current'],
                                    metadata_filepath)
   
    # Remove the previous path if it exists.
    if os.path.exists(previous_filepath):
      os.remove(previous_filepath)
    
    # Move the current path to the previous path.  
    if os.path.exists(current_filepath):
      os.rename(current_filepath, previous_filepath)





  def _delete_metadata(self, metadata_role):
    """
    <Purpose>
      Remove all (current) knowledge of 'metadata_role'.  The metadata
      belonging to 'metadata_role' is removed from the current
      'self.metadata' store and from the role database. The 'root.txt' role
      file is never removed.

    <Arguments>
      metadata_role:
        The name of the metadata. This is a role name and should not end
        in '.txt'.  Examples: 'root', 'targets', 'targets/linux/x86'.

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
    tuf.roledb.remove_role(metadata_role)





  def _ensure_not_expired(self, metadata_role):
    """
    <Purpose>
      Raise an exception if the current specified metadata has expired.
    
    <Arguments>
      metadata_role:
        The name of the metadata. This is a role name and should not end
        in '.txt'.  Examples: 'root', 'targets', 'targets/linux/x86'.
    
    <Exceptions>
      tuf.ExpiredMetadataError:
        If 'metadata_role' has expired.

    <Side Effects>
      None.

    <Returns>
      None.
    
    """
  
    # Construct the full metadata filename and the location of its
    # current path.  The current path of 'metadata_role' is needed
    # to log the exact filename of the expired metadata.
    metadata_filename = metadata_role + '.txt'
    rolepath =  os.path.join(self.metadata_directory['current'],
                             metadata_filename) 
    
    # Extract the expiration time.
    expires = self.metadata['current'][metadata_role]['expires']
   
    # If the current time has surpassed the expiration date, raise
    # an exception.
    if expires < time.time():
      expires_formatted = tuf.formats.format_time(expires)
      message = 'Metadata '+repr(rolepath)+' expired on '+expires_formatted+'.'
      raise tuf.ExpiredMetadataError(message)





  def all_targets(self):
    """
    <Purpose> 
      Get a list of the target information for all the trusted targets
      on the repository.  This list also includes all the targets of
      delegated roles.  The list conforms to 'tuf.formats.TARGETFILES_SCHEMA'
      and has the form:
      [{'filepath': 'a/b/c.txt',
        'fileinfo': {'length': 13323,
                     'hashes': {'sha256': dbfac345..}}
       ...]

    <Arguments>
      None.

    <Exceptions>
      tuf.RepositoryError:
        If the metadata for the 'targets' role is missing from
        the 'release' metadata.

      tuf.UnknownRoleError:
        If one of the roles could not be found in the role database.

    <Side Effects>
      The metadata for target roles is updated and stored.

    <Returns>
     A list of targets, conformant to 'tuf.formats.TARGETFILES_SCHEMA'.

    """
    
    # Load the most up-to-date targets of the 'targets' role and all
    # delegated roles.
    self._refresh_targets_metadata(include_delegations=True)
 
    all_targets = []
    # Fetch the targets for the 'targets' role.
    all_targets = self._targets_of_role('targets', skip_refresh=True)

    # Fetch the targets for the delegated roles.
    for delegated_role in tuf.roledb.get_delegated_rolenames('targets'):
      all_targets = self._targets_of_role(delegated_role, all_targets,
                                          skip_refresh=True)
    
    return all_targets





  def _refresh_targets_metadata(self, rolename='targets', include_delegations=False):
    """
    <Purpose>
      Refresh the targets metadata of 'rolename'.  If 'include_delegations'
      is True, include all the delegations that follow 'rolename'.  The metadata
      for the 'targets' role is updated in refresh() by the 
      _update_metadata_if_changed('targets') call, not here.  Delegated roles
      are not loaded when the repository is first initialized.  They are loaded
      from disk, updated if they have changed, and stored to the 'self.metadata'
      store by this function.  This function is called by the target methods,
      like all_targets() and targets_of_role().

    <Arguments>
      rolename:
        This is a delegated role name and should not end
        in '.txt'.  Example: 'targets/linux/x86'.
      
      include_delegations:
         Boolean indicating if the delegated roles set by 'rolename' should
         be refreshed.

    <Exceptions>
      tuf.RepositoryError:
        If the metadata file for the 'targets' role is missing
        from the 'release' metadata.

    <Side Effects>
      The metadata for the delegated roles are loaded and updated if they
      have changed.  Delegated metadata is removed from the role database if
      it has expired.

    <Returns>
      None.

    """

    roles_to_update = []

    # See if this role provides metadata and, if we're including
    # delegations, look for metadata from delegated roles.
    role_prefix = rolename + '/'
    for metadata_path in self.metadata['current']['release']['meta'].keys():
      if metadata_path == rolename + '.txt':
        roles_to_update.append(metadata_path[:-len('.txt')])
      elif include_delegations and metadata_path.startswith(role_prefix):
        roles_to_update.append(metadata_path[:-len('.txt')])

    # Remove the 'targets' role because it gets updated when the targets.txt
    # file is updated in _update_metadata_if_changed('targets').
    if rolename == 'targets':
      try:
        roles_to_update.remove('targets')
      except ValueError:
        message = 'The Release metadata file is missing the targets.txt entry.'
        raise tuf.RepositoryError(message)
  
    # If there is nothing to refresh, we are done.
    if not roles_to_update:
      return

    # Sort the roles so that parent roles always come first.
    roles_to_update.sort()
    logger.debug('Roles to update: '+repr(roles_to_update)+'.')

    # Iterate through 'roles_to_update', load its metadata
    # file, and update it if it has changed.
    for rolename in roles_to_update:
      self._load_metadata_from_file('previous', rolename)
      self._load_metadata_from_file('current', rolename)

      self._update_metadata_if_changed(rolename)

      # Remove the role if it has expired.
      try:
        self._ensure_not_expired(rolename)
      except tuf.ExpiredMetadataError:
        tuf.roledb.remove_role(rolename)





  def _targets_of_role(self, rolename, targets=None, skip_refresh=False):
    """
    <Purpose>
      Return the target information for all the targets of 'rolename'.
      The returned information is a list conformant to
      'tuf.formats.TARGETFILES_SCHEMA' and has the form:
      [{'filepath': 'a/b/c.txt',
        'fileinfo': {'length': 13323,
                     'hashes': {'sha256': dbfac345..}}
       ...]

    <Arguments>
      rolename:
        This is a role name and should not end
        in '.txt'.  Examples: 'targets', 'targets/linux/x86'.
      
      targets:
        A list of targets containing target information, conformant to
        'tuf.formats.TARGETFILES_SCHEMA'.

      skip_refresh:
        A boolean indicating if the target metadata for 'rolename'
        should be refreshed.

    <Exceptions>
      tuf.UnknownRoleError:
        If 'rolename' is not found in the role database.

    <Side Effects>
      The metadata for 'rolename' is refreshed if 'skip_refresh' is False.

    <Returns>
      A list of dict objects containing the target information of all the
      targets of 'rolename'.  Conformant to 'tuf.formats.TARGETFILES_SCHEMA'.

    """

    if targets is None:
      targets = []

    logger.debug('Getting targets of role: '+repr(rolename)+'.')

    if not tuf.roledb.role_exists(rolename):
      raise tuf.UnknownRoleError(rolename)

    # We do not need to worry about the target paths being trusted because
    # this is enforced before any new metadata is accepted.
    if not skip_refresh:
      self._refresh_targets_metadata(rolename)
  
    # Do we have metadata for 'rolename'?
    if rolename not in self.metadata['current']:
      message = 'No metadata for '+rolename+'. Unable to determine targets.'
      logger.debug(message)
      return targets

    # Get the targets specified by the role itself.
    for filepath, fileinfo in self.metadata['current'][rolename]['targets'].items():
      new_target = {} 
      new_target['filepath'] = filepath 
      new_target['fileinfo'] = fileinfo
      
      targets.append(new_target)

    return targets





  def targets_of_role(self, rolename='targets'):
    """
    <Purpose> 
      Return a list of trusted targets directly specified by 'rolename'.
      The returned information is a list conformant to
      tuf.formats.TARGETFILES_SCHEMA and has the form:
      [{'filepath': 'a/b/c.txt',
        'fileinfo': {'length': 13323,
                     'hashes': {'sha256': dbfac345..}}
       ...]
      
      This may be a very slow operation if there is a large number of
      delegations and many metadata files aren't already downloaded.

    <Arguments>
      rolename:
        The name of the role whose list of targets are wanted.
        The name of the role should start with 'targets'.
       
    <Exceptions>
      tuf.FormatError:
        If 'rolename' is improperly formatted.
     
      tuf.RepositoryError:
        If the metadata of 'rolename' could not be updated.

      tuf.UnknownRoleError:
        If 'rolename' is not found in the role database.

    <Side Effects>
      The metadata for updated delegated roles are downloaded and stored.
      
    <Returns>
      A list of targets, conformant to 'tuf.formats.TARGETFILES_SCHEMA'. 

    """
      
    # Does 'rolename' have the correct format?
    # Raise 'tuf.FormatError' if there is a mismatch.
    tuf.formats.RELPATH_SCHEMA.check_match(rolename)

    self._refresh_targets_metadata(rolename)
    
    return self._targets_of_role(rolename, skip_refresh=True)





  def target(self, target_filepath):
    """
    <Purpose>
      Return the target file information for 'target_filepath'.
    
    <Arguments>    
      target_filepath:
        The path to the target file on the repository. This
        will be relative to the 'targets' (or equivalent) directory
        on a given mirror.

    <Exceptions>
      tuf.FormatError:
        If 'target_filepath' is improperly formatted.

      tuf.RepositoryError:
        If 'target_filepath' was not found or there were more multiple
        versions (same file path but different file attributes).
   
    <Side Effects>
      The metadata for updated delegated roles are download and stored.
    
    <Returns>
      The target information for 'target_filepath', conformant to
      'tuf.formats.TARGETFILE_SCHEMA'.
    
    """

    # Does 'target_filepath' have the correct format?
    # Raise 'tuf.FormatError' if there is a mismatch.
    tuf.formats.RELPATH_SCHEMA.check_match(target_filepath)

    # Refresh the target metadata for all the delegated roles. 
    self._refresh_targets_metadata(include_delegations=True)
    all_rolenames = tuf.roledb.get_rolenames()

    # Iterate through all the target metadata.  Take precautions
    # to avoid duplicate files.
    target = []
    for rolename in all_rolenames:
      if self.metadata['current'][rolename]['_type'] != 'Targets':
        continue
      # We have a target role.  Extract the filepath and fileinfo
      # and compare it to 'target_filepath'.  Compare the fileinfo
      # to avoid duplicates.
      for filepath, fileinfo in self.metadata['current'][rolename] \
                                             ['targets'].items():
        if target_filepath == filepath:
          # If 'target' is empty, we can just go ahead and add 'target_filepath'
          # No need to check for duplicates in this case.
          if len(target) == 0:
            new_target = {}
            new_target['filepath'] = filepath
            new_target['fileinfo'] = fileinfo
            target.append(new_target)
            continue
          # It appears we have a duplicate.  If the fileinfo match,
          # do not add the duplicate.  Move on to the next target.
          elif len(target) == 1:
            if target[0]['fileinfo'] == fileinfo:
              continue
            # Okay, we have a matching filepath but a different fileinfo
            # for the duplicate.  Which one is the client expecting?
            # And why would the metadata list two different versions of the
            # same file?  Raise an exception.
            else:
              message = 'Found multiple '+repr(target_filepath)+'.'
              logger.error(message)
              raise tuf.RespositoryError(message)
   
    # Riase an exception if the target information could not be retrieved.
    if len(target) == 0:
      message = repr(target_filepath)+' not found.'
      logger.error(message)
      raise tuf.RepositoryError(message)
    
    return target[0] 





  def remove_obsolete_targets(self, destination_directory):
    """
    <Purpose>
      Remove any files that are in 'previous' but not 'current'.  This
      makes it so if you remove a file from a repository, it actually goes
      away.  The targets for the 'targets' role and all delegated roles
      are checked.
    
    <Arguments>
      destination_directory:
        The directory containing the target files tracked by TUF.

    <Exceptions>
      tuf.FormatError:
        If 'destination_directory' is improperly formatted.
      
      tuf.RepositoryError:
        If an error occurred removing any files.

    <Side Effects>
      Target files are removed from disk.

    <Returns>
      None.

    """
  
    # Does 'destination_directory' have the correct format?
    # Raise 'tuf.FormatError' if there is a mismatch.
    tuf.formats.PATH_SCHEMA.check_match(destination_directory)

    # Iterate through the rolenames and verify whether the 'previous'
    # directory contains a target no longer found in 'current'.
    for role in tuf.roledb.get_rolenames():
      if role.startswith('targets'):
        if role in self.metadata['previous'] and self.metadata['previous'][role] != None:
          for target in self.metadata['previous'][role]['targets'].keys():
            if target not in self.metadata['current'][role]['targets'].keys():
              # 'target' is only in 'previous', so remove it.
              logger.warn('Removing obsolete file: '+repr(target)+'.')
              # Remove the file if it hasn't been removed already.
              destination = os.path.join(destination_directory, target) 
              try:
                os.remove(destination)
              except OSError, e:
                # If 'filename' already removed, just log it.
                if e.errno == errno.ENOENT:
                  logger.info('File '+repr(destination)+' was already removed.')
                else:
                  logger.error(str(e))
              except Exception, e:
                logger.error(str(e))





  def updated_targets(self, targets, destination_directory):
    """
    <Purpose>
      Return the targets in 'targets' that have changed.  Targets are
      considered changed if they do not exist at 'destination_directory'
      or the target located there has mismatched file properties.

      The returned information is a list conformant to
      'tuf.formats.TARGETFILES_SCHEMA' and has the form:
      [{'filepath': 'a/b/c.txt',
        'fileinfo': {'length': 13323,
                     'hashes': {'sha256': dbfac345..}}
       ...]

    <Arguments>
      targets:
        A list of target files.

      destination_directory:
        The directory containing the target files.

    <Exceptions>
      tuf.FormatError:
        If the arguments are improperly formatted.

    <Side Effects>
      The files in 'targets' are read and their hashes computed. 

    <Returns>
      A list of targets, conformant to 'tuf.formats.TARGETFILES_SCHEMA'.

    """

    # Do the arguments have the correct format?
    # Raise 'tuf.FormatError' if there is a mismatch.
    tuf.formats.TARGETFILES_SCHEMA.check_match(targets)
    tuf.formats.PATH_SCHEMA.check_match(destination_directory)

    updated_targets = []

    for target in targets:
      # Get the target's filepath located in 'destination_directory'.
      # We will compare targets against this file.
      target_filepath = os.path.join(destination_directory, target['filepath'])
      
      # Try one of the algorithm/digest combos for a mismatch.  We break
      # as soon as we find a mismatch.
      for algorithm, digest in target['fileinfo']['hashes'].items():
        digest_object = None
        try:
          digest_object = tuf.hash.digest_filename(target_filepath,
                                                   algorithm=algorithm)
        # This exception would occur if the target does not exist locally. 
        except IOError:
          updated_targets.append(target)
          break
        # The file does exist locally, check if its hash differs. 
        if digest_object.hexdigest() != digest:
          updated_targets.append(target)
          break
    
    return updated_targets





  def download_target(self, target, destination_directory):
    """
    <Purpose>
      Download 'target' and verify it is trusted.
        
      This will only store the file at 'destination_directory' if the downloaded
      file matches the description of the file in the trusted metadata.
    
    <Arguments>
      target:
        The target to be downloaded.  Conformant to
        'tuf.formats.TARGETFILE_SCHEMA'.

      destination_directory:
        The directory to save the downloaded target file.

    <Exceptions>
      tuf.FormatError:
        If 'target' is not properly formatted.

      tuf.DownloadError:
        If a target could not be downloaded from any of the mirrors.

    <Side Effects>
      A target file is saved to the local system.

    <Returns>
      None.

    """

    # Do the arguments have the correct format? 
    # This check ensures the arguments have the appropriate 
    # number of objects and object types, and that all dict
    # keys are properly named.
    # Raise 'tuf.FormatError' if the check fail.
    tuf.formats.TARGETFILE_SCHEMA.check_match(target)
    tuf.formats.PATH_SCHEMA.check_match(destination_directory)
   
    # Reference to the 'get_list_of_mirrors' function.
    get_mirrors = tuf.mirrors.get_list_of_mirrors

    # Reference to the 'download_url_to_tempfileobj' function.
    download_file = tuf.download.download_url_to_tempfileobj

    # Extract the target file information.
    target_filepath = target['filepath']
    trusted_length = target['fileinfo']['length']
    trusted_hashes = target['fileinfo']['hashes']

    target_file_object = None
    # Iterate through the repositority mirrors until we successfully
    # download a target.
    for mirror_url in get_mirrors('target', target_filepath, self.mirrors):
      try: 
        target_file_object = download_file(mirror_url, trusted_hashes,
                                           trusted_length)
        break
      except (tuf.DownloadError, tuf.FormatError), e:
        logger.warn('Download failed from '+mirror_url+'.')
        target_file_object = None
        continue
    # We have gone through all the mirrors.  Did we get a target file object?
    if target_file_object == None: 
      raise tuf.DownloadError('No download locations known.')
   
    # We acquired a target file object from a mirror.  Move the file into
    # place (i.e., locally to 'destination_directory').
    destination = os.path.join(destination_directory, target_filepath)
    destination = os.path.abspath(destination)
    target_dirpath = os.path.dirname(destination)
    if target_dirpath:
      try:
        os.makedirs(target_dirpath)
      except OSError, e:
        if e.errno == errno.EEXIST:
          pass
        else:
          raise
    
    target_file_object.move(destination)
