import abc
import os
import logging

from securesystemslib import formats as sslib_formats

from tuf import formats
from tuf import roledb
from tuf import repository_lib as repolib

# See 'log.py' to learn how logging is handled in TUF.
logger = logging.getLogger(__name__)

# The extension of TUF metadata.
METADATA_EXTENSION = '.json'

# The metadata filenames of the top-level roles.
ROOT_FILENAME = 'root' + METADATA_EXTENSION
TARGETS_FILENAME = 'targets' + METADATA_EXTENSION
SNAPSHOT_FILENAME = 'snapshot' + METADATA_EXTENSION
TIMESTAMP_FILENAME = 'timestamp' + METADATA_EXTENSION

class SnapshotInterface():
  """
  <Purpose>
  Defines an interface for abstract snapshot metadata operations
  to be implemented for a variety of snapshot creation methods,
  including the classic manifest snapshot metadata and snapshot
  merkle trees
  """

  __metaclass__ = abc.ABCMeta

  @abc.abstractmethod
  def add_to_snapshot(self, rolename : str):
    """
    <Purpose>
     Indicate to the snapshot interface that 'rolename'
     should be included in the next snapshot generation.

    <Arguments>
     rolename:
      The name of the role to be added

    <Exceptions>
     TODO

    <Returns>
     None
    """
    raise NotImplementedError # pragma: no cover




  @abc.abstractmethod
  def remove_from_snapshot(self, rolename : str):
    """
    <Purpose>
     Indicate to the snapshot interface that 'rolename'
     should be removed from the next snapshot generation.

    <Arguments>
     rolename:
      The name of the role to be removed

    <Exceptions>
     TODO

    <Returns>
     None
    """
    raise NotImplementedError # pragma: no cover




  @abc.abstractmethod
  def generate_snapshot_metadata(self, metadata_directory, version, expiration_date,
    storage_backend, consistent_snapshot=False,
    repository_name='default', use_length=False, use_hashes=False):
    """
    <Purpose>
		 Create the snapshot metadata

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
     TODO
    """
    raise NotImplementedError # pragma: no cover




class ManifestSnapshot(SnapshotInterface):
  """
  <Purpose>
    A concrete implementation of SnapshotInterface that creates
    snapshot metadata using the traditional method described inthe
    TUF specification
  """


  # As ManifestSnapshot is effectively a stateless wrapper around various
  # standard library operations, we only ever need a single instance of it.
  # That single instance is safe to be (re-)used by all callers. Therefore
  # implement the singleton pattern to avoid uneccesarily creating multiple
  # objects.
  _instance = None

  def __new__(cls, *args, **kwargs):
    if cls._instance is None:
      cls._instance = object.__new__(cls, *args, **kwargs)
    return cls._instance


  def add_to_snapshot(self, rolename : str):
    return

  def remove_from_snapshot(self, rolename : str):
    return

  def generate_snapshot_metadata(self, metadata_directory, version, expiration_date,
    storage_backend, consistent_snapshot=False,
    repository_name='default', use_length=False, use_hashes=False):

    # Do the arguments have the correct format?
    # This check ensures arguments have the appropriate number of objects and
    # object types, and that all dict keys are properly named.
    # Raise 'securesystemslib.exceptions.FormatError' if the check fails.
    sslib_formats.PATH_SCHEMA.check_match(metadata_directory)
    formats.METADATAVERSION_SCHEMA.check_match(version)
    sslib_formats.ISO8601_DATETIME_SCHEMA.check_match(expiration_date)
    sslib_formats.BOOLEAN_SCHEMA.check_match(consistent_snapshot)
    sslib_formats.NAME_SCHEMA.check_match(repository_name)
    sslib_formats.BOOLEAN_SCHEMA.check_match(use_length)
    sslib_formats.BOOLEAN_SCHEMA.check_match(use_hashes)

    # Snapshot's 'fileinfodict' shall contain the version number of Root,
    # Targets, and all delegated roles of the repository.
    fileinfodict = {}

    length, hashes = repolib.get_hashes_and_length_if_needed(use_length, use_hashes,
        os.path.join(metadata_directory, TARGETS_FILENAME), storage_backend)

    targets_role = TARGETS_FILENAME[:-len(METADATA_EXTENSION)]

    targets_file_version = repolib.get_metadata_versioninfo(targets_role,
        repository_name)

    # Make file info dictionary with make_metadata_fileinfo because
    # in the tuf spec length and hashes are optional for all
    # METAFILES in snapshot.json including the top-level targets file.
    fileinfodict[TARGETS_FILENAME] = formats.make_metadata_fileinfo(
        targets_file_version['version'], length, hashes)

    # Search the metadata directory and generate the versioninfo of all the role
    # files found there.  This information is stored in the 'meta' field of
    # 'snapshot.json'.

    metadata_files = sorted(storage_backend.list_folder(metadata_directory),
        reverse=True)
    for metadata_filename in metadata_files:
      # Strip the version number if 'consistent_snapshot' is True.
      # Example:  '10.django.json'  --> 'django.json'
      metadata_name, junk = repolib.strip_version_number(metadata_filename,
          consistent_snapshot)

      # All delegated roles are added to the snapshot file.
      if metadata_filename.endswith(METADATA_EXTENSION):
        rolename = metadata_filename[:-len(METADATA_EXTENSION)]

        # Obsolete role files may still be found.  Ensure only roles loaded
        # in the roledb are included in the Snapshot metadata.  Since the
        # snapshot and timestamp roles are not listed in snapshot.json, do not
        # list these roles found in the metadata directory.
        if roledb.role_exists(rolename, repository_name) and \
            rolename not in roledb.TOP_LEVEL_ROLES:

          length, hashes = repolib.get_hashes_and_length_if_needed(use_length, use_hashes,
              os.path.join(metadata_directory, metadata_filename), storage_backend)

          file_version = repolib.get_metadata_versioninfo(rolename,
              repository_name)

          fileinfodict[metadata_name] = formats.make_metadata_fileinfo(
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
    return formats.build_dict_conforming_to_schema(
        formats.SNAPSHOT_SCHEMA,
        version=version,
        expires=expiration_date,
        meta=fileinfodict)
