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
  def generate_snapshot_metadata(metadata_directory, version, expiration_date,
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


