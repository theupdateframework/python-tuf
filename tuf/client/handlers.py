import os
import tuf
import securesystemslib
import logging
import shutil
import time
import iso8601
import six
import errno
import tempfile
import json
import hashlib

logger = logging.getLogger('tuf.client.handlers')
SUPPORTED_MAJOR_VERSION = 1

class MetadataHandler(object):


  def __init__(self, mirrors, repository_directory, repository_name=None):
    self.repository_directory = repository_directory
    self.repository_name = repository_name
    self.mirrors = mirrors





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





  def _verify_root_chain_link(self, rolename, current_root_metadata,
    next_root_metadata):

    if rolename != 'root':
      return True

    current_root_role = current_root_metadata['roles'][rolename]

    # Verify next metadata with current keys/threshold
    valid = tuf.sig.verify(next_root_metadata, rolename, self.repository_name,
        current_root_role['threshold'], current_root_role['keyids'])

    if not valid:
      raise securesystemslib.exceptions.BadSignatureError('Root is not signed'
          ' by previous threshold of keys.')





  def _verify_uncompressed_metadata_file(self, metadata_file_object,
      metadata_role):
      """
      <Purpose>
      Non-public method that verifies an uncompressed metadata file.  An
      exception is raised if 'metadata_file_object is invalid.  There is no
      return value.
       <Arguments>
      metadata_file_object:
          A 'securesystemslib.util.TempFile' instance containing the metadata
          file.  'metadata_file_object' ensures the entire file is returned with
          read().
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
      valid = tuf.sig.verify(metadata_signable, metadata_role,
          self.repository_name)
      if not valid:
        raise securesystemslib.exceptions.BadSignatureError(metadata_role)





class FileSystemMetadataHandler(MetadataHandler):





  def __init__(self, repository_mirrors, repository_directory, repository_name=None):
    self.mirrors = repository_mirrors
    self.repository_directory = repository_directory
    self.repository_name = repository_name
    # Store the location of the client's metadata directory.
    self.metadata_directory = {}
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





  def load_metadata_object(self, metadata_set, metadata_role):
    """
    Reads the metadata file from the disk, converts it to
    a json object and extracts the value of the signed attribute
    Returns None if the file does not exist
    """
    # Save and construct the full metadata path.
    metadata_directory = self.metadata_directory[metadata_set]
    metadata_filename = metadata_role + '.json'
    metadata_filepath = os.path.join(metadata_directory, metadata_filename)
     # Ensure the metadata path is valid/exists, else ignore the call.
    if os.path.exists(metadata_filepath):
      # Load the file.  The loaded object should conform to
      # 'tuf.formats.SIGNABLE_SCHEMA'.
      try:
        metadata_signable = securesystemslib.util.load_json_file(
            metadata_filepath)
      # Although the metadata file may exist locally, it may not
      # be a valid json file.  On the next refresh cycle, it will be
      # updated as required.  If Root if cannot be loaded from disk
      # successfully, an exception should be raised by the caller.
      except securesystemslib.exceptions.Error:
          return
      tuf.formats.check_signable_object_format(metadata_signable)
      # Extract the 'signed' role object from 'metadata_signable'.
      metadata_object = metadata_signable['signed']
      return metadata_object
    return None





  def get_metadata_file_details(self, metadata_set, metadata_filename):
      """
      Returns details of a metadata file - its length and hash value
      """
      path = os.path.join(self.metadata_directory[metadata_set],
                          metadata_filename)
      return securesystemslib.util.get_file_details(path)





  def get_metadata_file(self, metadata_role, remote_filename,
                        expected_version, current_version,
                        upperbound_filelength):
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
      A 'securesystemslib.util.TempFile' file-like object containing the
      metadata.
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
        # downloaded version is at least greater than the one locally
        # available.
        else:
          # Verify that the version number of the locally stored
          # 'timestamp.json', if available, is less than what was downloaded.
          # Otherwise, accept the new timestamp with version number
          # 'version_downloaded'.

          try:
            current_version = \
              self.metadata['current'][metadata_role]['version']

            if version_downloaded < current_version:
              raise tuf.exceptions.ReplayedMetadataError(metadata_role,
                  version_downloaded, current_version)

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





  def _get_metadata_file_content(self, metadata_role, remote_filename,
                          expected_version, current_version,
                          upperbound_filelength):
    """
    Returns content of a metadata file. The file is downloaded by
    calling get_metadata_file. Once that is done, its contents are returned.
    If the file could not be downloaded, None if returned
    """
    file_object = self.get_metadata_file(metadata_role, remote_filename,
                                         expected_version, current_version,
                                         upperbound_filelength)
    if not file_object:
      return None
    return securesystemslib.util.load_json_string(file_object.read().decode('utf-8'))





  def get_updated_metadata(self, metadata_role, current_version,
                        version=None, consistent_snapshot=False,
                        upperbound_filelength=None):
      """
      This method is called when updating metadata.
      A newwer version is downloaded, marked as current (moved to the current
      directory) and returned.
      """
      # Construct the metadata filename as expected by the download/mirror
      # modules.
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
      if consistent_snapshot and version:
          filename_version = version
          dirname, basename = os.path.split(remote_filename)
          remote_filename = os.path.join(
              dirname, str(filename_version) + '.' + basename)
      metadata_file_object = \
      self.get_metadata_file(metadata_role, remote_filename,
                             version, current_version,
                             upperbound_filelength)
      return self._move_metadata(metadata_filename, metadata_file_object)





  def _move_metadata(self, metadata_filename, metadata_file_object):
      """
      Moves the metadata file into place. The new metadata into the current
      directory and the old current into previous.
      """
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
      return metadata_signable





  def metadata_file_exists(self, metadata_set, metadata_filename):
    """
    Checks if the metadata exists. In this case it is just
    checked if the file exists on disk
    """
    path = os.path.join(self.metadata_directory[metadata_set],
                        metadata_filename)
    return os.path.exists(path)





  def move_current_to_previous(self, metadata_role):
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




  def delete_metadata(self, metadata_role):
    """
    Gets rid of the current metadata file.
    """
    self.move_current_to_previous(metadata_role)




class GitMetadataHandler(MetadataHandler):
  """
  The main idea is here is that in our case metadata is hosted
  by a git repository. A user will have a local copy of this
  repository and updating metadata means that a user updates their
  local metadata repository. We do not want to download files from
  a remote server.
  """


  def __init__(self, repository_directory, repository_name, mirrors):
    """
    In our case, the metadata is contained by a git repository.
    mirrors should contain url of that repository. The repository
    is cloned as a bare git repository. repository_directory is the user's
    local repository containing metadata.
    """
    pass





  def load_metadata_object(self, metadata_set, metadata_role):
    """
    In this case metadata should not be loaded from disk
    It is read from a bare git repository by calling git show
    """
    pass





  def metadata_file_exists(self, metadata_set, metadata_filename):
    """
    Check if the git repository contains the metadata file
    """
    pass





  def get_metadata_file_details(self, metadata_set, metadata_filename):
    """
    Calculation of the file details preferably without writing to a file
    just so that it ca be read later
    """
    pass





  def get_metadata_file_content(self, metadata_role, file_name,
                                expected_version, current_version,
                                upperbound_filelength=None, move_metadata=False):
    """
    We dont have the physical files in our case. So we just read the content
    of the file from git. This also searches for a while that has the expected
    version. This is done by checking out commits of the cloned repository.
    """
    pass






  def _move_current_to_previous(self, metadata_role):
    """
    This method should mark the current metadata as
    previous. Also, this should remove the current
    metadata.
    """
    pass






  def delete_metadata(self, metadata_role):
    "No need to do anything here"
    pass





  def get_updated_metadata(self, metadata_role, current_version,
                        version=None, consistent_snapshot=False,
                        upperbound_filelength=None):
    """
    Getting newer version of the metadata files in this case
    means checking out commits of the cloned bare git repository
    So, we traverse through the commits until we find the first one
    where the metadata file's version is equal to the needed one
    """
    pass





class FileTargetsHandler(object):





  def __init__(self, mirrors, consistent_snapshot):
    self.mirrors = mirrors
    self.consistent_snapshot = consistent_snapshot





  def _get_target_file(self, target_filepath, file_length, file_hashes):
    """
    <Purpose>
      Non-public method that safely (i.e., the file length and hash are
      strictly equal to the trusted) downloads a target file up to a certain
      length, and checks its hashes thereafter.

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
      # Note: values() does not return a list in Python 3.  Use list()
      # on values() for Python 2+3 compatibility.
      target_digest = list(file_hashes.values()).pop()
      dirname, basename = os.path.split(target_filepath)
      target_filepath = os.path.join(dirname, target_digest + '.' + basename)

    return self._get_file(target_filepath, verify_target_file,
        'target', file_length, download_safely=True)





  def _get_file(self, filepath, verify_file_function, file_type, file_length,
      download_safely=True):
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
      A 'securesystemslib.util.TempFile' file-like object containing the
      metadata or target.
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
          file_object = tuf.download.safe_download(file_mirror, file_length)

        else:
          file_object = tuf.download.unsafe_download(file_mirror, file_length)

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
      logger.error('Failed to update ' + repr(filepath) + ' from'
          ' all mirrors: ' + repr(file_mirror_errors))
      raise tuf.exceptions.NoWorkingMirrorError(file_mirror_errors)





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

    # Read the entire contents of 'file_object', a
    # 'securesystemslib.util.TempFile' file-like object that ensures the entire
    # file is read.
    observed_length = len(file_object.read())

    # Return and log a message if the length 'file_object' is equal to
    # 'trusted_file_length', otherwise raise an exception.  A hard check
    # ensures that a downloaded file strictly matches a known, or trusted,
    # file length.
    if observed_length != trusted_file_length:
      raise tuf.exceptions.DownloadLengthMismatchError(trusted_file_length,
          observed_length)

    else:
      logger.debug('Observed length (' + str(observed_length) +\
          ') == trusted length (' + str(trusted_file_length) + ')')





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
      logger.debug('Observed length (' + str(observed_length) +\
          ') <= trusted length (' + str(trusted_file_length) + ')')





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
        A 'securesystemslib.util.TempFile' file-like object.  'file_object'
        ensures that a read() without a size argument properly reads the entire
        file.

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
        raise securesystemslib.exceptions.BadHashError(trusted_hash,
            computed_hash)

      else:
        logger.info('The file\'s ' + algorithm + ' hash is'
            ' correct: ' + trusted_hash)





  def _remove_obsolete_targets(self, destination_directory):
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





  def _get_updated_targets(self, targets, destination_directory):
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





class RepositoryTargetsHandler(object):
  """
  Targets in this case are git repositories. We don't want to download files
  We want to update the repositories by calling git fetch/merge
  But we firstly want to ensure that the fetched commits are in
  accordance with the metadata
  """

  def __init__(self, mirrors, consistent_snapshot):
    self.mirrors = mirrors
    self.consistent_snapshot = consistent_snapshot





  def download_target(self, target, destination_directory):
    """
    This fetches the changes and merges them into the
    currently checked out branch
    """
    pass