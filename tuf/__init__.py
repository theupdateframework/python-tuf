"""
<Program Name>
  __init__.py

<Author>
  Geremy Condra
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  VD: April 4, 2012 Revision.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Define TUF Exceptions.

  The names chosen for TUF Exception classes should end in
  'Error' except where there is a good reason not to, and
  provide that reason in those cases.

"""

import urlparse

# Import 'tuf.formats' if a module tries to import the
# entire tuf package (i.e., from tuf import *). 
__all__ = ['formats']





class Error(Exception):
  """Indicate a generic error."""
  pass





class Warning(Warning):
  """TUF's warning category class.  It is used by the 'warnings' module."""
  pass





class FormatError(Error):
  """Indicate an error while validating an object's format."""
  pass





class InvalidMetadataJSONError(FormatError):
  """Indicate that a metadata file is not valid JSON."""

  def __init__(self, exception):
    # Store the original exception.
    self.exception = exception

  def __str__(self):
    # Show the original exception.
    return str(self.exception)





class UnsupportedAlgorithmError(Error):
  """Indicate an error while trying to identify a user-specified algorithm."""
  pass





class BadHashError(Error):
  """Indicate an error while checking the value a hash object."""

  def __init__(self, expected_hash, observed_hash):
    self.expected_hash = expected_hash
    self.observed_hash = observed_hash

  def __str__(self):
    return 'Observed hash ('+str(self.observed_hash)+\
           ') != expected hash ('+str(self.expected_hash)+')'





class BadPasswordError(Error):
  """Indicate an error after encountering an invalid password."""
  pass





class UnknownKeyError(Error):
  """Indicate an error while verifying key-like objects (e.g., keyids)."""
  pass





class RepositoryError(Error):
  """Indicate an error with a repository's state, such as a missing file."""
  pass





class ForbiddenTargetError(RepositoryError):
  """Indicate that a role signed for a target that it was not delegated to."""
  pass





class ExpiredMetadataError(Error):
  """Indicate that a TUF Metadata file has expired."""

  def __init__(self, expiry_time):
    self.expiry_time = expiry_time # UTC

  def __str__(self):
    return 'Metadata expired on '+str(self.expiry_time)+'.'





class ReplayedMetadataError(RepositoryError):
  """Indicate that some metadata has been replayed to the client."""

  def __init__(self, metadata_role, previous_version, current_version):
    self.metadata_role = metadata_role
    self.previous_version = previous_version
    self.current_version = current_version


  def __str__(self):
    return 'Downloaded '+str(self.metadata_role)+' is older ('+\
           str(self.previous_version)+') than the version currently '+\
           'installed ('+repr(self.current_version)+').'





class CryptoError(Error):
  """Indicate any cryptography-related errors."""
  pass





class BadSignatureError(CryptoError):
  """Indicate that some metadata file had a bad signature."""

  def __init__(self, metadata_role_name):
    self.metadata_role_name = metadata_role_name

  def __str__(self):
    return str(self.metadata_role_name)+' metadata has bad signature!'




class UnknownMethodError(CryptoError):
  """Indicate that a user-specified cryptograpthic method is unknown."""
  pass





class UnsupportedLibraryError(Error):
  """Indicate that a supported library could not be located or imported."""
  pass





class DecompressionError(Error):
  """Indicate that some error happened while decompressing a file."""

  def __init__(self, exception):
    # Store the original exception.
    self.exception = exception

  def __str__(self):
    # Show the original exception.
    return str(self.exception)





class DownloadError(Error):
  """Indicate an error occurred while attempting to download a file."""
  pass





class DownloadLengthMismatchError(DownloadError):
  """Indicate that a mismatch of lengths was seen while downloading a file."""

  def __init__(self, expected_length, observed_length):
    self.expected_length = expected_length #bytes
    self.observed_length = observed_length #bytes

  def __str__(self):
    return 'Observed length ('+str(self.observed_length)+\
           ') <= expected length ('+str(self.expected_length)+')'





class SlowRetrievalError(DownloadError):
  """"Indicate that downloading a file took an unreasonably long time."""

  def __init__(self, average_download_speed):
    self.__average_download_speed = average_download_speed #bytes/second

  def __str__(self):
    return "Average download speed: "+str(self.__average_download_speed)+\
           " bytes/second"





class KeyAlreadyExistsError(Error):
  """Indicate that a key already exists and cannot be added."""
  pass





class RoleAlreadyExistsError(Error):
  """Indicate that a role already exists and cannot be added."""
  pass





class UnknownRoleError(Error):
  """Indicate an error trying to locate or identify a specified TUF role."""
  pass





class UnknownTargetError(Error):
  """Indicate an error trying to locate or identify a specified target."""
  pass





class InvalidNameError(Error):
  """Indicate an error while trying to validate any type of named object"""
  pass





class NoWorkingMirrorError(Error):
  """An updater will throw this exception in case it could not download a
  metadata or target file.

  A dictionary of Exception instances indexed by every mirror URL will also be
  provided."""

  def __init__(self, mirror_errors):
    # Dictionary of URL strings to Exception instances
    self.mirror_errors = mirror_errors

  def __str__(self):
    all_errors = 'No working mirror was found:'

    for mirror_url, mirror_error in self.mirror_errors.iteritems():
      try:
        # http://docs.python.org/2/library/urlparse.html#urlparse.urlparse
        mirror_url_tokens = urlparse.urlparse(mirror_url)
      except:
        logging.exception('Failed to parse mirror URL: '+str(mirror_url))
        mirror_netloc = mirror_url
      else:
        mirror_netloc = mirror_url_tokens.netloc

      all_errors += '\n  '+str(mirror_netloc)+': '+str(mirror_error)

    return all_errors





