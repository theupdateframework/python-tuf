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





class UnsupportedAlgorithmError(Error):
  """Indicate an error while trying to identify a user-specified algorithm."""
  pass





class BadHashError(Error):
  """Indicate an error while checking the value a hash object."""
  pass





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
  pass





class ReplayedMetadataError(RepositoryError):
  """Indicate that some metadata has been replayed to the client."""

  def __init__(self, metadata_role, previous_version, current_version):
    self.metadata_role = metadata_role
    self.previous_version = previous_version
    self.current_version = current_version


  def __str__(self):
    return str(self.metadata_role)+' is older than the version currently'+\
      'installed.\nDownloaded version: '+repr(self.previous_version)+'\n'+\
      'Current version: '+repr(self.current_version)





class CryptoError(Error):
  """Indicate any cryptography-related errors."""
  pass





class BadSignatureError(CryptoError):
  """Indicate that some metadata file had a bad signature."""
  pass





class UnknownMethodError(CryptoError):
  """Indicate that a user-specified cryptograpthic method is unknown."""
  pass





class UnsupportedLibraryError(Error):
  """Indicate that a supported library could not be located or imported."""
  pass





class DecompressionError(Error):
  """Indicate that some error happened while decompressing a file."""
  pass





class DownloadError(Error):
  """Indicate an error occurred while attempting to download a file."""
  pass





class DownloadLengthMismatchError(DownloadError):
  """Indicate that a mismatch of lengths was seen while downloading a file."""
  pass





class SlowRetrievalError(DownloadError):
  """"Indicate that downloading a file took an unreasonably long time."""

  def __init__(self, number_of_slow_chunks):
    self.number_of_slow_chunks = number_of_slow_chunks





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
    return str(self.mirror_errors)





