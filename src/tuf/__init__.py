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





class ExpiredMetadataError(Error):
  """Indicate that a TUF Metadata file has expired."""
  pass





class MetadataNotAvailableError(Error):
  """Indicate an error locating a Metadata file for a specified target/role."""
  pass





class CryptoError(Error):
  """Indicate any cryptography-related errors."""
  pass





class UnsupportedLibraryError(Error):
  """Indicate that a supported library could not be located or imported."""
  pass





class UnknownMethodError(CryptoError):
  """Indicate that a user-specified cryptograpthic method is unknown."""
  pass





class DownloadError(Error):
  """Indicate an error occurred while attempting to download a file."""
  pass





class KeyAlreadyExistsError(Error):
  """Indicate that a key already exists and cannot be added."""
  pass





class RoleAlreadyExistsError(Error):
  """Indicate that a role already exists and cannot be added."""
  pass





class UnknownRoleError(Error):
  """Indicate an error trying to locate or identify a specified TUF role."""
  pass





class InvalidNameError(Error):
  """Indicate an error while trying to validate any type of named object"""
  pass
