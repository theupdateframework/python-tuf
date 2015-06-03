"""
<Program Name>
  util.py

<Author>
  Konstantin Andrianov

<Started>
  March 24, 2012.  Derived from original util.py written by Geremy Condra.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Provides utility services.  This module supplies utility functions such as:
  get_file_details() that computes the length and hash of a file, import_json
  that tries to import a working json module, load_json_* functions, and a
  TempFile class that generates a file-like object for temporary storage, etc.
"""

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import os
import sys
import gzip
import shutil
import logging
import tempfile

import tuf
import tuf.hash
import tuf.conf
import tuf.formats
import six

# The algorithm used by the repository to generate the digests of the
# target filepaths, which are included in metadata files and may be prepended
# to the filenames of consistent snapshots.
HASH_FUNCTION = 'sha256'

# See 'log.py' to learn how logging is handled in TUF.
logger = logging.getLogger('tuf.util')


class TempFile(object):
  """
  <Purpose>
    A high-level temporary file that cleans itself up or can be manually
    cleaned up. This isn't a complete file-like object. The file functions
    that are supported make additional common-case safe assumptions.  There
    are additional functions that aren't part of file-like objects.  TempFile
    is used in the download.py module to temporarily store downloaded data while
    all security checks (file hashes/length) are performed.
  """

  def _default_temporary_directory(self, prefix):
    """__init__ helper."""
    try:
      self.temporary_file = tempfile.NamedTemporaryFile(prefix=prefix)
    
    except OSError as err: # pragma: no cover
      logger.critical('Cannot create a system temporary directory: '+repr(err))
      raise tuf.Error(err)



  def __init__(self, prefix='tuf_temp_'):
    """
    <Purpose>
      Initializes TempFile.

    <Arguments>
      prefix:
        A string argument to be used with tempfile.NamedTemporaryFile function.

    <Exceptions>
      tuf.Error on failure to load temp dir.

    <Return>
      None.
    """

    self._compression = None
    
    # If compression is set then the original file is saved in 'self._orig_file'.
    self._orig_file = None
    temp_dir = tuf.conf.temporary_directory
    if temp_dir is not None and tuf.formats.PATH_SCHEMA.matches(temp_dir):
      try:
        self.temporary_file = tempfile.NamedTemporaryFile(prefix=prefix,
                                                          dir=temp_dir)
      except OSError as err:
        logger.error('Temp file in ' + temp_dir + ' failed: '+repr(err))
        logger.error('Will attempt to use system default temp dir.')
        self._default_temporary_directory(prefix)
    
    else:
      self._default_temporary_directory(prefix)





  def get_compressed_length(self):
    """
    <Purpose>
      Get the compressed length of the file. This will be correct information
      even when the file is read as an uncompressed one.

    <Arguments>
      None.

    <Exceptions>
      OSError.

    <Return>
      Nonnegative integer representing compressed file size.
    """

    # Even if we read a compressed file with the gzip standard library module,
    # the original file will remain compressed.
    return os.stat(self.temporary_file.name).st_size



  def flush(self):
    """
    <Purpose>
      Flushes buffered output for the file.

    <Arguments>
      None.

    <Exceptions>
      None.

    <Return>
      None.
    """

    self.temporary_file.flush()





  def read(self, size=None):
    """
    <Purpose>
      Read specified number of bytes.  If size is not specified then the whole
      file is read and the file pointer is placed at the beginning of the file.

    <Arguments>
      size:
        Number of bytes to be read.

    <Exceptions>
      tuf.FormatError: if 'size' is invalid.

    <Return>
      String of data.
    """

    if size is None:
      self.temporary_file.seek(0)
      data = self.temporary_file.read()
      self.temporary_file.seek(0)
      
      return data
    
    else:
      if not (isinstance(size, int) and size > 0):
        raise tuf.FormatError
      
      return self.temporary_file.read(size)





  def write(self, data, auto_flush=True):
    """
    <Purpose>
      Writes a data string to the file.

    <Arguments>
      data:
        A string containing some data.

      auto_flush:
        Boolean argument, if set to 'True', all data will be flushed from
        internal buffer.

    <Exceptions>
      None.

    <Return>
      None.
    """

    self.temporary_file.write(data)
    if auto_flush:
      self.flush()



  def move(self, destination_path):
    """
    <Purpose>
      Copies 'self.temporary_file' to a non-temp file at 'destination_path' and
      closes 'self.temporary_file' so that it is removed.

    <Arguments>
      destination_path:
        Path to store the file in.

    <Exceptions>
      None.

    <Return>
      None.
    """

    self.flush()
    self.seek(0)
    destination_file = open(destination_path, 'wb')
    shutil.copyfileobj(self.temporary_file, destination_file)
    destination_file.close()
    
    # 'self.close()' closes temporary file which destroys itself.
    self.close_temp_file()





  def seek(self, *args):
    """
    <Purpose>
      Set file's current position.

    <Arguments>
      *args:
        (*-operator): unpacking argument list is used
        because seek method accepts two args: offset and whence.  If whence is
        not specified, its default is 0.  Indicate offset to set the file's
        current position. Refer to the python manual for more info.

    <Exceptions>
      None.

    <Return>
      None.
    """

    self.temporary_file.seek(*args)





  def decompress_temp_file_object(self, compression):
    """
    <Purpose>
      To decompress a compressed temp file object.  Decompression is performed
      on a temp file object that is compressed, this occurs after downloading
      a compressed file.  For instance if a compressed version of some meta
      file in the repository is downloaded, the temp file containing the
      compressed meta file will be decompressed using this function.
      Note that after calling this method, write() can no longer be called.

                            meta.json.gz
                               |...[download]
                        temporary_file (containing meta.json.gz)
                        /             \
               temporary_file          _orig_file
          containing meta.json          containing meta.json.gz
          (decompressed data)

    <Arguments>
      compression:
        A string indicating the type of compression that was used to compress
        a file.  Only gzip is allowed.

    <Exceptions>
      tuf.FormatError: If 'compression' is improperly formatted.

      tuf.Error: If an invalid compression is given.

      tuf.DecompressionError: If the compression failed for any reason.

    <Side Effects>
      'self._orig_file' is used to store the original data of 'temporary_file'.

    <Return>
      None.
    """

    # Does 'compression' have the correct format?
    # Raise 'tuf.FormatError' if there is a mismatch.
    tuf.formats.NAME_SCHEMA.check_match(compression)
    
    if self._orig_file is not None:
      raise tuf.Error('Can only set compression on a TempFile once.')

    if compression != 'gzip':
      raise tuf.Error('Only gzip compression is supported.')

    self.seek(0)
    self._compression = compression
    self._orig_file = self.temporary_file

    try:
      gzip_file_object = gzip.GzipFile(fileobj=self.temporary_file, mode='rb')
      uncompressed_content = gzip_file_object.read()
      self.temporary_file = tempfile.NamedTemporaryFile()
      self.temporary_file.write(uncompressed_content)
      self.flush() 
    
    except Exception as exception:
      raise tuf.DecompressionError(exception)





  def close_temp_file(self):
    """
    <Purpose>
      Closes the temporary file object. 'close_temp_file' mimics usual
      file.close(), however temporary file destroys itself when
      'close_temp_file' is called. Further if compression is set, second
      temporary file instance 'self._orig_file' is also closed so that no open
      temporary files are left open.

    <Arguments>
      None.

    <Exceptions>
      None.

    <Side Effects>
      Closes 'self._orig_file'.

    <Return>
      None.
    """

    self.temporary_file.close()
    # If compression has been set, we need to explicitly close the original
    # file object.
    if self._orig_file is not None:
      self._orig_file.close()





def get_file_details(filepath, hash_algorithms=['sha256']):
  """
  <Purpose>
    To get file's length and hash information.  The hash is computed using the
    sha256 algorithm.  This function is used in the signerlib.py and updater.py
    modules.

  <Arguments>
    filepath:
      Absolute file path of a file.

    hash_algorithms:

  <Exceptions>
    tuf.FormatError: If hash of the file does not match HASHDICT_SCHEMA.

    tuf.Error: If 'filepath' does not exist. 

  <Returns>
    A tuple (length, hashes) describing 'filepath'.
  """
  
  # Making sure that the format of 'filepath' is a path string.
  # 'tuf.FormatError' is raised on incorrect format.
  tuf.formats.PATH_SCHEMA.check_match(filepath)
  tuf.formats.HASHALGORITHMS_SCHEMA.check_match(hash_algorithms)

  # The returned file hashes of 'filepath'.
  file_hashes = {}

  # Does the path exists?
  if not os.path.exists(filepath):
    raise tuf.Error('Path ' + repr(filepath) + ' doest not exist.')
  filepath = os.path.abspath(filepath)

  # Obtaining length of the file.
  file_length = os.path.getsize(filepath)

  # Obtaining hash of the file.
  for algorithm in hash_algorithms:
    digest_object = tuf.hash.digest_filename(filepath, algorithm)
    file_hashes.update({algorithm: digest_object.hexdigest()})

  # Performing a format check to ensure 'file_hash' corresponds HASHDICT_SCHEMA.
  # Raise 'tuf.FormatError' if there is a mismatch.
  tuf.formats.HASHDICT_SCHEMA.check_match(file_hashes)

  return file_length, file_hashes





def ensure_parent_dir(filename):
  """
  <Purpose>
    To ensure existence of the parent directory of 'filename'.  If the parent
    directory of 'name' does not exist, create it.

    Example: If 'filename' is '/a/b/c/d.txt', and only the directory '/a/b/'
    exists, then directory '/a/b/c/d/' will be created.

  <Arguments>
    filename:
      A path string.

  <Exceptions>
    tuf.FormatError: If 'filename' is improperly formatted.

  <Side Effects>
    A directory is created whenever the parent directory of 'filename' does not
    exist.

  <Return>
    None.
  """

  # Ensure 'filename' corresponds to 'PATH_SCHEMA'.
  # Raise 'tuf.FormatError' on a mismatch.
  tuf.formats.PATH_SCHEMA.check_match(filename)

  # Split 'filename' into head and tail, check if head exists.
  directory = os.path.split(filename)[0]

  if directory and not os.path.exists(directory):
    # mode = 'rwx------'. 448 (decimal) is 700 in octal.
    os.makedirs(directory, 448)





def file_in_confined_directories(filepath, confined_directories):
  """
  <Purpose>
    Check if the directory containing 'filepath' is in the list/tuple of
    'confined_directories'.

  <Arguments>
    filepath:
      A string representing the path of a file.  The following example path
      strings are viewed as files and not directories: 'a/b/c', 'a/b/c.txt'.

    confined_directories:
      A list, or a tuple, of directory strings.

  <Exceptions>
   tuf.FormatError: On incorrect format of the input.

  <Return>
    Boolean.  True, if path is either the empty string
    or in 'confined_paths'; False, otherwise.
  """

  # Do the arguments have the correct format?
  # Raise 'tuf.FormatError' if there is a mismatch.
  tuf.formats.RELPATH_SCHEMA.check_match(filepath)
  tuf.formats.RELPATHS_SCHEMA.check_match(confined_directories)

  for confined_directory in confined_directories:
    # The empty string (arbitrarily chosen) signifies the client is confined
    # to all directories and subdirectories.  No need to check 'filepath'.
    if confined_directory == '':
      return True

    # Normalized paths needed, to account for up-level references, etc.
    # TUF clients have the option of setting the list of directories in
    # 'confined_directories'.
    filepath = os.path.normpath(filepath)
    confined_directory = os.path.normpath(confined_directory)
    
    # A TUF client may restrict himself to specific directories on the
    # remote repository.  The list of paths in 'confined_path', not including
    # each path's subdirectories, are the only directories the client will
    # download targets from.
    if os.path.dirname(filepath) == confined_directory:
      return True

  return False






def find_delegated_role(roles, delegated_role):
  """
  <Purpose>
    Find the index, if any, of a role with a given name in a list of roles.

  <Arguments>
    roles:
      The list of roles, each of which must have a 'name' attribute.

    delegated_role:
      The name of the role to be found in the list of roles.

  <Exceptions>
    tuf.RepositoryError, if the list of roles has invalid data.

  <Side Effects>
    No known side effects.

  <Returns>
    The unique index, an interger, in the list of roles.  if 'delegated_role'
    does not exist, 'None' is returned.
  """

  # Do the arguments have the correct format?
  # Ensure the arguments have the appropriate number of objects and object
  # types, and that all dict keys are properly named.
  # Raise 'tuf.FormatError' if any are improperly formatted.
  tuf.formats.ROLELIST_SCHEMA.check_match(roles)
  tuf.formats.ROLENAME_SCHEMA.check_match(delegated_role)

  # The index of a role, if any, with the same name.
  role_index = None

  for index in six.moves.xrange(len(roles)):
    role = roles[index]
    name = role.get('name')
    
    # This role has no name.
    if name is None:
      no_name_message = 'Role with no name.'
      raise tuf.RepositoryError(no_name_message)
    
    # Does this role have the same name?
    else:
      # This role has the same name, and...
      if name == delegated_role:
        # ...it is the only known role with the same name.
        if role_index is None:
          role_index = index
        
        # ...there are at least two roles with the same name.
        else:
          duplicate_role_message = 'Duplicate role (' + str(delegated_role) + ').'
          raise tuf.RepositoryError(duplicate_role_message)
      
      # This role has a different name.
      else:
        logger.debug('Skipping delegated role: ' + repr(delegated_role))

  return role_index






def ensure_all_targets_allowed(rolename, list_of_targets, parent_delegations):
  """
  <Purpose>
    Ensure that the list of targets specified by 'rolename' are allowed; this is
    determined by inspecting the 'delegations' field of the parent role
    of 'rolename'.  If a target specified by 'rolename' is not found in the 
    delegations field of 'metadata_object_of_parent', raise an exception.  The
    top-level role 'targets' is allowed to list any target file, so this
    function does not raise an exception if 'rolename' is 'targets'.
 
    Targets allowed are either exlicitly listed under the 'paths' field, or
    implicitly exist under a subdirectory of a parent directory listed
    under 'paths'.  A parent role may delegate trust to all files under a 
    particular directory, including files in subdirectories, by simply
    listing the directory (e.g., '/packages/source/Django/', the equivalent
    of '/packages/source/Django/*').  Targets listed in hashed bins are
    also validated (i.e., its calculated path hash prefix must be delegated
    by the parent role).

    TODO: Should the TUF spec restrict the repository to one particular
    algorithm when calcutating path hash prefixes (currently restricted to 
    SHA256)?  Should we allow the repository to specify in the role dictionary
    the algorithm used for these generated hashed paths?

  <Arguments>
    rolename:
      The name of the role whose targets must be verified. This is a
      role name and should not end in '.json'.  Examples: 'root', 'targets',
      'targets/linux/x86'.

    list_of_targets:
      The targets of 'rolename', as listed in targets field of the 'rolename'
      metadata.  'list_of_targets' are target paths relative to the targets
      directory of the repository.  The delegations of the parent role are
      checked to verify that the targets of 'list_of_targets' are valid.
    
    parent_delegations:
      The parent delegations of 'rolename'.  The metadata object stores
      the allowed paths and path hash prefixes of child delegations in its 
      'delegations' attribute.

  <Exceptions>
    tuf.FormatError:
      If any of the arguments are improperly formatted.

    tuf.ForbiddenTargetError:
      If the targets of 'metadata_role' are not allowed according to
      the parent's metadata file.  The 'paths' and 'path_hash_prefixes'
      attributes are verified.

    tuf.RepositoryError:
      If the parent of 'rolename' has not made a delegation to 'rolename'.

  <Side Effects>
    None.

  <Returns>
    None.
  """
  
  # Do the arguments have the correct format?
  # Ensure the arguments have the appropriate number of objects and object
  # types, and that all dict keys are properly named.
  # Raise 'tuf.FormatError' if any are improperly formatted.
  tuf.formats.ROLENAME_SCHEMA.check_match(rolename)
  tuf.formats.RELPATHS_SCHEMA.check_match(list_of_targets)
  tuf.formats.DELEGATIONS_SCHEMA.check_match(parent_delegations)
  
  # Return if 'rolename' is 'targets'.  'targets' is not a delegated role.  Any
  # target file listed in 'targets' is allowed.
  if rolename == 'targets':
    return
  
  # The allowed targets of delegated roles are stored in the parent's metadata
  # file.  Iterate 'list_of_targets' and confirm they are trusted, or their root
  # parent directory exists in the role delegated paths, or path hash prefixes,
  # of the parent role.  First, locate 'rolename' in the 'roles' attribute of
  # 'parent_delegations'.
  roles = parent_delegations['roles']
  role_index = find_delegated_role(roles, rolename)

  # Ensure the delegated role exists prior to extracting trusted paths from
  # the parent's 'paths', or trusted path hash prefixes from the parent's
  # 'path_hash_prefixes'.
  if role_index is not None:
    role = roles[role_index] 
    allowed_child_paths = role.get('paths')
    allowed_child_path_hash_prefixes = role.get('path_hash_prefixes')
    actual_child_targets = list_of_targets 

    if allowed_child_path_hash_prefixes is not None:
      consistent = paths_are_consistent_with_hash_prefixes
      
      # 'actual_child_tarets' (i.e., 'list_of_targets') should have lenth
      # greater than zero due to the tuf.format check above.
      if not consistent(actual_child_targets,
                        allowed_child_path_hash_prefixes):
        message =  repr(rolename) + ' specifies a target that does not' + \
          ' have a path hash prefix listed in its parent role.'
        raise tuf.ForbiddenTargetError(message)
    
    elif allowed_child_paths is not None: 
      # Check that each delegated target is either explicitly listed or a parent
      # directory is found under role['paths'], otherwise raise an exception.
      # If the parent role explicitly lists target file paths in 'paths',
      # this loop will run in O(n^2), the worst-case.  The repository
      # maintainer will likely delegate entire directories, and opt for
      # explicit file paths if the targets in a directory are delegated to 
      # different roles/developers.
      for child_target in actual_child_targets:
        for allowed_child_path in allowed_child_paths:
          prefix = os.path.commonprefix([child_target, allowed_child_path])
          if prefix == allowed_child_path:
            break
        
        else: 
          raise tuf.ForbiddenTargetError('Role '+repr(rolename)+' specifies'+\
                                         ' target '+repr(child_target)+','+\
                                         ' which is not an allowed path'+\
                                         ' according to the delegations set'+\
                                         ' by its parent role.')

    else:
      # 'role' should have been validated when it was downloaded.
      # The 'paths' or 'path_hash_prefixes' attributes should not be missing,
      # so raise an error in case this clause is reached.
      raise tuf.FormatError(repr(role) + ' did not contain one of ' +\
                            'the required fields ("paths" or ' +\
                            '"path_hash_prefixes").')

  # Raise an exception if the parent has not delegated to the specified
  # 'rolename' child role.
  else:
    raise tuf.RepositoryError('The parent role has not delegated to '+\
                              repr(rolename)+'.')





def paths_are_consistent_with_hash_prefixes(paths, path_hash_prefixes):
  """
  <Purpose>
    Determine whether a list of paths are consistent with their alleged
    path hash prefixes. By default, the SHA256 hash function is used.

  <Arguments>
    paths:
      A list of paths for which their hashes will be checked.

    path_hash_prefixes:
      The list of path hash prefixes with which to check the list of paths.

  <Exceptions>
    tuf.FormatError:
      If the arguments are improperly formatted.

  <Side Effects>
    No known side effects.

  <Returns>
    A Boolean indicating whether or not the paths are consistent with the
    hash prefix.
  """
  
  # Do the arguments have the correct format?
  # Ensure the arguments have the appropriate number of objects and object
  # types, and that all dict keys are properly named.
  # Raise 'tuf.FormatError' if any are improperly formatted.
  tuf.formats.RELPATHS_SCHEMA.check_match(paths)
  tuf.formats.PATH_HASH_PREFIXES_SCHEMA.check_match(path_hash_prefixes)

  # Assume that 'paths' and 'path_hash_prefixes' are inconsistent until
  # proven otherwise.
  consistent = False

  # The format checks above ensure the 'paths' and 'path_hash_prefix' lists
  # have lengths greater than zero.
  for path in paths:
    path_hash = get_target_hash(path)
    
    # Assume that every path is inconsistent until proven otherwise.
    consistent = False

    for path_hash_prefix in path_hash_prefixes:
      if path_hash.startswith(path_hash_prefix):
        consistent = True
        break

    # This path has no matching path_hash_prefix. Stop looking further.
    if not consistent:
      break

  return consistent





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
  
  # Does 'target_filepath' have the correct format?
  # Ensure the arguments have the appropriate number of objects and object
  # types, and that all dict keys are properly named.
  # Raise 'tuf.FormatError' if there is a mismatch.
  tuf.formats.RELPATH_SCHEMA.check_match(target_filepath)

  # Calculate the hash of the filepath to determine which bin to find the 
  # target.  The client currently assumes the repository uses
  # 'HASH_FUNCTION' to generate hashes and 'utf-8'.
  digest_object = tuf.hash.digest(HASH_FUNCTION)
  encoded_target_filepath = target_filepath.encode('utf-8')
  digest_object.update(encoded_target_filepath)
  target_filepath_hash = digest_object.hexdigest() 

  return target_filepath_hash





_json_module = None

def import_json():
  """
  <Purpose>
    Tries to import json module. We used to fall back to the simplejson module,
    but we have dropped support for that module. We are keeping this interface
    intact for backwards compatibility.

  <Arguments>
    None.

  <Exceptions>
    ImportError: on failure to import the json module.

  <Side Effects>
    None.

  <Return>
    json module
  """

  global _json_module

  if _json_module is not None:
    return _json_module
  
  else:
    try:
      module = __import__('json')
   
    # The 'json' module is available in Python > 2.6, and thus this exception
    # should not occur in all supported Python installations (> 2.6) of TUF.
    except ImportError: #pragma: no cover
      raise ImportError('Could not import the json module')
    
    else:
      _json_module = module
      return module

json = import_json()



def load_json_string(data):
  """
  <Purpose>
    Deserialize 'data' (JSON string) to a Python object.

  <Arguments>
    data:
      A JSON string.
  
  <Exceptions>
    tuf.Error, if 'data' cannot be deserialized to a Python object.

  <Side Effects>
    None.

  <Returns>
    Deserialized object.  For example, a dictionary.
  """

  deserialized_object = None
  
  try:
    deserialized_object = json.loads(data)
 
  except TypeError:
    message = 'Invalid JSON string: ' + repr(data)
    raise tuf.Error(message)
  
  except ValueError:
    message = 'Cannot deserialize to a Python object: ' + repr(data)
    raise tuf.Error(message)
  
  else:
    return deserialized_object    



def load_json_file(filepath):
  """
  <Purpose>
    Deserialize a JSON object from a file containing the object.

  <Arguments>
    filepath:
      Absolute path of JSON file.

  <Exceptions>
    tuf.FormatError: If 'filepath' is improperly formatted.

    tuf.Error: If 'filepath' cannot be deserialized to a Python object.

    IOError in case of runtime IO exceptions.

  <Side Effects>
    None.

  <Return>
    Deserialized object.  For example, a dictionary.
  """

  # Making sure that the format of 'filepath' is a path string.
  # tuf.FormatError is raised on incorrect format.
  tuf.formats.PATH_SCHEMA.check_match(filepath)

  deserialized_object = None

  # The file is mostly likely gzipped.
  if filepath.endswith('.gz'):
    logger.debug('gzip.open(' + str(filepath) + ')')
    fileobject = six.StringIO(gzip.open(filepath).read().decode('utf-8'))
  
  else:
    logger.debug('open(' + str(filepath) + ')')
    fileobject = open(filepath)

  try:
    deserialized_object = json.load(fileobject)
  
  except (ValueError, TypeError) as e:
    message = 'Cannot deserialize to a Python object: ' + repr(filepath)
    raise tuf.Error(message)
  
  else:
    fileobject.close() 
    return deserialized_object
  
  finally:
    fileobject.close()



def digests_are_equal(digest1, digest2):
  """
  <Purpose>
    While protecting against timing attacks, compare the hexadecimal arguments
    and determine if they are equal.

  <Arguments>
    digest1:
      The first hexadecimal string value to compare.

    digest2:
      The second hexadecimal string value to compare.

  <Exceptions>
    tuf.FormatError: If the arguments are improperly formatted.

  <Side Effects>
    None.

  <Return>
    Return True if 'digest1' is equal to 'digest2', False otherwise.
  """
  
  # Ensure the arguments have the appropriate number of objects and object
  # types, and that all dict keys are properly named.
  # Raise 'tuf.FormatError' if there is a mismatch.
  tuf.formats.HEX_SCHEMA.check_match(digest1)
  tuf.formats.HEX_SCHEMA.check_match(digest2)

  if len(digest1) != len(digest2):
    return False

  are_equal = True
  
  for element in range(len(digest1)):
    if digest1[element] != digest2[element]:
      are_equal = False

  return are_equal
