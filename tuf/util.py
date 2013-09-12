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
    except OSError, err:
      logger.critical('Temp file in '+temp_dir+'failed: '+repr(err))
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
    if  temp_dir is not None and isinstance(temp_dir, str):
      try:
        self.temporary_file = tempfile.NamedTemporaryFile(prefix=prefix,
                                                          dir=temp_dir)
      except OSError, err:
        logger.error('Temp file in '+temp_dir+' failed: '+repr(err))
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

                            meta.txt.gz
                               |...[download]
                        temporary_file (containing meta.txt.gz)
                        /             \
               temporary_file          _orig_file
          containing meta.txt          containing meta.txt.gz
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
      self.temporary_file = gzip.GzipFile(fileobj=self.temporary_file,
                                          mode='rb')
    except Exception, exception:
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





def get_file_details(filepath):
  """
  <Purpose>
    To get file's length and hash information.  The hash is computed using the
    sha256 algorithm.  This function is used in the signerlib.py and updater.py
    modules.

  <Arguments>
    filepath:
      Absolute file path of a file.

  <Exceptions>
    tuf.FormatError: If hash of the file does not match HASHDICT_SCHEMA.

    tuf.Error: If 'filepath' does not exist. 

  <Returns>
    A tuple (length, hashes) describing 'filepath'.

  """
  # Making sure that the format of 'filepath' is a path string.
  # 'tuf.FormatError' is raised on incorrect format.
  tuf.formats.PATH_SCHEMA.check_match(filepath)

  # Does the path exists?
  if not os.path.exists(filepath):
    raise tuf.Error('Path '+repr(filepath)+' doest not exist.')
  filepath = os.path.abspath(filepath)

  # Obtaining length of the file.
  file_length = os.path.getsize(filepath)

  # Obtaining hash of the file.
  digest_object = tuf.hash.digest_filename(filepath, algorithm='sha256')
  file_hash = {'sha256' : digest_object.hexdigest()}

  # Performing a format check to ensure 'file_hash' corresponds HASHDICT_SCHEMA.
  # Raise 'tuf.FormatError' if there is a mismatch.
  tuf.formats.HASHDICT_SCHEMA.check_match(file_hash)

  return file_length, file_hash





def ensure_parent_dir(filename):
  """
  <Purpose>
    To ensure existence of the parent directory of 'filename'.  If the parent
    directory of 'name' does not exist, create it.

    Ex: If 'filename' is '/a/b/c/d.txt', and only the directory '/a/b/'
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
    os.makedirs(directory, 0700)





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
    except ImportError:
      raise ImportError('Could not import the json module')
    else:
      _json_module = module
      return module

json = import_json()



def load_json_string(data):
  """
  <Purpose>
    Deserialize a JSON object from a string 'data'.

  <Arguments>
    data:
      A JSON string.
  
  <Exceptions>
    None.

  <Side Effects>
    None.

  <Returns>
    Deserialized object.  For example a dictionary.

  """

  return json.loads(data)



def load_json_file(filepath):
  """
  <Purpose>
    Deserialize a JSON object from a file containing the object.

  <Arguments>
    data:
      Absolute path of JSON file.

  <Exceptions>
    tuf.FormatError: If 'filepath' is improperly formatted.

    IOError in case of runtime IO exceptions.

  <Side Effects>
    None.

  <Return>
    Deserialized object.  For example, a dictionary.

  """

  # Making sure that the format of 'filepath' is a path string.
  # tuf.FormatError is raised on incorrect format.
  tuf.formats.PATH_SCHEMA.check_match(filepath)

  # The file is mostly likely gzipped.
  if filepath.endswith('.gz'):
    logger.debug('gzip.open('+str(filepath)+')')
    fileobject = gzip.open(filepath)
  else:
    logger.debug('open('+str(filepath)+')')
    fileobject = open(filepath)

  try:
    return json.load(fileobject)
  finally:
    fileobject.close()


