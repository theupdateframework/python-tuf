"""
<Program Name>
  util.py

<Author>
  Konstantin Andrianov
  Derived from original util.py written by Geremy Condra.

<Started>
  March 24, 2012

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Provides utility services.  This module supplies utility functions such as:
  get_file_details that computes length and hash of a file, import_json that
  tries to import a working json module, load_json functions, TempFile class -
  generates a file-like object temporary starage, etc.

"""


import gzip
import os
import shutil
import sys
import re
import tempfile
import logging

import tuf.formats
import tuf.hash
import tuf.log
import tuf.conf


# See 'log.py' to learn how logging is handled in TUF
logger = logging.getLogger('tuf.util')





class TempFile(object):
  """
  <Purpose>
    A high-level temporary file that cleans itself up or can be manually
    cleaned up. This isn't a complete file-like object. The file functions
    that are supported make additional common-case safe assumptions. There
    are additional functions that aren't part of file-like objects.  TempFile
    is used in download.py module.

  """

  def __init__(self, prefix='tmp'):
    """
    <Purpose>
      Initializes TempFile.

    <Arguments>
      prefix:
        A string argument to be used with tempfile.TemporaryFile function.

    <Exceptions>
      OSError on failure to load temp dir.
      tuf.Error

    <Return>
      None.

    """

    self._compression = None

    # If compression is set then the original file is saved in 'self._orig_file'.
    self._orig_file = None

    temp_dir = tuf.conf.temporary_directory
    if  temp_dir is not None:
      # We use TemporaryFile for the auto-delete aspects of it to ensure
      # we don't leave behind temp files.
      try:
        self.temporary_file = tempfile.TemporaryFile(prefix=prefix, dir=temp_dir)
      except OSError, err:
        logger.error('Temp file in '+temp_dir+' failed: '+err)
        logger.error('Will attempt to use system default temp dir.')

    try:
      self.temporary_file = tempfile.TemporaryFile(prefix=prefix)
    except OSError, err:
      logger.critical('Temp file in '+temp_dir+'failed: '+err)
      raise tuf.Error(err)


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
      size: Number of bytes to be read.

    <Exceptions>
      None

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
      tuf.Error

    <Side Effects>
      'self._orig_file' is used to store the original data of 'temporary_file'.

    <Return>
      None.

    """

    if self._orig_file is not None:
      raise tuf.Error('Can only set compression on a TempFile once.')

    if compression != 'gzip':
      raise tuf.Error('Only gzip compression is supported.')
    self.seek(0)
    self._compression = compression
    self._orig_file = self.temporary_file
    self.temporary_file = gzip.GzipFile(fileobj=self.temporary_file, mode='rb')


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




# TODO: Change the argument name to something like 'file_path'
# TODO: Do something with 'repository_directory'
# TODO: Make sure that you are able to run from anywhere on the system
# TODO: not only from the repository directory.
def get_file_details(file_path, repository_directory=None):
  """
  <Purpose>
    To get file's length and hash information.  The hash is computed using
    sha256 algorithm.  This function is used in signerlib.py and updater.py
    modules.

  <Arguments>
    file_path:
      Absolute file path.  Otherwise, 'file_path' has to be relative to the
      current working directory.
      TODO: Include repository directory to

  <Exceptions>
    tuf.FormatError: If hash of the file does not match HASHDICT_SCHEMA.
    TODO: check non-existing path wich produces OSError.

  <Returns>
    A tuple (length, hashes) describing file_path.

  """
  # Making sure that the format of 'file_path' is a path string.
  # tuf.FormatError is raised on incorrect format.
  tuf.formats.RELPATH_SCHEMA.check_match(file_path)

  # Does the path exists?
  if not os.path.exists(file_path):
    raise tuf.Error, 'Path '+repr(file_path)+' doest not exist.'
  file_path = os.path.abspath(file_path)

  # Obtaining length of the file.
  file_length = os.path.getsize(file_path)

  # Obtaining hash of the file.
  digest_object = tuf.hash.digest_filename(file_path, algorithm='sha256')
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

  <Arguments>
    filename:
      A path string.

  <Side Effects>
    A directory is created whenever parent directory of 'filename' does not exist.

  <Return>
    None.

  """

  # Ensure 'name' corresponds to 'RELPATH_SCHEMA'.
  # Raise 'tuf.FormatError' on a mismatch.
  tuf.formats.RELPATH_SCHEMA.check_match(filename)

  # Split 'filename' into head and tail, check if head exists.
  directory = os.path.split(filename)[0]
  if directory and not os.path.exists(directory):
    os.makedirs(directory, 0700)





def path_in_confined_paths(test_path, confined_paths):
  """
  <Purpose>
    Check whether 'test_path' is in the list/tuple of 'confined_paths'.

  <Arguments>
    test_path:
      A string representing a path.

    confined_paths:
      A list or a tuple of path strings.

  <Exceptions>
   tuf.TypeError, if the arguments are improperly typed.

  <Return>
    Boolean.  True, if path is either the empty string
    or in 'confined_paths'; False, otherwise.

  """

  # Do the arguments are the correct format?
  # Raise 'tuf.FormatError' if there is a mismatch.
  tuf.formats.PATH_SCHEMA.check_match(test_path)
  tuf.formats.PATHS_SCHEMA.check_match(confined_paths)

  if not isinstance(test_path, basestring):
    raise TypeError('The test path must be a string')
  if not isinstance(confined_paths, (list, tuple)):
    raise TypeError('The confined paths must be a list or a tuple')

  for pattern in confined_paths:
    # Ignore slashes at the beginning.
    pattern = pattern.lstrip('/')

    # An empty string signifies the client should be confined to all
    # directories and subdirectories.  No need to check 'test_path'.
    if pattern == '':
      return True

    # Get the directory name (i.e., strip off the file_path+extension)
    directory_name = os.path.dirname(test_path)

    if directory_name == os.path.dirname(pattern):
      return True

  return False





_json_module = None

def import_json():
  """
  <Purpose>
    Tries to import json module.

  <Arguments>
    None.

  <Exceptions>
    ImportError on failure to import json or simplejson modules.
    NameError

  <Return>
    json/simplejson module

  """

  global _json_module
  if _json_module is not None:
    return _json_module

  for name in [ 'json', 'simplejson' ]:
    try:
      module = __import__(name)
    except ImportError:
      continue
    if not hasattr(module, 'dumps'):
      # Some versions of Ubuntu have a module called 'json' that is
      # not a recognizable simplejson module.
      if name == 'json':
        logger.warn('Your operating system has a nonfunctional json '
                    'module.  That is going to break any programs that '
                    'use the real json module in Python 2.6.  Trying '
                    'simplejson instead.')
      continue

    # Some old versions of simplejson escape / as \/ in a misguided and
    # inadequate attempt to fix XSS attacks.  Make them not do that.  This
    # code is not guaranteed to work on all broken versions of simplejson:
    # it replaces an entry in the internal character-replacement
    # dictionary so that '/' is translated to itself rather than to \/.
    # We also need to make sure that ensure_ascii is False, so that we
    # do not call the C-optimized string encoder in these broken versions,
    # which we can't fix easily.  Both parts are a kludge.
    try:
      escape_dct = module.encoder.ESCAPE_DCT
    except NameError:
      pass
    else:
      if escape_dct.has_key('/'):
        escape_dct['/'] = '/'
        save_dumps = module.dumps
        save_dump = module.dump
        def dumps(*k, **v):
          v['ensure_ascii'] = False
          return save_dumps(*k, **v)
        def dump(*k, **v):
          v['ensure_ascii'] = False
          return save_dump(*k, **v)
        module.dump = dump
        module.dumps = dumps
        logger.warn('Your operating system has an old broken '
                    'simplejson module.  I tried to fix it for you.')

    _json_module = module
    return module

  raise ImportError('Could not import a working json module')


json = import_json()


def load_json_string(data):
  """
  <Purpose>
    To deserialize a JSON object from a string 'data'.

  <Arguments>
    data:
      A JSON string.

  <Return>
    Deserialized object.  For example a dictionary.

  """

  return json.loads(data)


def load_json_file(filename):
  """
  <Purpose>
    To deserialize a JSON object from a file containing the object.

  <Arguments>
    data:
      A JSON string.

  <Return>
    Deserialized object.  For example a dictionary.

  """

  fp = open(filename)
  try:
    return json.load(fp)
  finally:
    fp.close()

