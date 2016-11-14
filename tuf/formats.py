#!/usr/bin/env python

"""
<Program Name>
  formats.py

<Author>
  Geremy Condra
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  Refactored April 30, 2012. -vladimir.v.diaz

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  A central location for all format-related checking of TUF objects.
  Some crypto-related formats may also be defined in tuf.ssl_commons.
  Note: 'formats.py' depends heavily on 'schema.py', so the 'schema.py'
  module should be read and understood before tackling this module.

  'formats.py' can be broken down into three sections.  (1) Schemas and object
  matching.  (2) Classes that represent Role Metadata and help produce correctly
  formatted files.  (3) Functions that help produce or verify TUF objects.

  The first section deals with schemas and object matching based on format.
  There are two ways of checking the format of objects.  The first method
  raises a 'tuf.ssl_commons.exceptions.FormatError' exception if the match
  fails and the other returns a Boolean result.

  tuf.formats.<SCHEMA>.check_match(object)
  tuf.formats.<SCHEMA>.matches(object)

  Example:

  rsa_key = {'keytype': 'rsa'
             'keyid': 34892fc465ac76bc3232fab 
             'keyval': {'public': 'public_key',
                        'private': 'private_key'}

  tuf.ssl_commons.formats.RSAKEY_SCHEMA.check_match(rsa_key)
  tuf.ssl_commons.formats.RSAKEY_SCHEMA.matches(rsa_key)

  In this example, if a dict key or dict value is missing or incorrect,
  the match fails.  There are numerous variations of object checking
  provided by 'formats.py' and 'schema.py'.

  The second section deals with the role metadata classes.  There are
  multiple top-level roles, each with differing metadata formats.
  Example:
  
  root_object = tuf.formats.RootFile.from_metadata(root_metadata_file)
  targets_metadata = tuf.formats.TargetsFile.make_metadata(...)

  The input and output of these classes are checked against their respective
  schema to ensure correctly formatted metadata.

  The last section contains miscellaneous functions related to the format of
  TUF objects.
  Example: 
  
  signable_object = make_signable(unsigned_object)
"""

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import binascii
import calendar
import re
import string
import datetime
import time

import tuf
import tuf.ssl_crypto.formats
import tuf.ssl_commons.schema as SCHEMA

import six

# A dict holding the version or file information for a particular metadata
# role.  The dict keys hold the relative file paths, and the dict values the
# corresponding version numbers and/or file information.
FILEINFODICT_SCHEMA = SCHEMA.DictOf(
  key_schema = tuf.ssl_crypto.formats.RELPATH_SCHEMA,
  value_schema = SCHEMA.OneOf([tuf.ssl_crypto.formats.VERSIONINFO_SCHEMA,
                              tuf.ssl_crypto.formats.FILEINFO_SCHEMA]))

# Role object in {'keyids': [keydids..], 'name': 'ABC', 'threshold': 1,
# 'paths':[filepaths..]} format.
ROLE_SCHEMA = SCHEMA.Object(
  object_name = 'ROLE_SCHEMA',
  name = SCHEMA.Optional(tuf.ssl_crypto.formats.ROLENAME_SCHEMA),
  keyids = tuf.ssl_crypto.formats.KEYIDS_SCHEMA,
  threshold = tuf.ssl_crypto.formats.THRESHOLD_SCHEMA,
  terminating = SCHEMA.Optional(tuf.ssl_crypto.formats.BOOLEAN_SCHEMA),
  paths = SCHEMA.Optional(tuf.ssl_crypto.formats.RELPATHS_SCHEMA),
  path_hash_prefixes = SCHEMA.Optional(tuf.ssl_crypto.formats.PATH_HASH_PREFIXES_SCHEMA))

# A dictionary of ROLEDICT, where dictionary keys can be repository names, and
# dictionary values containing information for each role available on the
# repository (corresponding to the repository belonging to named repository in
# the dictionary key)
ROLEDICTDB_SCHEMA = SCHEMA.DictOf(
  key_schema = tuf.ssl_crypto.formats.NAME_SCHEMA,
  value_schema = tuf.ssl_crypto.formats.ROLEDICT_SCHEMA)

# Command argument list, as used by the CLI tool.
# Example: {'keytype': ed25519, 'expires': 365,}
COMMAND_SCHEMA = SCHEMA.DictOf(
  key_schema = tuf.ssl_crypto.formats.NAME_SCHEMA,
  value_schema = SCHEMA.Any()) 

# Snapshot role: indicates the latest versions of all metadata (except
# timestamp).
SNAPSHOT_SCHEMA = SCHEMA.Object(
  object_name = 'SNAPSHOT_SCHEMA',
  _type = SCHEMA.String('Snapshot'),
  version = tuf.ssl_crypto.formats.METADATAVERSION_SCHEMA,
  expires = tuf.ssl_crypto.formats.ISO8601_DATETIME_SCHEMA,
  meta = FILEINFODICT_SCHEMA)

# Timestamp role: indicates the latest version of the snapshot file.
TIMESTAMP_SCHEMA = SCHEMA.Object(
  object_name = 'TIMESTAMP_SCHEMA',
  _type = SCHEMA.String('Timestamp'),
  version = tuf.ssl_crypto.formats.METADATAVERSION_SCHEMA,
  expires = tuf.ssl_crypto.formats.ISO8601_DATETIME_SCHEMA,
  meta = tuf.ssl_crypto.formats.FILEDICT_SCHEMA)



class MetaFile(object):
  """
  <Purpose>
    Base class for all metadata file classes.
    Classes representing metadata files such as RootFile
    and SnapshotFile all inherit from MetaFile.  The
    __eq__, __ne__, perform 'equal' and 'not equal' comparisons
    between Metadata File objects.
  """

  info = None

  def __eq__(self, other):
    return isinstance(other, MetaFile) and self.info == other.info
  
  __hash__ = None

  def __ne__(self, other):
    return not self.__eq__(other)


  def __getattr__(self, name):
    """
      Allow all metafile objects to have their interesting attributes
      referred to directly without the info dict. The info dict is just
      to be able to do the __eq__ comparison generically.
    """
   
    if name in self.info:
      return self.info[name]
    
    else:
      raise AttributeError(name)



class TimestampFile(MetaFile):
  def __init__(self, version, expires, filedict):
    self.info = {}
    self.info['version'] = version
    self.info['expires'] = expires
    self.info['meta'] = filedict


  @staticmethod
  def from_metadata(object):
    # Is 'object' a Timestamp metadata file?
    # Raise tuf.ssl_commons.exceptions.FormatError if not.
    TIMESTAMP_SCHEMA.check_match(object) 

    version = object['version']
    expires = object['expires']
    filedict = object['meta']
    
    return TimestampFile(version, expires, filedict)
    
    
  @staticmethod
  def make_metadata(version, expiration_date, filedict):
    result = {'_type' : 'Timestamp'}
    result['version'] = version 
    result['expires'] = expiration_date
    result['meta'] = filedict

    # Is 'result' a Timestamp metadata file?
    # Raise 'tuf.ssl_commons.exceptions.FormatError' if not.
    TIMESTAMP_SCHEMA.check_match(result)

    return result



class RootFile(MetaFile):
  def __init__(self, version, expires, keys, roles, consistent_snapshot,
               compression_algorithms):
    self.info = {}
    self.info['version'] = version
    self.info['expires'] = expires
    self.info['keys'] = keys
    self.info['roles'] = roles
    self.info['consistent_snapshot'] = consistent_snapshot
    self.info['compression_algorithms'] = compression_algorithms


  @staticmethod
  def from_metadata(object):
    # Is 'object' a Root metadata file?
    # Raise 'tuf.ssl_commons.exceptions.FormatError' if not.
    tuf.ssl_crypto.formats.ROOT_SCHEMA.check_match(object) 
    
    version = object['version']
    expires = object['expires']
    keys = object['keys']
    roles = object['roles']
    consistent_snapshot = object['consistent_snapshot']
    compression_algorithms = object['compression_algorithms']
    
    return RootFile(version, expires, keys, roles, consistent_snapshot,
                    compression_algorithms)


  @staticmethod
  def make_metadata(version, expiration_date, keydict, roledict,
                    consistent_snapshot, compression_algorithms):
    result = {'_type' : 'Root'}
    result['version'] = version
    result['expires'] = expiration_date
    result['keys'] = keydict
    result['roles'] = roledict
    result['consistent_snapshot'] = consistent_snapshot
    result['compression_algorithms'] = compression_algorithms
    
    # Is 'result' a Root metadata file?
    # Raise 'tuf.ssl_commons.exceptions.FormatError' if not.
    tuf.ssl_crypto.formats.ROOT_SCHEMA.check_match(result)
    
    return result




class SnapshotFile(MetaFile):
  def __init__(self, version, expires, versiondict):
    self.info = {}
    self.info['version'] = version
    self.info['expires'] = expires
    self.info['meta'] = versiondict


  @staticmethod
  def from_metadata(object):
    # Is 'object' a Snapshot metadata file?
    # Raise 'tuf.ssl_commons.exceptions.FormatError' if not.
    SNAPSHOT_SCHEMA.check_match(object)
    
    version = object['version']
    expires = object['expires']
    versiondict = object['meta']
    
    return SnapshotFile(version, expires, versiondict)


  @staticmethod
  def make_metadata(version, expiration_date, versiondict):
    result = {'_type' : 'Snapshot'}
    result['version'] = version 
    result['expires'] = expiration_date
    result['meta'] = versiondict

    # Is 'result' a Snapshot metadata file?
    # Raise 'tuf.ssl_commons.exceptions.FormatError' if not.
    SNAPSHOT_SCHEMA.check_match(result)
    
    return result




class TargetsFile(MetaFile):
  def __init__(self, version, expires, filedict=None, delegations=None):
    if filedict is None:
      filedict = {}
    if delegations is None:
      delegations = {}
    self.info = {}
    self.info['version'] = version
    self.info['expires'] = expires
    self.info['targets'] = filedict
    self.info['delegations'] = delegations


  @staticmethod
  def from_metadata(object):
    # Is 'object' a Targets metadata file?
    # Raise tuf.ssl_commons.exceptions.FormatError if not.
    tuf.ssl_crypto.formats.TARGETS_SCHEMA.check_match(object)
    
    version = object['version']
    expires = object['expires']
    filedict = object.get('targets')
    delegations = object.get('delegations')
    
    return TargetsFile(version, expires, filedict, delegations)


  @staticmethod
  def make_metadata(version, expiration_date, filedict=None, delegations=None):
    if filedict is None and delegations is None:
      raise tuf.ssl_commons.exceptions.Error('We don\'t allow completely'
        ' empty targets metadata.')

    result = {'_type' : 'Targets'}
    result['version'] = version
    result['expires'] = expiration_date
    result['targets'] = {} 
    if filedict is not None:
      result['targets'] = filedict
    if delegations is not None:
      result['delegations'] = delegations

    # Is 'result' a Targets metadata file?
    # Raise 'tuf.ssl_commons.exceptions.FormatError' if not.
    tuf.ssl_crypto.formats.TARGETS_SCHEMA.check_match(result)
    
    return result



class MirrorsFile(MetaFile):
  def __init__(self, version, expires):
    self.info = {}
    self.info['version'] = version
    self.info['expires'] = expires


  @staticmethod
  def from_metadata(object):
    raise NotImplementedError


  @staticmethod
  def make_metadata():
    raise NotImplementedError



# A dict holding the recognized schemas for the top-level roles.
SCHEMAS_BY_TYPE = {
  'Root' : tuf.ssl_crypto.formats.ROOT_SCHEMA,
  'Targets' : tuf.ssl_crypto.formats.TARGETS_SCHEMA,
  'Snapshot' : SNAPSHOT_SCHEMA,
  'Timestamp' : TIMESTAMP_SCHEMA,
  'Mirrors' : tuf.ssl_crypto.formats.MIRRORLIST_SCHEMA}

# A dict holding the recognized class names for the top-level roles.
# That is, the role classes listed in this module (e.g., class TargetsFile()).
ROLE_CLASSES_BY_TYPE = {
  'Root' : RootFile,
  'Targets' : TargetsFile,
  'Snapshot' : SnapshotFile,
  'Timestamp' : TimestampFile,
  'Mirrors' : MirrorsFile}



def datetime_to_unix_timestamp(datetime_object):
  """
  <Purpose>
    Convert 'datetime_object' (in datetime.datetime()) format) to a Unix/POSIX
    timestamp.  For example, Python's time.time() returns a Unix timestamp, and
    includes the number of microseconds.  'datetime_object' is converted to UTC.

    >>> datetime_object = datetime.datetime(1985, 10, 26, 1, 22)
    >>> timestamp = datetime_to_unix_timestamp(datetime_object)
    >>> timestamp 
    499137720

  <Arguments>
    datetime_object:
      The datetime.datetime() object to convert to a Unix timestamp.

  <Exceptions>
    tuf.ssl_commons.exceptions.FormatError, if 'datetime_object' is not a
    datetime.datetime() object.

  <Side Effects>
    None.

  <Returns>
    A unix (posix) timestamp (e.g., 499137660).
  """
  
  # Is 'datetime_object' a datetime.datetime() object?
  # Raise 'tuf.ssl_commons.exceptions.FormatError' if not.
  if not isinstance(datetime_object, datetime.datetime):
    message = repr(datetime_object) + ' is not a datetime.datetime() object.'
    raise tuf.ssl_commons.exceptions.FormatError(message) 
   
  unix_timestamp = calendar.timegm(datetime_object.timetuple())
  
  return unix_timestamp





def unix_timestamp_to_datetime(unix_timestamp):
  """
  <Purpose>
    Convert 'unix_timestamp' (i.e., POSIX time, in UNIX_TIMESTAMP_SCHEMA format)
    to a datetime.datetime() object.  'unix_timestamp' is the number of seconds
    since the epoch (January 1, 1970.)
   
    >>> datetime_object = unix_timestamp_to_datetime(1445455680)
    >>> datetime_object 
    datetime.datetime(2015, 10, 21, 19, 28)

  <Arguments>
    unix_timestamp:
      An integer representing the time (e.g., 1445455680).  Conformant to
      'tuf.ssl_crypto.formats.UNIX_TIMESTAMP_SCHEMA'.

  <Exceptions>
    tuf.ssl_commons.exceptions.FormatError, if 'unix_timestamp' is improperly
    formatted.

  <Side Effects>
    None.

  <Returns>
    A datetime.datetime() object corresponding to 'unix_timestamp'.
  """
  
  # Is 'unix_timestamp' properly formatted?
  # Raise 'tuf.ssl_commons.exceptions.FormatError' if there is a mismatch.
  tuf.ssl_crypto.formats.UNIX_TIMESTAMP_SCHEMA.check_match(unix_timestamp)

  # Convert 'unix_timestamp' to a 'time.struct_time',  in UTC.  The Daylight
  # Savings Time (DST) flag is set to zero.  datetime.fromtimestamp() is not
  # used because it returns a local datetime.
  struct_time = time.gmtime(unix_timestamp)

  # Extract the (year, month, day, hour, minutes, seconds) arguments for the 
  # datetime object to be returned.
  datetime_object = datetime.datetime(*struct_time[:6])

  return datetime_object



def format_base64(data):
  """
  <Purpose>
    Return the base64 encoding of 'data' with whitespace and '=' signs omitted.

  <Arguments>
    data:
      Binary or buffer of data to convert.

  <Exceptions>
    tuf.ssl_commons.exceptions.FormatError, if the base64 encoding fails or the
    argument is invalid.

  <Side Effects>
    None.

  <Returns>
    A base64-encoded string.
  """
  
  try:
    return binascii.b2a_base64(data).decode('utf-8').rstrip('=\n ')
  
  except (TypeError, binascii.Error) as e:
    raise tuf.ssl_commons.exceptions.FormatError('Invalid base64'
      ' encoding: ' + str(e))




def parse_base64(base64_string):
  """
  <Purpose>
    Parse a base64 encoding with whitespace and '=' signs omitted.
  
  <Arguments>
    base64_string:
      A string holding a base64 value.

  <Exceptions>
    tuf.ssl_commons.exceptions.FormatError, if 'base64_string' cannot be parsed
    due to an invalid base64 encoding.

  <Side Effects>
    None.

  <Returns>
    A byte string representing the parsed based64 encoding of
    'base64_string'.
  """

  if not isinstance(base64_string, six.string_types):
    message = 'Invalid argument: '+repr(base64_string)
    raise tuf.ssl_commons.exceptions.FormatError(message)

  extra = len(base64_string) % 4
  if extra:
    padding = '=' * (4 - extra)
    base64_string = base64_string + padding

  try:
    return binascii.a2b_base64(base64_string.encode('utf-8'))
  
  except (TypeError, binascii.Error) as e:
    raise tuf.ssl_commons.exceptions.FormatError('Invalid base64'
      ' encoding: ' + str(e))



def make_fileinfo(length, hashes, version=None, custom=None):
  """
  <Purpose>
    Create a dictionary conformant to 'FILEINFO_SCHEMA'.
    This dict describes both metadata and target files.

  <Arguments>
    length:
      An integer representing the size of the file.

    hashes:
      A dict of hashes in 'HASHDICT_SCHEMA' format, which has the form:
       {'sha256': 123df8a9b12, 'sha512': 324324dfc121, ...}

    version:
      An optional integer representing the version of the file.

    custom:
      An optional object providing additional information about the file.

  <Exceptions>
    tuf.ssl_commons.exceptions.FormatError, if the 'FILEINFO_SCHEMA' to be
    returned does not have the correct format.

  <Side Effects>
    If any of the arguments are incorrectly formatted, the dict
    returned will be checked for formatting errors, and if found,
    will raise a 'tuf.ssl_commons.exceptions.FormatError' exception.

  <Returns>
    A dictionary conformant to 'FILEINFO_SCHEMA', representing the file
    information of a metadata or target file.
  """

  fileinfo = {'length' : length, 'hashes' : hashes}

  if version is not None:
    fileinfo['version'] = version 

  if custom is not None:
    fileinfo['custom'] = custom

  # Raise 'tuf.ssl_commons.exceptions.FormatError' if the check fails.
  tuf.ssl_crypto.formats.FILEINFO_SCHEMA.check_match(fileinfo)

  return fileinfo



def make_versioninfo(version_number):
  """
  <Purpose>
    Create a dictionary conformant to 'VERSIONINFO_SCHEMA'.  This dict
    describes both metadata and target files.

  <Arguments>
    version_number:
      An integer representing the version of a particular metadata role.
      The dictionary returned by this function is expected to be included
      in Snapshot metadata.

  <Exceptions>
    tuf.ssl_commons.exceptions.FormatError, if the dict to be returned does not
    have the correct format (i.e., VERSIONINFO_SCHEMA).

  <Side Effects>
    None.

  <Returns>
    A dictionary conformant to 'VERSIONINFO_SCHEMA', containing the version
    information of a metadata role.
  """

  versioninfo = {'version': version_number}

  # Raise 'tuf.ssl_commons.exceptions.FormatError' if 'versioninfo' is
  # improperly formatted.
  try: 
    tuf.ssl_crypto.formats.VERSIONINFO_SCHEMA.check_match(versioninfo)
  
  except:
    raise
  
  else:
    return versioninfo




def make_role_metadata(keyids, threshold, name=None, paths=None,
                       path_hash_prefixes=None):
  """
  <Purpose>
    Create a dictionary conforming to 'tuf.formats.ROLE_SCHEMA',
    representing the role with 'keyids', 'threshold', and 'paths'
    as field values.  'paths' is optional (i.e., used only by the
    'Target' role).

  <Arguments>
    keyids: a list of key ids.

    threshold:
      An integer denoting the number of required keys
      for the signing role.

    name:
      A string that is the name of this role.

    paths:
      The 'Target' role stores the paths of target files
      in its metadata file.  'paths' is a list of
      file paths.

    path_hash_prefixes:
      The 'Target' role stores the paths of target files in its metadata file.
      'path_hash_prefixes' is a succint way to describe a set of paths to
      target files.

  <Exceptions>
    tuf.ssl_commons.exceptions.FormatError, if the returned role meta is
    formatted incorrectly.

  <Side Effects>
    If any of the arguments do not have a proper format, a
    tuf.ssl_commons.exceptions.FormatError exception is raised when the
    'ROLE_SCHEMA' dict is created.

  <Returns>
    A properly formatted role meta dict, conforming to
    'ROLE_SCHEMA'.
  """

  role_meta = {}
  role_meta['keyids'] = keyids
  role_meta['threshold'] = threshold

  if name is not None:
    role_meta['name'] = name

  # According to the specification, the 'paths' and 'path_hash_prefixes' must
  # be mutually exclusive. However, at the time of writing we do not always
  # ensure that this is the case with the schema checks (see #83). Therefore,
  # we must do it for ourselves.

  if paths is not None and path_hash_prefixes is not None:
    raise tuf.ssl_commons.exceptions.FormatError('Both "paths" and'
      ' "path_hash_prefixes" are specified.')

  if path_hash_prefixes is not None:
    role_meta['path_hash_prefixes'] = path_hash_prefixes
  elif paths is not None:
    role_meta['paths'] = paths

  # Does 'role_meta' have the correct type?
  # This check ensures 'role_meta' conforms to tuf.formats.ROLE_SCHEMA.
  ROLE_SCHEMA.check_match(role_meta)

  return role_meta



def get_role_class(expected_rolename):
  """
  <Purpose>
    Return the role class corresponding to
    'expected_rolename'.  The role name returned
    by expected_meta_rolename() should be the name
    passed as an argument to this function.  If
    'expected_rolename' is 'Root', the class
    RootFile is returned.

  <Arguments>
    expected_rolename:
      The role name used to determine which role class
      to return.

  <Exceptions>
    tuf.ssl_commons.exceptions.FormatError, if 'expected_rolename' is not a
    supported role.

  <Side Effects>
    None.

  <Returns>
    The class corresponding to 'expected_rolename'.
    E.g., 'Snapshot' as an argument to this function causes
    SnapshotFile' to be returned. 
  """
 
  # Does 'expected_rolename' have the correct type?
  # This check ensures 'expected_rolename' conforms to
  # 'tuf.ssl_crypto.formats.NAME_SCHEMA'.
  # Raise 'tuf.ssl_commons.exceptions.FormatError' if there is a mismatch.
  tuf.ssl_crypto.formats.NAME_SCHEMA.check_match(expected_rolename)
  
  try:
    role_class = ROLE_CLASSES_BY_TYPE[expected_rolename]
  
  except KeyError:
    raise tuf.ssl_commons.exceptions.FormatError(repr(expected_rolename) + ' '
     'not supported.')
  
  else:
    return role_class



def expected_meta_rolename(meta_rolename):
  """
  <Purpose>
    Ensure 'meta_rolename' is properly formatted.
    'targets' is returned as 'Targets'.
    'targets role1' is returned as 'Targets Role1'.

    The words in the string (i.e., separated by whitespace)
    are capitalized.

  <Arguments>
    meta_rolename:
      A string representing the rolename.
      E.g., 'root', 'targets'.

  <Exceptions>
    tuf.ssl_commons.exceptions.FormatError, if 'meta_rolename' is improperly
    formatted.

  <Side Effects>
    None.

  <Returns>
    A string (e.g., 'Root', 'Targets').
  """
   
  # Does 'meta_rolename' have the correct type?
  # This check ensures 'meta_rolename' conforms to
  # 'tuf.ssl_crypto.formats.NAME_SCHEMA'.
  # Raise 'tuf.ssl_commons.exceptions.FormatError' if there is a mismatch.
  tuf.ssl_crypto.formats.NAME_SCHEMA.check_match(meta_rolename)
  
  return string.capwords(meta_rolename)



def check_signable_object_format(object):
  """
  <Purpose>
    Ensure 'object' is properly formatted, conformant to
    'tuf.ssl_crypto.formats.SIGNABLE_SCHEMA'.  Return the signing role on
    success.  Note: The 'signed' field of a 'SIGNABLE_SCHEMA' is checked
    against tuf.ssl_commons.schema.Any().  The 'signed' field, however, should
    actually hold one of the supported role schemas (e.g., 'ROOT_SCHEMA',
    'TARGETS_SCHEMA').  The role schemas all differ in their format, so this
    function determines exactly which schema is listed in the 'signed' field.

  <Arguments>
    object:
     The object compare against 'SIGNABLE.SCHEMA'. 

  <Exceptions>
    tuf.ssl_commons.exceptions.FormatError, if 'object' does not have the
    correct format.

  <Side Effects>
    None.

  <Returns>
    A string representing the signing role (e.g., 'root', 'targets').
    The role string is returned with characters all lower case.
  """
  
  # Does 'object' have the correct type?
  # This check ensures 'object' conforms to
  # 'tuf.ssl_crypto.formats.SIGNABLE_SCHEMA'.
  tuf.ssl_crypto.formats.SIGNABLE_SCHEMA.check_match(object)

  try:
    role_type = object['signed']['_type']
  
  except (KeyError, TypeError):
    raise tuf.ssl_commons.exceptions.FormatError('Untyped object')
  
  try:
    schema = SCHEMAS_BY_TYPE[role_type]
  
  except KeyError:
    raise tuf.ssl_commons.exceptions.FormatError('Unrecognized'
      ' type ' + repr(role_type))
  
  # 'tuf.ssl_commons.exceptions.FormatError' raised if 'object' does not have a
  # properly formatted role schema.
  schema.check_match(object['signed'])

  return role_type.lower()




if __name__ == '__main__':
  # The interactive sessions of the documentation strings can
  # be tested by running formats.py as a standalone module.
  # python -B formats.py
  import doctest
  doctest.testmod()
