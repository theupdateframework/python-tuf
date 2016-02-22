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
  Note: 'formats.py' depends heavily on 'schema.py', so the 'schema.py'
  module should be read and understood before tackling this module.

  'formats.py' can be broken down into three sections.  (1) Schemas and object
  matching.  (2) Classes that represent Role Metadata and help produce correctly
  formatted files.  (3) Functions that help produce or verify TUF objects.

  The first section deals with schemas and object matching based on format.
  There are two ways of checking the format of objects.  The first method
  raises a 'tuf.FormatError' exception if the match fails and the other
  returns a Boolean result.

  tuf.formats.<SCHEMA>.check_match(object)
  tuf.formats.<SCHEMA>.matches(object)

  Example:

  rsa_key = {'keytype': 'rsa'
             'keyid': 34892fc465ac76bc3232fab 
             'keyval': {'public': 'public_key',
                        'private': 'private_key'}

  tuf.formats.RSAKEY_SCHEMA.check_match(rsa_key)
  tuf.formats.RSAKEY_SCHEMA.matches(rsa_key)

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
import tuf.schema as SCHEMA

import six

# Note that in the schema definitions below, the 'SCHEMA.Object' types allow
# additional keys which are not defined. Thus, any additions to them will be
# easily backwards compatible with clients that are already deployed.

# A datetime in 'YYYY-MM-DDTHH:MM:SSZ' ISO 8601 format.  The "Z" zone designator
# for the zero UTC offset is always used (i.e., a numerical offset is not
# supported.)  Example: '2015-10-21T13:20:00Z'.  Note:  This is a simple format
# check, and an ISO8601 string should be fully verified when it is parsed.
ISO8601_DATETIME_SCHEMA = SCHEMA.RegularExpression(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z')

# A Unix/POSIX time format.  An integer representing the number of seconds
# since the epoch (January 1, 1970.)  Metadata uses this format for the
# 'expires' field.  Set 'hi' to the upper timestamp limit (year 2038), the max
# value of an int.
UNIX_TIMESTAMP_SCHEMA = SCHEMA.Integer(lo=0, hi=2147483647)

# A hexadecimal value in '23432df87ab..' format.
HASH_SCHEMA = SCHEMA.RegularExpression(r'[a-fA-F0-9]+')

# A dict in {'sha256': '23432df87ab..', 'sha512': '34324abc34df..', ...} format.
HASHDICT_SCHEMA = SCHEMA.DictOf(
  key_schema = SCHEMA.AnyString(),
  value_schema = HASH_SCHEMA)

# A hexadecimal value in '23432df87ab..' format.
HEX_SCHEMA = SCHEMA.RegularExpression(r'[a-fA-F0-9]+')

# A key identifier (e.g., a hexadecimal value identifying an RSA key).
KEYID_SCHEMA = HASH_SCHEMA

# A list of KEYID_SCHEMA.
KEYIDS_SCHEMA = SCHEMA.ListOf(KEYID_SCHEMA)

# The method used for a generated signature (e.g., 'RSASSA-PSS').
SIG_METHOD_SCHEMA = SCHEMA.AnyString()

# A relative file path (e.g., 'metadata/root/').
RELPATH_SCHEMA = SCHEMA.AnyString()
RELPATHS_SCHEMA = SCHEMA.ListOf(RELPATH_SCHEMA)

# An absolute path.
PATH_SCHEMA = SCHEMA.AnyString()
PATHS_SCHEMA = SCHEMA.ListOf(PATH_SCHEMA)

# Uniform Resource Locator identifier (e.g., 'https://www.updateframework.com/').
URL_SCHEMA = SCHEMA.AnyString()

# A dictionary holding version information.
VERSION_SCHEMA = SCHEMA.Object(
  object_name = 'VERSION_SCHEMA',
  major = SCHEMA.Integer(lo=0),
  minor = SCHEMA.Integer(lo=0),
  fix = SCHEMA.Integer(lo=0))

# An integer representing the numbered version of a metadata file.
# Must be 1, or greater.
METADATAVERSION_SCHEMA = SCHEMA.Integer(lo=0)

# An integer representing length.  Must be 0, or greater.
LENGTH_SCHEMA = SCHEMA.Integer(lo=0)

# An integer representing logger levels, such as logging.CRITICAL (=50).
# Must be between 0 and 50.
LOGLEVEL_SCHEMA = SCHEMA.Integer(lo=0, hi=50)

# A string representing a named object.
NAME_SCHEMA = SCHEMA.AnyString()
NAMES_SCHEMA = SCHEMA.ListOf(NAME_SCHEMA)

# A byte string representing data.
DATA_SCHEMA = SCHEMA.AnyBytes()

# Supported hash algorithms.
HASHALGORITHMS_SCHEMA = SCHEMA.ListOf(SCHEMA.OneOf(
  [SCHEMA.String('md5'), SCHEMA.String('sha1'),
   SCHEMA.String('sha224'), SCHEMA.String('sha256'),
   SCHEMA.String('sha384'), SCHEMA.String('sha512')]))

# The contents of an encrypted TUF key.  Encrypted TUF keys are saved to files
# in this format.
ENCRYPTEDKEY_SCHEMA = SCHEMA.AnyBytes()

# A value that is either True or False, on or off, etc.
BOOLEAN_SCHEMA = SCHEMA.Boolean()

# A role's threshold value (i.e., the minimum number
# of signatures required to sign a metadata file).
# Must be 1 and greater.
THRESHOLD_SCHEMA = SCHEMA.Integer(lo=1)

# A string representing a role's name. 
ROLENAME_SCHEMA = SCHEMA.AnyString()

# The minimum number of bits for an RSA key.  Must be 2048 bits, or greater
# (recommended by TUF). Crypto modules like 'pycrypto_keys.py' may set further
# restrictions on keys (e.g., the number of bits must be a multiple of 256).
# Recommended RSA key sizes:
# http://www.emc.com/emc-plus/rsa-labs/historical/twirl-and-rsa-key-size.htm#table1
RSAKEYBITS_SCHEMA = SCHEMA.Integer(lo=2048)

# The number of hashed bins, or the number of delegated roles.  See
# delegate_hashed_bins() in 'repository_tool.py' for an example.  Note:
# Tools may require further restrictions on the number of bins, such
# as requiring them to be a power of 2. 
NUMBINS_SCHEMA = SCHEMA.Integer(lo=1)

# A PyCrypto signature.
PYCRYPTOSIGNATURE_SCHEMA = SCHEMA.AnyBytes()

# A pyca-cryptography signature.
PYCACRYPTOSIGNATURE_SCHEMA = SCHEMA.AnyBytes()

# An RSA key in PEM format.
PEMRSA_SCHEMA = SCHEMA.AnyString()

# A string representing a password.
PASSWORD_SCHEMA = SCHEMA.AnyString()

# A list of passwords.
PASSWORDS_SCHEMA = SCHEMA.ListOf(PASSWORD_SCHEMA)

# The actual values of a key, as opposed to meta data such as a key type and
# key identifier ('rsa', 233df889cb).  For RSA keys, the key value is a pair of
# public and private keys in PEM Format stored as strings.
KEYVAL_SCHEMA = SCHEMA.Object(
  object_name = 'KEYVAL_SCHEMA',
  public = SCHEMA.AnyString(),
  private = SCHEMA.Optional(SCHEMA.AnyString()))

# Supported TUF key types. 
KEYTYPE_SCHEMA = SCHEMA.OneOf(
  [SCHEMA.String('rsa'), SCHEMA.String('ed25519')])

# A generic TUF key.  All TUF keys should be saved to metadata files in this
# format.
KEY_SCHEMA = SCHEMA.Object(
  object_name = 'KEY_SCHEMA',
  keytype = SCHEMA.AnyString(),
  keyval = KEYVAL_SCHEMA)

# A TUF key object.  This schema simplifies validation of keys that may be
# one of the supported key types.
# Supported key types: 'rsa', 'ed25519'.
ANYKEY_SCHEMA = SCHEMA.Object(
  object_name = 'ANYKEY_SCHEMA',
  keytype = KEYTYPE_SCHEMA,
  keyid = KEYID_SCHEMA,
  keyval = KEYVAL_SCHEMA)

# A list of TUF key objects.
ANYKEYLIST_SCHEMA = SCHEMA.ListOf(ANYKEY_SCHEMA)

# An RSA TUF key.
RSAKEY_SCHEMA = SCHEMA.Object(
  object_name = 'RSAKEY_SCHEMA',
  keytype = SCHEMA.String('rsa'),
  keyid = KEYID_SCHEMA,
  keyval = KEYVAL_SCHEMA)

# An ED25519 raw public key, which must be 32 bytes.
ED25519PUBLIC_SCHEMA = SCHEMA.LengthBytes(32)

# An ED25519 raw seed key, which must be 32 bytes.  
ED25519SEED_SCHEMA = SCHEMA.LengthBytes(32)

# An ED25519 raw signature, which must be 64 bytes.  
ED25519SIGNATURE_SCHEMA = SCHEMA.LengthBytes(64)

# Required installation libraries expected by the repository tools and other
# cryptography modules.
REQUIRED_LIBRARIES_SCHEMA = SCHEMA.ListOf(SCHEMA.OneOf(
  [SCHEMA.String('general'), SCHEMA.String('ed25519'), SCHEMA.String('rsa')]))

# An ed25519 TUF key.
ED25519KEY_SCHEMA = SCHEMA.Object(
  object_name = 'ED25519KEY_SCHEMA',
  keytype = SCHEMA.String('ed25519'),
  keyid = KEYID_SCHEMA,
  keyval = KEYVAL_SCHEMA)

# Information about target files, like file length and file hash(es).  This
# schema allows the storage of multiple hashes for the same file (e.g., sha256
# and sha512 may be computed for the same file and stored).
FILEINFO_SCHEMA = SCHEMA.Object(
  object_name = 'FILEINFO_SCHEMA',
  length = LENGTH_SCHEMA,
  hashes = HASHDICT_SCHEMA,
  custom = SCHEMA.Optional(SCHEMA.Object()))

# Version information specified in "snapshot.json" for each role available on
# the TUF repository.  The 'FILEINFO_SCHEMA' object was previously listed in
# the snapshot role, but was switched to this object format to reduce the
# amount of metadata that needs to be downloaded.  Listing version numbers in
# "snapshot.json" also prevents rollback attacks for roles that clients have
# not downloaded. 
VERSIONINFO_SCHEMA = SCHEMA.Object(
  object_name = 'VERSIONINFO_SCHEMA',
  version = METADATAVERSION_SCHEMA)

# A dict holding the version information for a particular metadata role.  The
# dict keys hold the relative file paths, and the dict values the corresponding
# version numbers.
VERSIONDICT_SCHEMA = SCHEMA.DictOf(
  key_schema = RELPATH_SCHEMA,
  value_schema = VERSIONINFO_SCHEMA)

# A dict holding the information for a particular target / file.  The dict keys
# hold the relative file paths, and the dict values the corresponding file
# information.
FILEDICT_SCHEMA = SCHEMA.DictOf(
  key_schema = RELPATH_SCHEMA,
  value_schema = FILEINFO_SCHEMA)

# A dict holding a target file.
TARGETFILE_SCHEMA = SCHEMA.Object(
  object_name = 'TARGETFILE_SCHEMA',
  filepath = RELPATH_SCHEMA,
  fileinfo = FILEINFO_SCHEMA)

# A list of TARGETFILE_SCHEMA.
TARGETFILES_SCHEMA = SCHEMA.ListOf(TARGETFILE_SCHEMA)

# A single signature of an object.  Indicates the signature, the ID of the
# signing key, and the signing method.
# I debated making the signature schema not contain the key ID and instead have
# the signatures of a file be a dictionary with the key being the keyid and the
# value being the signature schema without the keyid. That would be under
# the argument that a key should only be able to sign a file once. However,
# one can imagine that maybe a key wants to sign multiple times with different
# signature methods.
SIGNATURE_SCHEMA = SCHEMA.Object(
  object_name = 'SIGNATURE_SCHEMA',
  keyid = KEYID_SCHEMA,
  method = SIG_METHOD_SCHEMA,
  sig = HEX_SCHEMA)

# List of SIGNATURE_SCHEMA.
SIGNATURES_SCHEMA = SCHEMA.ListOf(SIGNATURE_SCHEMA)

# A schema holding the result of checking the signatures of a particular
# 'SIGNABLE_SCHEMA' role.
# For example, how many of the signatures for the 'Target' role are
# valid?  This SCHEMA holds this information.  See 'sig.py' for
# more information.
SIGNATURESTATUS_SCHEMA = SCHEMA.Object(
  object_name = 'SIGNATURESTATUS_SCHEMA',
  threshold = SCHEMA.Integer(),
  good_sigs = KEYIDS_SCHEMA,
  bad_sigs = KEYIDS_SCHEMA,
  unknown_sigs = KEYIDS_SCHEMA,
  untrusted_sigs = KEYIDS_SCHEMA,
  unknown_method_sigs = KEYIDS_SCHEMA)

# A signable object.  Holds the signing role and its associated signatures.
SIGNABLE_SCHEMA = SCHEMA.Object(
  object_name = 'SIGNABLE_SCHEMA',
  signed = SCHEMA.Any(),
  signatures = SCHEMA.ListOf(SIGNATURE_SCHEMA))

# A dict where the dict keys hold a keyid and the dict values a key object.
KEYDICT_SCHEMA = SCHEMA.DictOf(
  key_schema = KEYID_SCHEMA,
  value_schema = KEY_SCHEMA)

# The format used by the key database to store keys.  The dict keys hold a key
# identifier and the dict values any object.  The key database should store
# key objects in the values (e.g., 'RSAKEY_SCHEMA', 'DSAKEY_SCHEMA').
KEYDB_SCHEMA = SCHEMA.DictOf(
  key_schema = KEYID_SCHEMA,
  value_schema = SCHEMA.Any())

# The format of the resulting "scp config dict" after extraction from the
# push configuration file (i.e., push.cfg).  In the case of a config file
# utilizing the scp transfer module, it must contain the 'general' and 'scp'
# sections, where 'general' must contain a 'transfer_module' and
# 'metadata_path' entry, and 'scp' the 'host', 'user', 'identity_file', and
# 'remote_directory' entries.  See 'tuf/pushtools/pushtoolslib.py' and
# 'tuf/pushtools/push.py'.
SCPCONFIG_SCHEMA = SCHEMA.Object(
  object_name = 'SCPCONFIG_SCHEMA',
  general = SCHEMA.Object(
    object_name = '[general]',
    transfer_module = SCHEMA.String('scp'),
    metadata_path = PATH_SCHEMA,
    targets_directory = PATH_SCHEMA),
  scp=SCHEMA.Object(
    object_name = '[scp]',
    host = URL_SCHEMA,
    user = NAME_SCHEMA,
    identity_file = PATH_SCHEMA,
    remote_directory = PATH_SCHEMA))

# The format of the resulting "receive config dict" after extraction from the
# receive configuration file (i.e., receive.cfg).  The receive config file
# must contain a 'general' section, and this section the 'pushroots',
# 'repository_directory', 'metadata_directory', 'targets_directory', and
# 'backup_directory' entries.
# see 'tuf/pushtools/pushtoolslib.py' and 'tuf/pushtools/receive/receive.py'
RECEIVECONFIG_SCHEMA = SCHEMA.Object(
  object_name = 'RECEIVECONFIG_SCHEMA', general=SCHEMA.Object(
    object_name = '[general]',
    pushroots = SCHEMA.ListOf(PATH_SCHEMA),
    repository_directory = PATH_SCHEMA,
    metadata_directory = PATH_SCHEMA,
    targets_directory = PATH_SCHEMA,
    backup_directory = PATH_SCHEMA)) 

# A path hash prefix is a hexadecimal string.
PATH_HASH_PREFIX_SCHEMA = HEX_SCHEMA

# A list of path hash prefixes.
PATH_HASH_PREFIXES_SCHEMA = SCHEMA.ListOf(PATH_HASH_PREFIX_SCHEMA)

# Role object in {'keyids': [keydids..], 'name': 'ABC', 'threshold': 1,
# 'paths':[filepaths..]} format.
ROLE_SCHEMA = SCHEMA.Object(
  object_name = 'ROLE_SCHEMA',
  name = SCHEMA.Optional(ROLENAME_SCHEMA),
  keyids = KEYIDS_SCHEMA,
  threshold = THRESHOLD_SCHEMA,
  backtrack = SCHEMA.Optional(BOOLEAN_SCHEMA),
  paths = SCHEMA.Optional(RELPATHS_SCHEMA),
  path_hash_prefixes = SCHEMA.Optional(PATH_HASH_PREFIXES_SCHEMA))

# A dict of roles where the dict keys are role names and the dict values holding 
# the role data/information.
ROLEDICT_SCHEMA = SCHEMA.DictOf(
  key_schema = ROLENAME_SCHEMA,
  value_schema = ROLE_SCHEMA)

# Like ROLEDICT_SCHEMA, except that ROLE_SCHEMA instances are stored in order.
ROLELIST_SCHEMA = SCHEMA.ListOf(ROLE_SCHEMA)

# The delegated roles of a Targets role (a parent).
DELEGATIONS_SCHEMA = SCHEMA.Object(
  keys = KEYDICT_SCHEMA,
  roles = ROLELIST_SCHEMA)

# Supported compression extension (e.g., 'gz').
COMPRESSION_SCHEMA = SCHEMA.OneOf([SCHEMA.String(''), SCHEMA.String('gz')])

# List of supported compression extensions.
COMPRESSIONS_SCHEMA = SCHEMA.ListOf(
  SCHEMA.OneOf([SCHEMA.String(''), SCHEMA.String('gz')]))

# The fileinfo format of targets specified in the repository and
# developer tools.  The second element of this list holds custom data about the
# target, such as file permissions, author(s), last modified, etc.
CUSTOM_SCHEMA = SCHEMA.Object()

PATH_FILEINFO_SCHEMA = SCHEMA.DictOf(
  key_schema = RELPATH_SCHEMA,
  value_schema = CUSTOM_SCHEMA)

# tuf.roledb
ROLEDB_SCHEMA = SCHEMA.Object(
  object_name = 'ROLEDB_SCHEMA',
  keyids = KEYIDS_SCHEMA,
  signing_keyids = SCHEMA.Optional(KEYIDS_SCHEMA),
  threshold = THRESHOLD_SCHEMA,
  version = SCHEMA.Optional(METADATAVERSION_SCHEMA),
  expires = SCHEMA.Optional(ISO8601_DATETIME_SCHEMA),
  signatures = SCHEMA.Optional(SIGNATURES_SCHEMA),
  compressions = SCHEMA.Optional(COMPRESSIONS_SCHEMA),
  paths = SCHEMA.Optional(SCHEMA.OneOf([RELPATHS_SCHEMA, PATH_FILEINFO_SCHEMA])),
  path_hash_prefixes = SCHEMA.Optional(PATH_HASH_PREFIXES_SCHEMA),
  delegations = SCHEMA.Optional(DELEGATIONS_SCHEMA),
  partial_loaded = SCHEMA.Optional(BOOLEAN_SCHEMA))

# Root role: indicates root keys and top-level roles.
ROOT_SCHEMA = SCHEMA.Object(
  object_name = 'ROOT_SCHEMA',
  _type = SCHEMA.String('Root'),
  version = METADATAVERSION_SCHEMA,
  consistent_snapshot = BOOLEAN_SCHEMA,
  compression_algorithms = COMPRESSIONS_SCHEMA,
  expires = ISO8601_DATETIME_SCHEMA,
  keys = KEYDICT_SCHEMA,
  roles = ROLEDICT_SCHEMA)

# Targets role: Indicates targets and delegates target paths to other roles.
TARGETS_SCHEMA = SCHEMA.Object(
  object_name = 'TARGETS_SCHEMA',
  _type = SCHEMA.String('Targets'),
  version = METADATAVERSION_SCHEMA,
  expires = ISO8601_DATETIME_SCHEMA,
  targets = FILEDICT_SCHEMA,
  delegations = SCHEMA.Optional(DELEGATIONS_SCHEMA))

# Snapshot role: indicates the latest versions of all metadata (except timestamp).
SNAPSHOT_SCHEMA = SCHEMA.Object(
  object_name = 'SNAPSHOT_SCHEMA',
  _type = SCHEMA.String('Snapshot'),
  version = METADATAVERSION_SCHEMA,
  expires = ISO8601_DATETIME_SCHEMA,
  meta = VERSIONDICT_SCHEMA)

# Timestamp role: indicates the latest version of the snapshot file.
TIMESTAMP_SCHEMA = SCHEMA.Object(
  object_name = 'TIMESTAMP_SCHEMA',
  _type = SCHEMA.String('Timestamp'),
  version = METADATAVERSION_SCHEMA,
  expires = ISO8601_DATETIME_SCHEMA,
  meta = VERSIONDICT_SCHEMA)

# project.cfg file: stores information about the project in a json dictionary
PROJECT_CFG_SCHEMA = SCHEMA.Object(
    object_name = 'PROJECT_CFG_SCHEMA',
    project_name = SCHEMA.AnyString(),
    layout_type = SCHEMA.OneOf([SCHEMA.String('repo-like'), SCHEMA.String('flat')]),
    targets_location = PATH_SCHEMA,
    metadata_location = PATH_SCHEMA,
    prefix = PATH_SCHEMA,
    public_keys = KEYDICT_SCHEMA,
    threshold = SCHEMA.Integer(lo = 0, hi = 2)
    )

# A schema containing information a repository mirror may require,
# such as a url, the path of the directory metadata files, etc.
MIRROR_SCHEMA = SCHEMA.Object(
  object_name = 'MIRROR_SCHEMA',
  url_prefix = URL_SCHEMA,
  metadata_path = RELPATH_SCHEMA,
  targets_path = RELPATH_SCHEMA,
  confined_target_dirs = RELPATHS_SCHEMA,
  custom = SCHEMA.Optional(SCHEMA.Object()))

# A dictionary of mirrors where the dict keys hold the mirror's name and
# and the dict values the mirror's data (i.e., 'MIRROR_SCHEMA').
# The repository class of 'updater.py' accepts dictionaries
# of this type provided by the TUF client.
MIRRORDICT_SCHEMA = SCHEMA.DictOf(
  key_schema = SCHEMA.AnyString(),
  value_schema = MIRROR_SCHEMA)

# A Mirrorlist: indicates all the live mirrors, and what documents they
# serve.
MIRRORLIST_SCHEMA = SCHEMA.Object(
  object_name = 'MIRRORLIST_SCHEMA',
  _type = SCHEMA.String('Mirrors'),
  version = METADATAVERSION_SCHEMA,
  expires = ISO8601_DATETIME_SCHEMA,
  mirrors = SCHEMA.ListOf(MIRROR_SCHEMA))

# Any of the role schemas (e.g., TIMESTAMP_SCHEMA, SNAPSHOT_SCHEMA, etc.)
ANYROLE_SCHEMA = SCHEMA.OneOf([ROOT_SCHEMA, TARGETS_SCHEMA, SNAPSHOT_SCHEMA,
                               TIMESTAMP_SCHEMA, MIRROR_SCHEMA])





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
  def __init__(self, version, expires, versiondict):
    self.info = {}
    self.info['version'] = version
    self.info['expires'] = expires
    self.info['meta'] = versiondict


  @staticmethod
  def from_metadata(object):
    # Is 'object' a Timestamp metadata file?
    # Raise tuf.FormatError if not.
    TIMESTAMP_SCHEMA.check_match(object) 

    version = object['version']
    expires = object['expires']
    versiondict = object['meta']
    
    return TimestampFile(version, expires, versiondict)
    
    
  @staticmethod
  def make_metadata(version, expiration_date, versiondict):
    result = {'_type' : 'Timestamp'}
    result['version'] = version 
    result['expires'] = expiration_date
    result['meta'] = versiondict

    # Is 'result' a Timestamp metadata file?
    # Raise 'tuf.FormatError' if not.
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
    # Raise 'tuf.FormatError' if not.
    ROOT_SCHEMA.check_match(object) 
    
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
    # Raise 'tuf.FormatError' if not.
    ROOT_SCHEMA.check_match(result)
    
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
    # Raise 'tuf.FormatError' if not.
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
    # Raise 'tuf.FormatError' if not.
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
    # Raise tuf.FormatError if not.
    TARGETS_SCHEMA.check_match(object)
    
    version = object['version']
    expires = object['expires']
    filedict = object.get('targets')
    delegations = object.get('delegations')
    
    return TargetsFile(version, expires, filedict, delegations)


  @staticmethod
  def make_metadata(version, expiration_date, filedict=None, delegations=None):
    if filedict is None and delegations is None:
      raise tuf.Error('We don\'t allow completely empty targets metadata.')

    result = {'_type' : 'Targets'}
    result['version'] = version
    result['expires'] = expiration_date
    result['targets'] = {} 
    if filedict is not None:
      result['targets'] = filedict
    if delegations is not None:
      result['delegations'] = delegations

    # Is 'result' a Targets metadata file?
    # Raise 'tuf.FormatError' if not.
    TARGETS_SCHEMA.check_match(result)
    
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
  'Root' : ROOT_SCHEMA,
  'Targets' : TARGETS_SCHEMA,
  'Snapshot' : SNAPSHOT_SCHEMA,
  'Timestamp' : TIMESTAMP_SCHEMA,
  'Mirrors' : MIRRORLIST_SCHEMA}

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
    tuf.FormatError, if 'datetime_object' is not a datetime.datetime() object.

  <Side Effects>
    None.

  <Returns>
    A unix (posix) timestamp (e.g., 499137660).
  """
  
  # Is 'datetime_object' a datetime.datetime() object?
  # Raise 'tuf.FormatError' if not.
  if not isinstance(datetime_object, datetime.datetime):
    message = repr(datetime_object) + ' is not a datetime.datetime() object.'
    raise tuf.FormatError(message) 
   
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
      'tuf.formats.UNIX_TIMESTAMP_SCHEMA'.

  <Exceptions>
    tuf.FormatError, if 'unix_timestamp' is improperly formatted.

  <Side Effects>
    None.

  <Returns>
    A datetime.datetime() object corresponding to 'unix_timestamp'.
  """
  
  # Is 'unix_timestamp' properly formatted?
  # Raise 'tuf.FormatError' if there is a mismatch.
  UNIX_TIMESTAMP_SCHEMA.check_match(unix_timestamp)

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
    Return the base64 encoding of 'data' with whitespace
    and '=' signs omitted.

  <Arguments>
    data:
      Binary or buffer of data to convert.

  <Exceptions>
    tuf.FormatError, if the base64 encoding fails or the argument
    is invalid.

  <Side Effects>
    None.

  <Returns>
    A base64-encoded string.
  """
  
  try:
    return binascii.b2a_base64(data).decode('utf-8').rstrip('=\n ')
  
  except (TypeError, binascii.Error) as e:
    raise tuf.FormatError('Invalid base64 encoding: ' + str(e))





def parse_base64(base64_string):
  """
  <Purpose>
    Parse a base64 encoding with whitespace and '=' signs omitted.
  
  <Arguments>
    base64_string:
      A string holding a base64 value.

  <Exceptions>
    tuf.FormatError, if 'base64_string' cannot be parsed due to
    an invalid base64 encoding.

  <Side Effects>
    None.

  <Returns>
    A byte string representing the parsed based64 encoding of
    'base64_string'.
  """

  if not isinstance(base64_string, six.string_types):
    message = 'Invalid argument: '+repr(base64_string)
    raise tuf.FormatError(message)

  extra = len(base64_string) % 4
  if extra:
    padding = '=' * (4 - extra)
    base64_string = base64_string + padding

  try:
    return binascii.a2b_base64(base64_string.encode('utf-8'))
  
  except (TypeError, binascii.Error) as e:
    raise tuf.FormatError('Invalid base64 encoding: ' + str(e))





def make_signable(object):
  """
  <Purpose>
    Return the role metadata 'object' in 'SIGNABLE_SCHEMA' format.
    'object' is added to the 'signed' key, and an empty list
    initialized to the 'signatures' key.  The caller adds signatures
    to this second field.
    Note: check_signable_object_format() should be called after
    make_signable() and signatures added to ensure the final
    signable object has a valid format (i.e., a signable containing
    a supported role metadata).

  <Arguments>
    object:
      A role schema dict (e.g., 'ROOT_SCHEMA', 'SNAPSHOT_SCHEMA'). 

  <Exceptions>
    None.

  <Side Effects>
    None.

  <Returns>
    A dict in 'SIGNABLE_SCHEMA' format.
  """

  if not isinstance(object, dict) or 'signed' not in object:
    return { 'signed' : object, 'signatures' : [] }
  else:
    return object





def make_fileinfo(length, hashes, custom=None):
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

    custom:
      An optional object providing additional information about the file.

  <Exceptions>
    tuf.FormatError, if the 'FILEINFO_SCHEMA' to be returned
    does not have the correct format.

  <Side Effects>
    If any of the arguments are incorrectly formatted, the dict
    returned will be checked for formatting errors, and if found,
    will raise a 'tuf.FormatError' exception.

  <Returns>
    A dictionary conformant to 'FILEINFO_SCHEMA', representing the file
    information of a metadata or target file.
  """

  fileinfo = {'length' : length, 'hashes' : hashes}
  if custom is not None:
    fileinfo['custom'] = custom

  # Raise 'tuf.FormatError' if the check fails.
  FILEINFO_SCHEMA.check_match(fileinfo)

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
    tuf.FormatError, if the dict to be returned does not have the correct
    format (i.e., VERSIONINFO_SCHEMA).

  <Side Effects>
    None.

  <Returns>
    A dictionary conformant to 'VERSIONINFO_SCHEMA', containing the version
    information of a metadata role.
  """

  versioninfo = {'version' : version_number}

  # Raise 'tuf.FormatError' if 'versioninfo' is improperly formatted.
  try: 
    VERSIONINFO_SCHEMA.check_match(versioninfo)
  
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
    tuf.FormatError, if the returned role meta is
    formatted incorrectly.

  <Side Effects>
    If any of the arguments do not have a proper format, a 
    tuf.formats exception is raised when the 'ROLE_SCHEMA' dict
    is created.

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
    raise \
      tuf.FormatError('Both "paths" and "path_hash_prefixes" are specified.')

  if path_hash_prefixes is not None:
    role_meta['path_hash_prefixes'] = path_hash_prefixes
  elif paths is not None:
    role_meta['paths'] = paths

  # Does 'role_meta' have the correct type?
  # This check ensures 'role_meta' conforms to
  # tuf.formats.ROLE_SCHEMA.
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
    tuf.FormatError, if 'expected_rolename' is not a
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
  # 'tuf.formats.NAME_SCHEMA'.
  # Raise 'tuf.FormatError' if there is a mismatch.
  NAME_SCHEMA.check_match(expected_rolename)
  
  try:
    role_class = ROLE_CLASSES_BY_TYPE[expected_rolename]
  
  except KeyError:
    raise tuf.FormatError(repr(expected_rolename) + ' not supported.')
  
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
    tuf.FormatError, if 'meta_rolename' is improperly formatted.

  <Side Effects>
    None.

  <Returns>
    A string (e.g., 'Root', 'Targets').
  """
   
  # Does 'meta_rolename' have the correct type?
  # This check ensures 'meta_rolename' conforms to
  # 'tuf.formats.NAME_SCHEMA'.
  # Raise 'tuf.FormatError' if there is a mismatch.
  NAME_SCHEMA.check_match(meta_rolename)
  
  return string.capwords(meta_rolename)





def check_signable_object_format(object):
  """
  <Purpose>
    Ensure 'object' is properly formatted, conformant to
    'tuf.formats.SIGNABLE_SCHEMA'.  Return the signing role on success.
    Note: The 'signed' field of a 'SIGNABLE_SCHEMA' is checked against
    tuf.schema.Any().  The 'signed' field, however, should actually
    hold one of the supported role schemas (e.g., 'ROOT_SCHEMA',
    'TARGETS_SCHEMA').  The role schemas all differ in their format, so this
    function determines exactly which schema is listed in the 'signed'
    field.

  <Arguments>
    object:
     The object compare against 'SIGNABLE.SCHEMA'. 

  <Exceptions>
    tuf.FormatError, if 'object' does not have the correct format.

  <Side Effects>
    None.

  <Returns>
    A string representing the signing role (e.g., 'root', 'targets').
    The role string is returned with characters all lower case.
  """
  
  # Does 'object' have the correct type?
  # This check ensures 'object' conforms to
  # 'tuf.formats.SIGNABLE_SCHEMA'.
  SIGNABLE_SCHEMA.check_match(object)

  try:
    role_type = object['signed']['_type']
  
  except (KeyError, TypeError):
    raise tuf.FormatError('Untyped object')
  
  try:
    schema = SCHEMAS_BY_TYPE[role_type]
  
  except KeyError:
    raise tuf.FormatError('Unrecognized type ' + repr(role_type))
  
  # 'tuf.FormatError' raised if 'object' does not have a properly
  # formatted role schema.
  schema.check_match(object['signed'])

  return role_type.lower()





def _canonical_string_encoder(string):
  """
  <Purpose>
    Encode 'string' to canonical string format.
    
  <Arguments>
    string:
      The string to encode.

  <Exceptions>
    None.

  <Side Effects>
    None.

  <Returns>
    A string with the canonical-encoded 'string' embedded.
  """

  string = '"%s"' % re.sub(r'(["\\])', r'\\\1', string)
 
  return string





def _encode_canonical(object, output_function):
  # Helper for encode_canonical.  Older versions of json.encoder don't
  # even let us replace the separators.

  if isinstance(object, six.string_types):
    output_function(_canonical_string_encoder(object))
  elif object is True:
    output_function("true")
  elif object is False:
    output_function("false")
  elif object is None:
    output_function("null")
  elif isinstance(object, six.integer_types):
    output_function(str(object))
  elif isinstance(object, (tuple, list)):
    output_function("[")
    if len(object):
      for item in object[:-1]:
        _encode_canonical(item, output_function)
        output_function(",")
      _encode_canonical(object[-1], output_function)
    output_function("]")
  elif isinstance(object, dict):
    output_function("{")
    if len(object):
      items = sorted(six.iteritems(object))
      for key, value in items[:-1]:
        output_function(_canonical_string_encoder(key))
        output_function(":")
        _encode_canonical(value, output_function)
        output_function(",")
      key, value = items[-1]
      output_function(_canonical_string_encoder(key))
      output_function(":")
      _encode_canonical(value, output_function)
    output_function("}")
  else:
    raise tuf.FormatError('I cannot encode '+repr(object))





def encode_canonical(object, output_function=None):
  """
  <Purpose>
    Encode 'object' in canonical JSON form, as specified at
    http://wiki.laptop.org/go/Canonical_JSON .  It's a restricted
    dialect of JSON in which keys are always lexically sorted,
    there is no whitespace, floats aren't allowed, and only quote
    and backslash get escaped.  The result is encoded in UTF-8,
    and the resulting bits are passed to output_function (if provided),
    or joined into a string and returned.

    Note: This function should be called prior to computing the hash or
    signature of a JSON object in TUF.  For example, generating a signature
    of a signing role object such as 'ROOT_SCHEMA' is required to ensure
    repeatable hashes are generated across different json module versions
    and platforms.  Code elsewhere is free to dump JSON objects in any format
    they wish (e.g., utilizing indentation and single quotes around object
    keys).  These objects are only required to be in "canonical JSON" format
    when their hashes or signatures are needed.

    >>> encode_canonical("")
    '""'
    >>> encode_canonical([1, 2, 3])
    '[1,2,3]'
    >>> encode_canonical([])
    '[]'
    >>> encode_canonical({"A": [99]})
    '{"A":[99]}'
    >>> encode_canonical({"x" : 3, "y" : 2})
    '{"x":3,"y":2}'
  
  <Arguments>
    object:
      The object to be encoded.

    output_function:
      The result will be passed as arguments to 'output_function'
      (e.g., output_function('result')).

  <Exceptions>
    tuf.FormatError, if 'object' cannot be encoded or 'output_function'
    is not callable.

  <Side Effects>
    The results are fed to 'output_function()' if 'output_function' is set.  

  <Returns>
    A string representing the 'object' encoded in canonical JSON form.
  """

  result = None
  # If 'output_function' is unset, treat it as
  # appending to a list.
  if output_function is None:
    result = []
    output_function = result.append

  try:
    _encode_canonical(object, output_function)
  
  except (TypeError, tuf.FormatError) as  e:
    message = 'Could not encode ' + repr(object) + ': ' + str(e)
    raise tuf.FormatError(message)

  # Return the encoded 'object' as a string.
  # Note: Implies 'output_function' is None,
  # otherwise results are sent to 'output_function'.
  if result is not None:
    return ''.join(result)





if __name__ == '__main__':
  # The interactive sessions of the documentation strings can
  # be tested by running formats.py as a standalone module.
  # python -B formats.py
  import doctest
  doctest.testmod()
