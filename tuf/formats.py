#!/usr/bin/env python

# Copyright 2012 - 2017, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
<Program Name>
  formats.py

<Author>
  Geremy Condra
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Copyright>
  See LICENSE-MIT OR LICENSE for licensing information.

<Purpose>
  A central module to define the data structures / formats used in the TUF
  reference implementation, along with some functions for creating and checking
  objects that conform to them.

  Because simpler components used in larger structures are defined first,
  please look to the last definitions if you're looking for the metadata role
  definitions.

  These definitions depend on some basic schema-defining functionality and
  crypto formats from securesystemslib.schemas and securesystemslib.formats.

  'formats.py' can be broken down into two sections:
    (1) Schema definitions
    (2) Functions that help produce or verify schema-conformant objects
        (build_dict_conforming_to_schema, make_signable, etc.)


  Checking objects against these definitions can be done with either of two
  methods:

      <SCHEMA>.check_match(object)
          Raises FormatError if object does not match <SCHEMA>.

      <SCHEMA>.matches(object)
          Returns True if object matches <SCHEMA>, else False.

  Example:

  rsa_key = {'keytype': 'rsa'
             'keyid': 34892fc465ac76bc3232fab
             'keyval': {'public': 'public_key',
                        'private': 'private_key'}

  securesystemslib.formats.RSAKEY_SCHEMA.check_match(rsa_key)
  securesystemslib.formats.RSAKEY_SCHEMA.matches(rsa_key)

  In this example, if a dict key or dict value is missing or incorrect,
  the match fails.  There are numerous variations of object checking
  provided by 'formats.py' and 'schema.py'.

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
import datetime
import time
import copy

import securesystemslib.formats
import securesystemslib.schema as SCHEMA

import tuf

import six


# Version numbers for metadata and data sizes/lengths are natural integers.
INTEGER_NATURAL_SCHEMA = SCHEMA.Integer(lo=0)

# The version of the specification with which a piece of metadata conforms is
# expressed as a string.  It should conform to the typical major.minor.fix
# format version numbers commonly use, but we are not yet strict about this.
SPECIFICATION_VERSION_SCHEMA = SCHEMA.AnyString()

# A datetime in 'YYYY-MM-DDTHH:MM:SSZ' ISO 8601 format.  The "Z" zone designator
# for the zero UTC offset is always used (i.e., a numerical offset is not
# supported.)  Example: '2015-10-21T13:20:00Z'.  Note:  This is a simple format
# check, and an ISO8601 string should be fully verified when it is parsed.
ISO8601_DATETIME_SCHEMA = SCHEMA.RegularExpression(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z')

# A string representing a role's name.
ROLENAME_SCHEMA = SCHEMA.AnyString()

# Command argument list, as used by the CLI tool.
# Example: {'keytype': ed25519, 'expires': 365,}
COMMAND_SCHEMA = SCHEMA.DictOf(
  key_schema = securesystemslib.formats.NAME_SCHEMA,
  value_schema = SCHEMA.Any())

# A value that is either True or False, on or off, etc.
BOOLEAN_SCHEMA = SCHEMA.Boolean()

# A role's threshold value (i.e., the minimum number
# of signatures required to sign a metadata file).
# Must be 1 and greater.
THRESHOLD_SCHEMA = SCHEMA.Integer(lo=1)

# A key identifier (e.g., a hexadecimal value identifying an RSA key).
KEYID_SCHEMA = securesystemslib.formats.HASH_SCHEMA

# A list of KEYID_SCHEMA.
KEYIDS_SCHEMA = SCHEMA.ListOf(KEYID_SCHEMA)

# The actual values of a key, as opposed to meta data such as a key type and
# key identifier ('rsa', 233df889cb).  For RSA keys, the key value is a pair of
# public and private keys in PEM Format stored as strings.
KEYVAL_SCHEMA = SCHEMA.Object(
  object_name = 'KEYVAL_SCHEMA',
  public = SCHEMA.AnyString(),
  private = SCHEMA.Optional(SCHEMA.AnyString()))

# A generic TUF key.  All TUF keys should be saved to metadata files in this
# format.
KEY_SCHEMA = SCHEMA.Object(
  object_name = 'KEY_SCHEMA',
  keytype = SCHEMA.AnyString(),
  keyval = KEYVAL_SCHEMA,
  expires = SCHEMA.Optional(ISO8601_DATETIME_SCHEMA))

# A dict where the dict keys hold a keyid and the dict values a key object.
KEYDICT_SCHEMA = SCHEMA.DictOf(
  key_schema = KEYID_SCHEMA,
  value_schema = KEY_SCHEMA)


# A path hash prefix is a hexadecimal string.
PATH_HASH_PREFIX_SCHEMA = securesystemslib.formats.HEX_SCHEMA

# A list of path hash prefixes.
PATH_HASH_PREFIXES_SCHEMA = SCHEMA.ListOf(PATH_HASH_PREFIX_SCHEMA)


# FILEINFO schemas:
# In TUF, we store information about files in a variety of ways.
# Sometimes, versions are used, and sometimes length and hashes are required.
# So FILEINFO_SCHEMA will match any of these three schemas:
# FILEINFO_IN_TIMESTAMP_SCHEMA, FILEINFO_IN_SNAPSHOT_SCHEMA,
# and FILEINFO_IN_TARGETS_SCHEMA.

# Timestamp metadata must list version, hashes, and length for the Snapshot
# metadata.
#   example:
#     { 'version':  7, 'length': 52, 'hashes': {'sha256': '123456...'}}
FILEINFO_IN_TIMESTAMP_SCHEMA = SCHEMA.Object(
    object_name = 'FILEINFO_IN_TIMESTAMP_SCHEMA',
    version = INTEGER_NATURAL_SCHEMA,
    length = INTEGER_NATURAL_SCHEMA,
    hashes = securesystemslib.formats.HASHDICT_SCHEMA)

# Snapshot metadata lists only version numbers for all the Targets roles on the
# repository.  (Other implementations might include hashes and length.)
#   example:
#     { 'version': 5 }
FILEINFO_IN_SNAPSHOT_SCHEMA = SCHEMA.Object(
    object_name = 'FILEINFO_IN_SNAPSHOT_SCHEMA',
    version = INTEGER_NATURAL_SCHEMA)


# Because Targets metadata must provide cryptographically secure information
# about the targets that must be verified, it must list hashes and length.
# It does not list version numbers, but may list additional, custom fields.
#
# Custom fields might be, for example, things like the hash to expect when an
# encrypted target file is decrypted, the file permissions recommended, authors,
# compatible part numbers, etc.).
#   examples:
#     {'length': 10, 'hashes': {'sha256': '123456...'}}
#     {
#       'length': 10,
#       'hashes': {'sha256': '123456...'},
#       'custom': {'arbitrary': 123, 'metadata': {1: ''}}
#     }
CUSTOM_SCHEMA = SCHEMA.Object()
FILEINFO_IN_TARGETS_SCHEMA = SCHEMA.Object(
    object_name= 'FILEINFO_IN_TARGETS_SCHEMA',
    length = INTEGER_NATURAL_SCHEMA,
    hashes = securesystemslib.formats.HASHDICT_SCHEMA,
    custom = SCHEMA.Optional(CUSTOM_SCHEMA))

# FILEINFO_SCHEMA provides a generalization of the above FILEINFO schemas, for
# testing and modularity reasons.
FILEINFO_SCHEMA = SCHEMA.OneOf(
    [FILEINFO_IN_TIMESTAMP_SCHEMA,
    FILEINFO_IN_SNAPSHOT_SCHEMA,
    FILEINFO_IN_TARGETS_SCHEMA])


# A dictionary mapping paths or rolenames to FILEINFO_SCHEMAs.
# This is used in Timestamp, Snapshot, and Targets roles.
#
#   examples:
#     { 'targets':
#       {'length': 10, 'hashes': {'sha256': '123456'}, 'version': 3}}
#
FILEINFO_DICT_SCHEMA = SCHEMA.DictOf(
  key_schema = SCHEMA.OneOf(
      [securesystemslib.formats.PATH_SCHEMA, ROLENAME_SCHEMA]),
  value_schema = FILEINFO_SCHEMA)

# LABELED_FILEINFO_SCHEMA is a filepath-labeled equivalent of
# FILEINFO_IN_TARGETS_SCHEMA.  It may be of use when storing or exporting
# information about multiple targets.
# e.g.
#     {'filepath': '1.tgz',
#      'fileinfo': {'length': 10, 'hashes': {'sha256': '123456'}}}
LABELED_FILEINFO_SCHEMA = SCHEMA.Object(
  object_name = 'TARGELABELED_FILEINFO_SCHEMATINFO_SCHEMA',
  filepath = securesystemslib.formats.PATH_SCHEMA,
  fileinfo = FILEINFO_IN_TARGETS_SCHEMA)

# A list of LABELED_FILEINFO_SCHEM objects.
LABELED_FILEINFOS_SCHEMA = SCHEMA.ListOf(LABELED_FILEINFO_SCHEMA)



# A dict of repository names to mirrors.
REPO_NAMES_TO_MIRRORS_SCHEMA = SCHEMA.DictOf(
  key_schema = SCHEMA.AnyString(),
  value_schema = SCHEMA.ListOf(securesystemslib.formats.URL_SCHEMA))

# An object containing the map file's "mapping" attribute.
MAPPING_SCHEMA = SCHEMA.ListOf(SCHEMA.Object(
  paths = securesystemslib.formats.PATHS_SCHEMA,
  repositories = SCHEMA.ListOf(SCHEMA.AnyString()),
  terminating = BOOLEAN_SCHEMA,
  threshold = THRESHOLD_SCHEMA))

# A dict containing the map file (named 'map.json', by default).  The format of
# the map file is covered in TAP 4: Multiple repository consensus on entrusted
# targets.
MAPFILE_SCHEMA = SCHEMA.Object(
  repositories = REPO_NAMES_TO_MIRRORS_SCHEMA,
  mapping = MAPPING_SCHEMA)


# SIGNERS_SCHEMA is the minimal information necessary to delegate or
# authenticate in TUF.  It is a list of keyids and a threshold.  For example,
# the data in root metadata stored for each top-level role takes this form.
# TODO: Contemplate alternative names like AUTHENTICATION_INFO_SCHEMA.
#   examples:
#     { 'keyids': ['1234...', 'abcd...', ...], threshold: 2}
SIGNERS_SCHEMA = SCHEMA.Object(
  object_name = 'SIGNERS_SCHEMA',
  keyids = securesystemslib.formats.KEYIDS_SCHEMA,
  threshold = THRESHOLD_SCHEMA)


# A dict of SIGNERS_SCHEMA dicts.  The dictionary in the 'roles' field of Root
# metadata takes this form, where each top-level role has an entry listing the
# keyids and threshold Root expects of those roles.
# In this dictionary, the keys are role names and the values are SIGNERS_SCHEMA
# holding keyids and threshold.
#   example:
#     { 'root':      {keyids': ['1234...', 'abcd...', ...], threshold: 2},
#       'snapshot':  {keyids': ['5656...', '9876...', ...], threshold: 1},
#       ...
#     }
SIGNERS_DICT_SCHEMA = SCHEMA.DictOf(
  key_schema = ROLENAME_SCHEMA,
  value_schema = SIGNERS_SCHEMA)


# DELEGATION_SCHEMA expands on SIGNERS_SCHEMA with some optional fields that
# pertain to Targets delegations.  Each entry in the 'delegations' field
# DELEGATION_SCHEMA provides, at a minimum, a list of keyids and a threshold.
# This schema was previously also used for elements of the 'roles' dictionary
# in Root metadata, where keyids and threshold are provided for each top-level
# role; now, however, SIGNERS_SCHEMA should be used for those.
# This schema can also be used in the delegations field of Targets metadata,
# where it is used to define a targets delegation.
# This was once "ROLE_SCHEMA", but that was a misleading name.
# A minimal example, used for a particular entry in Root's 'roles' field:
#      {
#        'keyids': [<some keyid>, <some other keyid>, ...],
#        'threshold': 1
#      }
#
DELEGATION_SCHEMA = SCHEMA.Object(
  object_name = 'DELEGATION_SCHEMA',
  name = SCHEMA.Optional(securesystemslib.formats.ROLENAME_SCHEMA),
  keyids = securesystemslib.formats.KEYIDS_SCHEMA,
  threshold = securesystemslib.formats.THRESHOLD_SCHEMA,
  terminating = SCHEMA.Optional(securesystemslib.formats.BOOLEAN_SCHEMA),
  paths = SCHEMA.Optional(securesystemslib.formats.PATHS_SCHEMA),
  path_hash_prefixes = SCHEMA.Optional(securesystemslib.formats.PATH_HASH_PREFIXES_SCHEMA))


# The 'delegations' entry in a piece of targets role metadata.
# The 'keys' entry contains a dictionary mapping keyid to key information.
# The 'roles' entry contains a list of DELEGATION_SCHEMA.  (The specification
# requires the name 'roles', even though this is somewhat misleading as it is
# populated by delegations.)
DELEGATIONS_SCHEMA = SCHEMA.Object(
  keys = KEYDICT_SCHEMA,
  roles = SCHEMA.ListOf(DELEGATION_SCHEMA))


# The number of hashed bins, or the number of delegated roles.  See
# delegate_hashed_bins() in 'repository_tool.py' for an example.  Note:
# Tools may require further restrictions on the number of bins, such
# as requiring them to be a power of 2.
NUMBINS_SCHEMA = SCHEMA.Integer(lo=1)


PATH_FILEINFO_SCHEMA = SCHEMA.DictOf(
  key_schema = securesystemslib.formats.PATH_SCHEMA,
  value_schema = CUSTOM_SCHEMA)

# A signable object.  Holds metadata and signatures over that metadata.
SIGNABLE_SCHEMA = SCHEMA.Object(
  object_name = 'SIGNABLE_SCHEMA',
  signed = SCHEMA.Any(),
  signatures = SCHEMA.ListOf(securesystemslib.formats.SIGNATURE_SCHEMA))

# Root role: indicates root keys and top-level roles.
ROOT_SCHEMA = SCHEMA.Object(
  object_name = 'ROOT_SCHEMA',
  _type = SCHEMA.String('root'),
  spec_version = SPECIFICATION_VERSION_SCHEMA,
  version = INTEGER_NATURAL_SCHEMA,
  consistent_snapshot = BOOLEAN_SCHEMA,
  expires = ISO8601_DATETIME_SCHEMA,
  keys = KEYDICT_SCHEMA,
  roles = SIGNERS_DICT_SCHEMA)

# Targets role: Indicates targets and delegates target paths to other roles.
TARGETS_SCHEMA = SCHEMA.Object(
  object_name = 'TARGETS_SCHEMA',
  _type = SCHEMA.String('targets'),
  spec_version = SPECIFICATION_VERSION_SCHEMA,
  version = INTEGER_NATURAL_SCHEMA,
  expires = ISO8601_DATETIME_SCHEMA,
  targets = FILEINFO_DICT_SCHEMA,
  delegations = SCHEMA.Optional(DELEGATIONS_SCHEMA))

# Snapshot role: indicates the latest versions of all metadata (except
# timestamp).
SNAPSHOT_SCHEMA = SCHEMA.Object(
  object_name = 'SNAPSHOT_SCHEMA',
  _type = SCHEMA.String('snapshot'),
  version = INTEGER_NATURAL_SCHEMA,
  expires = securesystemslib.formats.ISO8601_DATETIME_SCHEMA,
  spec_version = SPECIFICATION_VERSION_SCHEMA,
  meta = FILEINFO_DICT_SCHEMA)

# Timestamp role: indicates the latest version of the snapshot file.
TIMESTAMP_SCHEMA = SCHEMA.Object(
  object_name = 'TIMESTAMP_SCHEMA',
  _type = SCHEMA.String('timestamp'),
  spec_version = SPECIFICATION_VERSION_SCHEMA,
  version = SCHEMA.Integer(lo=0),
  expires = securesystemslib.formats.ISO8601_DATETIME_SCHEMA,
  meta = FILEINFO_DICT_SCHEMA)


# project.cfg file: stores information about the project in a json dictionary
PROJECT_CFG_SCHEMA = SCHEMA.Object(
    object_name = 'PROJECT_CFG_SCHEMA',
    project_name = SCHEMA.AnyString(),
    layout_type = SCHEMA.OneOf([SCHEMA.String('repo-like'), SCHEMA.String('flat')]),
    targets_location = securesystemslib.formats.PATH_SCHEMA,
    metadata_location = securesystemslib.formats.PATH_SCHEMA,
    prefix = securesystemslib.formats.PATH_SCHEMA,
    public_keys = securesystemslib.formats.KEYDICT_SCHEMA,
    threshold = SCHEMA.Integer(lo = 0, hi = 2)
    )

# A schema containing information a repository mirror may require,
# such as a url, the path of the directory metadata files, etc.
MIRROR_SCHEMA = SCHEMA.Object(
  object_name = 'MIRROR_SCHEMA',
  url_prefix = securesystemslib.formats.URL_SCHEMA,
  metadata_path = securesystemslib.formats.PATH_SCHEMA,
  targets_path = securesystemslib.formats.PATH_SCHEMA,
  confined_target_dirs = securesystemslib.formats.PATHS_SCHEMA,
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
  _type = SCHEMA.String('mirrors'),
  version = INTEGER_NATURAL_SCHEMA,
  expires = securesystemslib.formats.ISO8601_DATETIME_SCHEMA,
  mirrors = SCHEMA.ListOf(MIRROR_SCHEMA))

# TODO: Figure out if MIRROR_SCHEMA should be removed from this list.
#       (Probably)
# Any of the role schemas (e.g., TIMESTAMP_SCHEMA, SNAPSHOT_SCHEMA, etc.)
ANYROLE_SCHEMA = SCHEMA.OneOf([ROOT_SCHEMA, TARGETS_SCHEMA, SNAPSHOT_SCHEMA,
                               TIMESTAMP_SCHEMA, MIRROR_SCHEMA])


# ROLES_SCHEMA is simply a dictionary of role metadata for any of the types of
# TUF roles.
# This is used for RoleDB.  RoleDB stores role metadata in memory, to manipulate
# and use before updating a client's metadata or writing new metadata.  It
# takes the form of a dictionary containing a ROLES_SCHEMA for each repository
# RoleDB stores metadata from.  ROLES_SCHEMA is simply a mapping from rolename
# to the role metadata for that role.
ROLES_SCHEMA = SCHEMA.DictOf(
    key_schema = ROLENAME_SCHEMA,
    value_schema = ANYROLE_SCHEMA)

# TODO: This probably doesn't need to exist.
# The format of the resulting "scp config dict" after extraction from the
# push configuration file (i.e., push.cfg).  In the case of a config file
# utilizing the scp transfer module, it must contain the 'general' and 'scp'
# sections, where 'general' must contain a 'transfer_module' and
# 'metadata_path' entry, and 'scp' the 'host', 'user', 'identity_file', and
# 'remote_directory' entries.
SCPCONFIG_SCHEMA = SCHEMA.Object(
  object_name = 'SCPCONFIG_SCHEMA',
  general = SCHEMA.Object(
    object_name = '[general]',
    transfer_module = SCHEMA.String('scp'),
    metadata_path = securesystemslib.formats.PATH_SCHEMA,
    targets_directory = securesystemslib.formats.PATH_SCHEMA),
  scp=SCHEMA.Object(
    object_name = '[scp]',
    host = securesystemslib.formats.URL_SCHEMA,
    user = securesystemslib.formats.NAME_SCHEMA,
    identity_file = securesystemslib.formats.PATH_SCHEMA,
    remote_directory = securesystemslib.formats.PATH_SCHEMA))

# The format of the resulting "receive config dict" after extraction from the
# receive configuration file (i.e., receive.cfg).  The receive config file
# must contain a 'general' section, and this section the 'pushroots',
# 'repository_directory', 'metadata_directory', 'targets_directory', and
# 'backup_directory' entries.
RECEIVECONFIG_SCHEMA = SCHEMA.Object(
  object_name = 'RECEIVECONFIG_SCHEMA', general=SCHEMA.Object(
    object_name = '[general]',
    pushroots = SCHEMA.ListOf(securesystemslib.formats.PATH_SCHEMA),
    repository_directory = securesystemslib.formats.PATH_SCHEMA,
    metadata_directory = securesystemslib.formats.PATH_SCHEMA,
    targets_directory = securesystemslib.formats.PATH_SCHEMA,
    backup_directory = securesystemslib.formats.PATH_SCHEMA))



def make_signable(obj):
  """
  <Purpose>
    Returns a signable envelope dictionary around the given object.
    If obj is already a signable dictionary, return that dictionary unchanged.

    # TODO: The if-it's-already-a-signable-just-return-that behavior is bad.
    #       Kill it.  You want predictable behavior from your functions.  If
    #       your code does something that should happen once twice, something
    #       is wrong and you want it to break immediately, not at some weird
    #       point in the future.  I'm not fixing this right now because there
    #       are already enough things this might break and I don't want to
    #       complicate debugging just yet, but this has to be fixed, so TODO.

    In other words, returns a dictionary conforming to SIGNABLE_SCHEMA, of the
    form:
      {
        'signatures': [],
        'signed': obj
      }

    The resulting dictionary can then be signed, adding signature objects
    conforming to securesystemslib.formats.SIGNATURE_SCHEMA to the 'signatures'
    field's list.

    Note: check_signable_object_format() should be called after
    make_signable(), as well as after adding signatures, to ensure that the
    final signable object has a valid format.

  <Arguments>
    obj:
      While this was written to produce signable envelops around role metadata
      dictionaries, this function supports any object (though those objects
      should be serializable in order to be signed and for those signatures to
      later be verified).

  <Exceptions>
    None.

  <Side Effects>
    None.

  <Returns>
    A dictionary conforming to securesystemslib.formats.SIGNABLE_SCHEMA.
  """

  if isinstance(object, dict) and 'signed' in object and 'signatures' in object:
    # This is bad.
    return object

  return { 'signed' : object, 'signatures' : [] }





def build_dict_conforming_to_schema(schema, **kwargs):
  """
  <Purpose>
    Given a schema.Object object (for example, TIMESTAMP_SCHEMA from this
    module) and a set of keyword arguments, create a dictionary that conforms
    to the given schema, using the keyword arguments to define the elements of
    the new dict.

    Checks the result to make sure that it conforms to the given schema, raising
    an error if not.

  <Arguments>
    schema
      A schema.Object, like TIMESTAMP_SCHEMA, FILEINFO_SCHEMA,
      securesystemslib.formats.SIGNATURE_SCHEMA, etc.

    **kwargs
      A keyword argument for each element of the schema.  Optional arguments
      may be included or skipped, but all required arguments must be included.

      For example, for TIMESTAMP_SCHEMA, a call might look like:
        build_dict_conforming_to_schema(
            TIMESTAMP_SCHEMA,
            _type='timestamp',
            spec_version='1.0',
            version=1,
            expires='2020-01-01T00:00:00Z',
            meta={...})
      Some arguments will be filled in if excluded: _type, spec_version

  <Returns>
    A dictionary conforming to the given schema.  Adds certain required fields
    if they are missing and can be deduced from the schema.  The data returned
    is a deep copy.

  <Exceptions>
    securesystemslib.exceptions.FormatError
      if the provided data does not match the schema when assembled.

  <Side Effects>
    None.  In particular, the provided values are not modified, and the
    returned dictionary does not include references to them.

  """

  # Check the schema argument type (must provide check_match and _required).
  if not isinstance(schema, SCHEMA.Object):
    raise ValueError(
        'The first argument must be a schema.Object instance, but is not. '
        'Given schema: ' + repr(schema))

  # Make a copy of the provided fields so that the caller's provided values
  # do not change when the returned values are changed.
  dictionary = copy.deepcopy(kwargs)


  # Automatically provide certain schema properties if they are not already
  # provided and are required in objects of class <schema>.
  # This includes:
  #   _type:        <securesystemslib.schema.String object>
  #   spec_version: SPECIFICATION_VERSION_SCHEMA
  #
  # (Please note that _required is slightly misleading, as it includes both
  #  required and optional elements. It should probably be called _components.)
  #
  for key, element_type in schema._required: #pylint: disable=protected-access

    if key in dictionary:
      # If the field has been provided, proceed normally.
      continue

    elif isinstance(element_type, SCHEMA.Optional):
      # If the field has NOT been provided but IS optional, proceed without it.
      continue

    else:
      # If the field has not been provided and is required, check to see if
      # the field is one of the fields we automatically fill.

      # Currently, the list is limited to ['_type', 'spec_version'].

      if key == '_type' and isinstance(element_type, SCHEMA.String):
        # A SCHEMA.String stores its expected value in _string, so use that.
        dictionary[key] = element_type._string #pylint: disable=protected-access

      elif (key == 'spec_version' and
          element_type == SPECIFICATION_VERSION_SCHEMA):
        # If not provided, use the specification version in tuf/__init__.py
        dictionary[key] = tuf.SPECIFICATION_VERSION


  # If what we produce does not match the provided schema, raise a FormatError.
  schema.check_match(dictionary)

  return dictionary





# A dict holding the recognized schemas for the top-level roles.
SCHEMAS_BY_TYPE = {
  'root' : ROOT_SCHEMA,
  'targets' : TARGETS_SCHEMA,
  'snapshot' : SNAPSHOT_SCHEMA,
  'timestamp' : TIMESTAMP_SCHEMA,
  'mirrors' : MIRRORLIST_SCHEMA}



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
    securesystemslib.exceptions.FormatError, if 'datetime_object' is not a
    datetime.datetime() object.

  <Side Effects>
    None.

  <Returns>
    A unix (posix) timestamp (e.g., 499137660).
  """

  # Is 'datetime_object' a datetime.datetime() object?
  # Raise 'securesystemslib.exceptions.FormatError' if not.
  if not isinstance(datetime_object, datetime.datetime):
    message = repr(datetime_object) + ' is not a datetime.datetime() object.'
    raise securesystemslib.exceptions.FormatError(message)

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
      'securesystemslib.formats.UNIX_TIMESTAMP_SCHEMA'.

  <Exceptions>
    securesystemslib.exceptions.FormatError, if 'unix_timestamp' is improperly
    formatted.

  <Side Effects>
    None.

  <Returns>
    A datetime.datetime() object corresponding to 'unix_timestamp'.
  """

  # Is 'unix_timestamp' properly formatted?
  # Raise 'securesystemslib.exceptions.FormatError' if there is a mismatch.
  securesystemslib.formats.UNIX_TIMESTAMP_SCHEMA.check_match(unix_timestamp)

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
    securesystemslib.exceptions.FormatError, if the base64 encoding fails or the
    argument is invalid.

  <Side Effects>
    None.

  <Returns>
    A base64-encoded string.
  """

  try:
    return binascii.b2a_base64(data).decode('utf-8').rstrip('=\n ')

  except (TypeError, binascii.Error) as e:
    raise securesystemslib.exceptions.FormatError('Invalid base64'
      ' encoding: ' + str(e))




def parse_base64(base64_string):
  """
  <Purpose>
    Parse a base64 encoding with whitespace and '=' signs omitted.

  <Arguments>
    base64_string:
      A string holding a base64 value.

  <Exceptions>
    securesystemslib.exceptions.FormatError, if 'base64_string' cannot be parsed
    due to an invalid base64 encoding.

  <Side Effects>
    None.

  <Returns>
    A byte string representing the parsed based64 encoding of
    'base64_string'.
  """

  if not isinstance(base64_string, six.string_types):
    message = 'Invalid argument: '+repr(base64_string)
    raise securesystemslib.exceptions.FormatError(message)

  extra = len(base64_string) % 4
  if extra:
    padding = '=' * (4 - extra)
    base64_string = base64_string + padding

  try:
    return binascii.a2b_base64(base64_string.encode('utf-8'))

  except (TypeError, binascii.Error) as e:
    raise securesystemslib.exceptions.FormatError('Invalid base64'
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
    securesystemslib.exceptions.FormatError, if the 'FILEINFO_SCHEMA' to be
    returned does not have the correct format.

  <Side Effects>
    If any of the arguments are incorrectly formatted, the dict
    returned will be checked for formatting errors, and if found,
    will raise a 'securesystemslib.exceptions.FormatError' exception.

  <Returns>
    A dictionary conformant to 'FILEINFO_SCHEMA', representing the file
    information of a metadata or target file.
  """

  fileinfo = {'length' : length, 'hashes' : hashes}

  if version is not None:
    fileinfo['version'] = version

  if custom is not None:
    fileinfo['custom'] = custom

  # Raise 'securesystemslib.exceptions.FormatError' if the check fails.
  securesystemslib.formats.FILEINFO_SCHEMA.check_match(fileinfo)

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
    securesystemslib.exceptions.FormatError, if the dict to be returned does not
    have the correct format (i.e., VERSIONINFO_SCHEMA).

  <Side Effects>
    None.

  <Returns>
    A dictionary conformant to 'VERSIONINFO_SCHEMA', containing the version
    information of a metadata role.
  """

  versioninfo = {'version': version_number}

  # Raise 'securesystemslib.exceptions.FormatError' if 'versioninfo' is
  # improperly formatted.
  securesystemslib.formats.VERSIONINFO_SCHEMA.check_match(versioninfo)

  return versioninfo





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
    securesystemslib.exceptions.FormatError, if 'meta_rolename' is improperly
    formatted.

  <Side Effects>
    None.

  <Returns>
    A string (e.g., 'Root', 'Targets').
  """

  # Does 'meta_rolename' have the correct type?
  # This check ensures 'meta_rolename' conforms to
  # 'securesystemslib.formats.NAME_SCHEMA'.
  # Raise 'securesystemslib.exceptions.FormatError' if there is a mismatch.
  securesystemslib.formats.NAME_SCHEMA.check_match(meta_rolename)

  return meta_rolename.lower()



def check_signable_object_format(signable):
  """
  <Purpose>
    Ensure 'signable' is properly formatted, conformant to
    'SIGNABLE_SCHEMA'.  Return the signing role on
    success.  Note: The 'signed' field of a 'SIGNABLE_SCHEMA' is checked
    against securesystemslib.schema.Any().  The 'signed' field, however, should
    actually hold one of the supported role schemas (e.g., 'ROOT_SCHEMA',
    'TARGETS_SCHEMA').  The role schemas all differ in their format, so this
    function determines exactly which schema is listed in the 'signed' field.

  <Arguments>
    signable:
     The signable object compared against 'SIGNABLE.SCHEMA'.

  <Exceptions>
    securesystemslib.exceptions.FormatError, if 'signable' does not have the
    correct format.

  <Side Effects>
    None.

  <Returns>
    A string representing the signing role (e.g., 'root', 'targets').
    The role string is returned with characters all lower case.
  """

  # Does 'signable' have the correct type?
  # This check ensures 'signable' conforms to
  # 'SIGNABLE_SCHEMA'.
  SIGNABLE_SCHEMA.check_match(signable)

  try:
    role_type = signable['signed']['_type']

  except (KeyError, TypeError):
    raise securesystemslib.exceptions.FormatError('Untyped signable object.')

  try:
    schema = SCHEMAS_BY_TYPE[role_type]

  except KeyError:
    raise securesystemslib.exceptions.FormatError('Unrecognized'
      ' type ' + repr(role_type))

  # 'securesystemslib.exceptions.FormatError' raised if 'signable' does not
  # have a properly formatted role schema.
  schema.check_match(signable['signed'])

  return role_type.lower()



if __name__ == '__main__':
  # The interactive sessions of the documentation strings can
  # be tested by running formats.py as a standalone module.
  # python -B formats.py
  import doctest
  doctest.testmod()
