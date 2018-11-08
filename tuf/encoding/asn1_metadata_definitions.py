#!/usr/bin/env python
"""
<Program>
  asn1_metadata_definitions.py

<Copyright>
  See LICENSE-MIT or LICENSE for licensing information.

<Purpose>
  These are the asn1crypto-compatible ASN.1 definitions for TUF metadata.
  Please also see tuf_metadata_definitions.asn1

  When changes are made to these metadata definitions, they should also be made
  to tuf_metadata_definitions.asn1 (and vice versa).

  When modifying the two files, it is important to take care to keep them
  consistent with each other.  This does not affect the implementation itself,
  but tuf_metadata_definitions.asn1 is the more abstract file that implementers
  using other languages may use for compatibility.

  It is not yet clear to me how to limit values in asn1crypto in the way that
  you can in pyasn1 using ValueRangeConstraint. For thresholds, versions,
  timestamps, etc., we want only non-negative integers.

  On list-like dictionaries:
    A systematic modification to the structure of the data was necessary to
    translate list-like dictionaries from the TUF-internal format to ASN.1.  A
    list-like dictionary is a dictionary in which the keys are unpredictable.
    This is as opposed to a struct-like dictionary, where the structure is
    knowable in advance.  Note that because ASN.1 does not support
    dictionaries, definitions introduce additional layers where the TUF spec
    uses a list-like dictionary, with the additional layer being a list
    containing key-value pairs. For example, see RoleLongInfoContainers in
    Timestamp metadata, or Hashes. Look for _from_listlike_dict below for more
    examples.
"""

import asn1crypto.core as ac


# Common types, for use in the various metadata types

# Normally, one would use SequenceOf in place, rather than define a class
# for each type of SequenceOf that we want to use, but, for now, the way we
# parse these definitions chokes on those sorts of definitions, so we'll just
# create a class for each type of SequenceOf we need.
class OctetStrings(ac.SequenceOf):  # Hopefully temporary
  _child_spec = ac.OctetString
class VisibleStrings(ac.SequenceOf): # Hopefully temporary
  _child_spec = ac.VisibleString



class Signature(ac.Sequence):
  _fields = [
      ('keyid', ac.OctetString),
      ('sig', ac.OctetString)]


class Signatures(ac.SequenceOf):
  _child_spec = Signature


class Hash(ac.Sequence):
  """
  Conceptual ASN.1 structure (Python pseudocode):
      {'function': 'sha256', 'digest': '...'}      # additional layer (was list-like dict)
  Equivalent TUF-internal JSON-compatible metadata:
      'sha256': '...'                              # entry in a list-like dict
  """
  _fields = [
      ('function', ac.VisibleString),
      ('digest', ac.OctetString)]



class Hashes(ac.SetOf):
  """
  List of Hash objects.
  Conceptual ASN.1 structure (Python pseudocode):
      [ {'function': 'sha256', 'digest': '...'},    # additional layer (was list-like dict)
        {'function': 'sha512', 'digest': '...'} ]   # additional layer (was list-like dict)
  Equivalent TUF-internal JSON-compatible metadata:
      {'sha256': '...', 'sha512': '...'}            # list-like dict
  """
  _child_spec = Hash

  # Hack to preserve information about structure of original non-ASN.1 data.
  # This notes that this type is converted from a list-like dictionary, not a
  # list or a struct-like dictionary, and so the individual elements had to be
  # altered structurally (each key becomes the first field in the element, and
  # each value becomes the second). This is because ASN.1 does not directly
  # support dictionaries. This field is checked to decide if that magic should
  # be undone, converting         {'key': key, 'value': value}
  # back into                     {key: value}.
  # For more, see comments at the top of this module regarding list-like dicts.
  _from_listlike_dict = True



# Hopefully temporary: swap in content itself in class Key?
class KeyValues(ac.Sequence):
  # Note that if this subclasses Set instead Sequence and 'private' is optional,
  # strange issues arise.  There might be a bug in asn1crypto related to this.
  _fields = [
      ('public', ac.VisibleString),
      ('private', ac.VisibleString, {'optional': True})]

# Could instead maintain KeyValues as a list-like dict for more flexibility,
# but note that that requires both of these classes to be defined, and list-like
# dict conversion is a little clunky.
# class KeyValues(ac.SequenceOf):
#   _child_spec = KeyValue
#   _from_listlike_dict = True
# class KeyValue(ac.Sequence):
#   _fields = [
#       ('type', ac.VisibleString),
#       ('value', ac.VisibleString)] #ac.OctetString)]



# Public Keys are stored in two slightly different formats.
# When we're dealing with the key itself (e.g. when it's imported from disk),
# the format matches Key.
# When we're listing the key information in Root or Targets metadata,
# the format matches HashIndexedKey.
class Key(ac.Sequence):
  _fields = [
      ('keyid', ac.OctetString),
      ('keytype', ac.VisibleString),
      ('scheme', ac.VisibleString),
      # Currently, we don't dynamically create types (using the type()
      # function with three arguments), and in the recursion, we need every
      # level to have established properties.  So instead of using the
      # third parameter here like this:
      #  ('keyval', ac.SetOf, {'_child_spec': KeyValue}),
      # we're going to instead define a class for lists of KeyValue objects
      # and another for lists of VisibleString objects.
      ('keyval', KeyValues),
      ('keyid-hash-algorithms', VisibleStrings)]

class Keys(ac.SequenceOf):      # Hopefully temporary
  _child_spec = Key



class KeyWithoutID(ac.Sequence):
  """

  """
  _fields = [
      ('keytype', ac.VisibleString),
      ('scheme', ac.VisibleString),
      # Currently, we don't dynamically create types (using the type()
      # function with three arguments), and in the recursion, we need every
      # level to have established properties.  So instead of using the
      # third parameter here like this:
      #  ('keyval', ac.SetOf, {'_child_spec': KeyValue}),
      # we're going to instead define a class for these things:
      ('keyval', KeyValues),
      ('keyid-hash-algorithms', VisibleStrings)]



class HashIndexedKey(ac.Sequence):
  """
  Conceptual ASN.1 structure (Python pseudocode):
      {'keyid': '1234...', 'keyinfo': {...}}    # additional layer (was list-like dict)
  Equivalent TUF-internal JSON-compatible metadata:
      '1234...': {...}                          # entry in a list-like dict
  """
  _fields = [
      ('keyid', ac.OctetString),
      ('keyinfo', KeyWithoutID)]



class HashIndexedKeys(ac.SequenceOf):
  """
  Conceptual ASN.1 structure (Python pseudocode):
      [                                 # additional layer (was list-like dict)
        {'keyid': '1234...', 'keyinfo': {...}},
        {'keyid': '5678...', 'keyinfo': {...}},
        ...
      ]
  Equivalent TUF-internal JSON-compatible metadata:
      {                                             # list-like dict
        '1234...': {...},
        '5678...': {...},
        ...
      }
  """
  _child_spec = HashIndexedKey
  _from_listlike_dict = True





## Types used only in Root metadata
class KeyIDsAndThreshold(ac.Sequence): # # TODO: This name is awful.
  _fields = [
      # Currently, we don't dynamically create types (using the type()
      # function with three arguments), and in the recursion, we need every
      # level to have established properties.  So instead of using the
      # third parameter here like this:
      #  ('keyids', ac.SequenceOf, {'_child_spec': ac.OctetString}),
      # we're going to instead define a class for a list of OctetString objects.
      ('keyids', OctetStrings),
      ('threshold', ac.Integer)]


# For some reason, if TopLevelDelegations is a Set, then it fails to decode
# from DER back to ASN.1....  I don't understand why.
class TopLevelDelegations(ac.Sequence):
  _fields = [
      ('root', KeyIDsAndThreshold),
      ('timestamp', KeyIDsAndThreshold),
      ('snapshot', KeyIDsAndThreshold),
      ('targets', KeyIDsAndThreshold)]

  # Or could make this a SequenceOf, and use a list-like delegation:
  # _child_spec = TopLevelDelegation
  # _from_listlike_dict = True
  # And then use this definition for the intermediate layer:
  # class TopLevelDelegation(ac.Sequence):
  #   _fields = [
  #       ('role', ac.VisibleString),
  #       ('keyids-and-threshold', KeyIDsAndThreshold)]


class RootMetadata(ac.Sequence):
  _fields = [
      ('_type', ac.VisibleString),
      ('spec_version', ac.VisibleString),
      ('expires', ac.VisibleString),
      ('version', ac.Integer),
      ('consistent-snapshot', ac.Boolean),
      ('keys', HashIndexedKeys),
      # Currently, we don't dynamically create types (using the type()
      # function with three arguments), and in the recursion, we need every
      # level to have established properties.  So instead of using the
      # third parameter here like this:
      #  ('roles', ac.SetOf, {'_child_spec': TopLevelDelegation})]
      # we're going to instead define a class for these things:
      ('roles', TopLevelDelegations)]





## Types used only in Timestamp metadata
class RoleLongInfo(ac.Sequence):
  """
  Information about a role, including its hash, length, and version.  This is
  how Timestamp currently lists metadata about Snapshot in order to allow
  clients to check their Snapshot file.

  Conceptual ASN.1 structure (Python pseudocode):
      {'hashes': [
        {'function': 'sha256', 'digest': '...'},
        {'function': 'sha512', 'digest': '...'}
      ],
       'length': 50,
       'version': 3}
  Equivalent TUF-internal JSON-compatible metadata:
      {'hashes': {'sha256': '...', 'sha512': '...'}
       'length': 50,
       'version': 3}
  """
  _fields = [
      ('hashes', Hashes),
      ('length', ac.Integer),
      ('version', ac.Integer)]



class RoleLongInfoContainer(ac.Sequence):
  """
  Conceptual ASN.1 structure (Python pseudocode):
      {
        'filename': 'snapshot.json',    # additional layer (was list-like dict)
        'roleinfo': {                   # additional layer (was list-like dict)
          'length': 61,
          'version': 1,
          'hashes': [
            {'function': 'sha256', 'digest': '...'},    # additional layer (was list-like dict)
            {'function': 'sha512', 'digest': '...'}     # additional layer (was list-like dict)
          ]
        }
      }
  Equivalent TUF-internal JSON-compatible metadata:
      'snapshot.json': {                       # entry in a list-like dict
        "hashes": {
          'sha256': '...', 'sha512': '...'     # list-like dict
        }
      }

  See comments at the top of this module regarding list-like dictionaries.
  """
  _fields = [
      ('filename', ac.VisibleString),
      ('roleinfo', RoleLongInfo)]



class RoleLongInfoContainers(ac.SetOf):
  """
  Conceptual ASN.1 structure (Python pseudocode):
      [
        {
          'filename': 'snapshot.json',        # additional layer (was list-like dict)
          'roleinfo': {                       # additional layer (was list-like dict)
            'length': 61,
            'version': 1,
            'hashes': [
              {'function': 'sha256', 'digest': '...'},  # additional layer (was list-like dict)
              {'function': 'sha512', 'digest': '...'}.  # additional layer (was list-like dict)
            ]
          }
        },
        <no other values expected>
      ]
  Equivalent TUF-internal JSON-compatible metadata:
      {                                                  # list-like dict
        'snapshot.json': {
          'version': 1,
          'hashes': {'sha256': '...', 'sha512': '...'}}  # list-like dict
        },
        <no other values expected>
      }
  """
  _child_spec = RoleLongInfoContainer
  _from_listlike_dict = True


class TimestampMetadata(ac.Sequence):
  _fields = [
      ('_type', ac.VisibleString),
      ('spec_version', ac.VisibleString),
      ('expires', ac.VisibleString),
      ('version', ac.Integer),
      ('meta', RoleLongInfoContainers)] #ac.SetOf, {'_child_spec': RoleLongInfoContainer})]




## Types used only in Snapshot metadata
class RoleShortInfo(ac.Sequence):
  """
  Information about what the current version number of a single Targets or
  delegated Targets role (or Root role, if pre-TAP5). This is how Snapshot
  lists metadata about Targets, delegated Targets, and sometimes Root, in order
  to allow clients to check that their Targets files were present together on a
  valid repository at the same time, overcoming some mix-and-match attacks.

  Conceptual ASN.1 structure (Python pseudocode):
      {'version: 3}
  Equivalent TUF-internal JSON-compatible metadata:
      {'version': 3}
  """
  _fields = [
      ('version', ac.Integer)]



class RoleShortInfoContainer(ac.Sequence):
  """
  This layer is a result of some redundancy in the TUF metadata specification.
  Snapshot lists entries like " targets.json': {'version': 1} " in dictionary
  'meta' instead of entries like: " targets.json': 1 "
  Conceptual ASN.1 structure (Python pseudocode):
      {
        'filename': 'targets.json',    # additional layer (was list-like dict)
        'roleinfo': {                  # additional layer (was list-like dict)
          'version': 1,
        }
      }
  Equivalent TUF-internal JSON-compatible metadata:
      'targets.json': {'version': 1}         # entry in a list-like dict

  See comments at the top of this module regarding list-like dictionaries.
  """
  _fields = [
      ('filename', ac.VisibleString),
      ('roleinfo', RoleShortInfo)]



class RoleShortInfoContainers(ac.SequenceOf):
  """
  Information about what the current version number of all Targets and
  delegated Targets roles should be.
  This is how Snapshot currently lists metadata about all Targets roles in
  order to enable clients to know if role metadata they receive is not current
  or should not be concurrent with the given snapshot file on the repository.

  Conceptual ASN.1 structure (Python pseudocode):
      [
        {'filename': 'role1.json',   {'version': 3}},
        {'filename': 'role2.json',   {'version': 5}},
        {'filename': 'targets.json', {'version': 3}}
      ]
  Equivalent TUF-internal JSON-compatible metadata:
      {
        'role1.json':   {'version': 3},
        'role2.json':   {'version': 5},
        'targets.json': {'version': 3}
      }
  """
  _child_spec = RoleShortInfoContainer
  _from_listlike_dict = True



class SnapshotMetadata(ac.Sequence):
  _fields = [
      ('_type', ac.VisibleString),
      ('spec_version', ac.VisibleString),
      ('expires', ac.VisibleString),
      ('version', ac.Integer),
      # Currently, we don't dynamically create types (using the type()
      # function with three arguments), and in the recursion, we need every
      # level to have established properties.  So instead of using the using
      # the optional third parameter for each component like this:
      #  ('meta', ac.SetOf, {'_child_spec': RoleVersion})]
      # we instead defined a separate class for a list of RoleVersion objects.
      ('meta', RoleShortInfoContainers)]





## Types used only in Targets (and delegated targets) metadata
class Delegation(ac.Sequence):
  _fields = [
      ('name', ac.VisibleString),
      # Currently, we don't dynamically create types (using the type()
      # function with three arguments), and in the recursion, we need every
      # level to have established properties.  So instead of using the using
      # the optional third parameter for each component like this:
      #  ('keyids', ac.SequenceOf, {'_child_spec': ac.OctetString}),
      #  ('paths', ac.SequenceOf, {'_child_spec': ac.VisibleString}),
      # we instead defined separate classes for lists of OctetString and
      # VisibleString objects.
      ('keyids', OctetStrings),
      ('paths', VisibleStrings),
      ('threshold', ac.Integer),
      ('terminating', ac.Boolean, {'default': False})]

# Hopefully temporary
class Delegations(ac.SequenceOf):
  _child_spec = Delegation

class Custom(ac.Sequence):
  _fields = [
      ('key', ac.VisibleString),
      ('value', ac.VisibleString)]


class Customs(ac.SequenceOf):
  _child_spec = Custom
  _from_listlike_dict = True


class TargetInfo(ac.Sequence):
  _fields = [
      ('length', ac.Integer),
      ('hashes', Hashes),
      # Currently, we don't dynamically create types (using the type()
      # function with three arguments), and in the recursion, we need every
      # level to have established properties.  So instead of using the using
      # the optional third parameter for each component like this:
      #  ('custom', ac.SetOf, {'_child_spec': Custom, 'optional': True})]
      # we instead defined a separate class for a list of Custom objects:
      ('custom', Customs, {'optional': True})]


class Target(ac.Sequence):
  _fields = [
      ('target-name', ac.VisibleString),
      ('target-info', TargetInfo)]


class Targets(ac.SequenceOf):
  _child_spec = Target
  _from_listlike_dict = True


# Hopefully temporary
class DelegationSection(ac.Sequence):
  _fields = [
      # Currently, we don't dynamically create types (using the type()
      # function with three arguments), and in the recursion, we need every
      # level to have established properties.  So instead of using the using
      # the optional third parameter for each component like this:
      # ('keys', ac.SequenceOf, {'_child_spec': Key}),
      # ('roles', ac.SequenceOf, {'_child_spec': Delegation})]
      # we instead defined separate classes for lists of Key and Delegation
      # objects.
      ('keys', HashIndexedKeys),
      ('roles', Delegations)]


class TargetsMetadata(ac.Sequence):
  _fields = [
      ('_type', ac.VisibleString),
      ('spec_version', ac.VisibleString),
      ('expires', ac.VisibleString),
      ('version', ac.Integer),
      # Currently, we don't dynamically create types (using the type()
      # function with three arguments), and in the recursion, we need every
      # level to have established properties.  So instead of using the using
      # the optional third parameter for each component like this:
      # ('targets', ac.SetOf, {'_child_spec': Target}),
      # ('delegations', ac.Sequence, {'_fields': [
      #     ('keys', ac.SetOf, {'_child_spec': Key}),
      #     ('roles', ac.SequenceOf, {'_child_spec': Delegation})]})]
      # we instead defined separate classes for lists of Target objects and the
      # Delegation section.

      # we're going to instead define a class for these things:
      ('targets', Targets),
      ('delegations', DelegationSection)]




# Keeping these four class definitions together for the moment while I
# contemplate this paradigm, but will later distribute them to their
# corresponding sections above.
class RootEnvelope(ac.Sequence):
  _fields = [
      ('signatures', Signatures),
      ('signed', RootMetadata)]

class TimestampEnvelope(ac.Sequence):
  _fields = [
      ('signatures', Signatures),
      ('signed', TimestampMetadata)]

class SnapshotEnvelope(ac.Sequence):
  _fields = [
      ('signatures', Signatures),
      ('signed', SnapshotMetadata)]

class TargetsEnvelope(ac.Sequence):
  _fields = [
      ('signatures', Signatures),
      ('signed', TargetsMetadata)]






# # Or we could define the following, instead of the above four Envelope classes.
#
# class AnyMetadata(ac.Choice):
#   _alternatives = [
#       ('root', RootMetadata),
#       ('timestamp', TimestampMetadata),
#       ('snapshot', SnapshotMetadata),
#       ('targets', TargetsMetadata)]
#
# class SignableEnvelope(ac.Sequence):
#   _fields = [
#       ('signatures', Signatures),
#       ('signed', AnyMetadata)]
