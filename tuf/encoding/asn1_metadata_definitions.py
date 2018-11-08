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

  It is not yet clear to me how to bound values in asn1crypto in the way that
  you can in pyasn1 using ValueRangeConstraint. For thresholds, versions,
  timestamps, etc., we want only non-negative integers.
"""

import asn1crypto.core as ac
# from asn1crypto.core import \
#     Sequence, SequenceOf, Set, SetOf, Integer, OctetString, IA5String


# Common types, for use in the various metadata types

# Normally, one would use SequenceOf in place, rather than define a class
# for each type of SequenceOf that we want to use, but, for now, the way we
# parse these definitions chokes on those sorts of definitions, so we'll just
# create a class for each type of SequenceOf we need.
class OctetStrings(ac.SequenceOf):  # Hopefully temporary
  _child_spec = ac.OctetString
class VisibleStrings(ac.SequenceOf): # Hopefully temporary

# Not supported?
# class IntegerNatural(ac.Integer):
#   subtypeSpec = constraint.ValueRangeConstraint(0, MAX) # 0 <= value <= MAX

class Signature(ac.Sequence):
  _fields = [
      ('keyid', ac.OctetString),
      ('method', ac.VisibleString),
      ('value', ac.OctetString)]

class Hash(ac.Sequence):
  """
  Conceptual ASN.1 structure (Python pseudocode):
      {'function': 'sha256', 'digest': '...'}
  Equivalent TUF-internal JSON-compatible metadata:
      {'sha256': '...'}
  """
  _fields = [
      ('function', ac.VisibleString),
      ('digest', ac.OctetString)]

# TEMPORARY, FOR DEBUGGING ONLY; DO NOT MERGE
class Hashes(ac.SetOf):
  """
  List of Hash objects.
  Conceptual ASN.1 structure (Python pseudocode):
      [ {'function': 'sha256', 'digest': '...'},
        {'function': 'sha512', 'digest': '...'} ]
  Equivalent TUF-internal JSON-compatible metadata:
      {'sha256': '...', 'sha512': '...'}
  """
  _child_spec = Hash


# TEMPORARY: swap in content itself in class PublicKey
class KeyIDHashAlgorithms(ac.SequenceOf):
  _child_spec = ac.VisibleString


# Hopefully temporary: swap in content itself in class Key?
class KeyValues(ac.Sequence):
  # Note that if this subclasses Set instead Sequence and 'private' is optional,
  # strange issues arise.  There might be a bug in asn1crypto related to this.
  _fields = [
      ('public', ac.VisibleString)] #ac.OctetString)]

class PublicKey(ac.Sequence):
  _fields = [
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



## Types used only in Root metadata
class TopLevelDelegation(ac.Sequence):
  _fields = [
      ('role', ac.VisibleString),
      ('keyids', ac.SequenceOf, {'_child_spec': ac.OctetString}),
      ('threshold', ac.Integer)]

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
class HashesContainer(ac.Sequence):
  """
  Single-element, vapid wrapper for Hashes, solely to match structure of the
  TUF-internal metadata. (This layer could be removed from both metadata
  formats to result in a clearer definition without change to the implicit
  semantics, but would break backward compatibility.)
  Conceptual ASN.1 structure (Python pseudocode):
      {'hashes': [
        {'function': 'sha256', 'digest': '...'},
        {'function': 'sha512', 'digest': '...'}
      ]}
  Equivalent TUF-internal JSON-compatible metadata:
      {'hashes': {'sha256': '...', 'sha512': '...'}}
  """
  _fields = [
      ('hashes', Hashes)]



class HashOfSnapshot(ac.Sequence):
  """
  Conceptual ASN.1 structure (Python pseudocode): {
      'filename': 'snapshot.json',
      'hashes': [
          {'function': 'sha256', 'digest': '...'},
          {'function': 'sha512', 'digest': '...'}
      ]
  }
  Equivalent TUF-internal JSON-compatible metadata: {
      'snapshot.json': { "hashes": {'sha256': '...', 'sha512': '...'}}
  """
  _fields = [
      ('filename', ac.VisibleString),
      ('hashes', HashesContainer)]

class HashesOfSnapshot(ac.SetOf):
  """
  Conceptual ASN.1 structure (Python pseudocode):
      [ {'filename': 'snapshot.json',
         'hashes': [
           {'function': 'sha256', 'digest': '...'},
           {'function': 'sha512', 'digest': '...'}
         ]},
        <no other values expected>
      ]
  Equivalent TUF-internal JSON-compatible metadata:
      {'snapshot.json': { "hashes": {'sha256': '...', 'sha512': '...'}},
        <no other values expected>
      }
  """
  _child_spec = HashOfSnapshot

class TimestampMetadata(ac.Sequence):
  _fields = [
      ('_type', ac.VisibleString),
      ('spec_version', ac.VisibleString),
      ('expires', ac.VisibleString),
      ('version', ac.Integer),
      ('meta', ac.SetOf, {'_child_spec': HashOfSnapshot})]


## Types used only in Snapshot metadata
class RoleInfo(ac.Sequence):
  _fields = [
      ('filename', ac.VisibleString),
      ('version', ac.Integer)]

class SnapshotMetadata(ac.Sequence):
  _fields = [
      ('_type', ac.VisibleString),
      ('spec_version', ac.VisibleString),
      ('expires', ac.VisibleString),
      ('version', ac.Integer),
      ('meta', ac.SetOf, {'_child_spec': RoleInfo})]




## Types used only in Targets (and delegated targets) metadata
class Delegation(ac.Sequence):
  _fields = [
      ('name', ac.VisibleString),
      ('keyids', ac.SequenceOf, {'_child_spec': ac.OctetString}),
      ('paths', ac.SequenceOf, {'_child_spec': ac.VisibleString}),
      ('threshold', ac.Integer),
      ('terminating', ac.Boolean, {'default': False})]

class Custom(ac.Sequence):
  _fields = [
      ('key', ac.VisibleString),
      ('value', ac.VisibleString)]

class Target(ac.Sequence):
  _fields = [
      ('target-name', ac.VisibleString),
      ('length', ac.Integer),
      ('hashes', ac.SetOf, {'_child_spec': Hash}),
      ('custom', ac.SetOf, {'_child_spec': Custom, 'optional': True})]

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
