"""
<Name>
  tuf/encoding/targets_asn1_coder.py

<Purpose>
  This module contains conversion functions (get_asn_signed and get_json_signed)
  for converting Targets role metadata to and from TUF's standard
  Python dictionary metadata format (usually serialized as JSON) and an ASN.1
  format that conforms to pyasn1 specifications and Uptane's ASN.1 definitions.

<Functions>
  get_asn_signed(pydict_signed)
  get_json_signed(asn_signed)

"""
from __future__ import unicode_literals

from pyasn1.type import univ, tag

from tuf.encoding.metadata_asn1_definitions import *

import calendar
from datetime import datetime #import datetime


def get_asn_signed(json_signed):
  targetsMetadata = TargetsMetadata()\
                    .subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                 tag.tagFormatConstructed, 1))

  set_asn_targets(json_signed, targetsMetadata)
  set_asn_delegations(json_signed, targetsMetadata)

  signedBody = SignedBody()\
               .subtype(explicitTag=tag.Tag(tag.tagClassContext,
                                            tag.tagFormatConstructed, 3))
  signedBody['targetsMetadata'] = targetsMetadata

  signed = Signed().subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                tag.tagFormatConstructed, 0))
  signed['type'] = int(RoleType('targets'))
  signed['expires'] = calendar.timegm(datetime.strptime(
      json_signed['expires'], "%Y-%m-%dT%H:%M:%SZ").timetuple())
  signed['version'] = json_signed['version']
  signed['body'] = signedBody

  return signed


def get_json_signed(asn_metadata):
  json_signed = {
    '_type': 'Targets',
    'delegations': {
     'keys': {},
     'roles': []
    },
  }

  asn_signed = asn_metadata['signed']
  json_signed['expires'] = datetime.utcfromtimestamp(
    asn_signed['expires']).isoformat()+'Z'
  json_signed['version'] = int(asn_signed['version'])

  targetsMetadata = asn_signed['body']['targetsMetadata']
  set_json_targets(json_signed, targetsMetadata)
  set_json_delegations(json_signed, targetsMetadata)

  return json_signed


def set_asn_delegations(json_signed, targetsMetadata):
  # Optional bit.
  if len(json_signed['delegations']['keys']) > 0 or \
     len(json_signed['delegations']['roles']) > 0:
    delegations = TargetsDelegations()\
                  .subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                               tag.tagFormatSimple, 2))
    set_asn_keys(json_signed, delegations)
    set_asn_roles(json_signed, delegations)
    targetsMetadata['delegations'] = delegations



def set_asn_keys(json_signed, delegations):
  keys = PublicKeys().subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                  tag.tagFormatSimple, 1))
  numberOfKeys = 0

  # Sort first to ensure a deterministic list in ASN.1.
  sorted_keyids = sorted(json_signed['delegations']['keys'])
  for keyid in sorted_keyids:
    keymeta = json_signed['delegations']['keys'][keyid]
    key = PublicKey()

    key['publicKeyid'] = Keyid().subtype(explicitTag=tag.Tag(
        tag.tagClassContext, tag.tagFormatConstructed, 0))
    key['publicKeyid']['octetString'] = univ.OctetString(
        hexValue=keyid).subtype(implicitTag=tag.Tag(tag.tagClassContext,
        tag.tagFormatSimple, 1))

    key['publicKeyType'] = int(PublicKeyType(keymeta['keytype']))
    value = BinaryData().subtype(explicitTag=tag.Tag(tag.tagClassContext,
                                                     tag.tagFormatConstructed,
                                                     2))
    octetString = univ.OctetString(hexValue=keymeta['keyval']['public'])\
                  .subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                               tag.tagFormatSimple, 1))
    value['octetString'] = octetString
    key['publicKeyValue'] = value
    keys[numberOfKeys] = key
    numberOfKeys += 1

  delegations['numberOfKeys'] = numberOfKeys
  delegations['keys'] = keys


def set_asn_roles(json_signed, delegations):
  prioritizedPathsToRoles = \
    PrioritizedPathsToRoles().subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                          tag.tagFormatSimple,
                                                          3))
  numberOfDelegations = 0

  # Sort first to ensure a deterministic list in ASN.1.
  sorted_json_roles = sorted(json_signed['delegations']['roles'])
  for json_role in sorted_json_roles:
    pathsToRoles = PathsToRoles()

    paths = Paths().subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                tag.tagFormatSimple, 1))
    numberOfPaths = 0

    # Sort first to ensure a deterministic list in ASN.1.
    sorted_paths = sorted(json_role['paths'])
    for json_path in sorted_paths:
      path = Path(json_path)
      # Some damned bug in pyasn1 I could not care less to fix right now.
      paths.setComponentByPosition(numberOfPaths, path, False)
      numberOfPaths += 1

    pathsToRoles['numberOfPaths'] = 1
    pathsToRoles['paths'] = paths

    roles = MultiRoles().subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                     tag.tagFormatSimple, 3))
    numberOfRoles = 0

    # NOTE: There are no multi-role delegations (TAP 3) yet in TUF.
    role = MultiRole()
    role['rolename'] = json_role['name']

    keyids = Keyids().subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                  tag.tagFormatSimple, 2))
    numberOfKeyids = 0

    # Sort first to ensure a deterministic list in ASN.1.
    sorted_keyids = sorted(json_role['keyids'])
    for json_keyid in sorted_keyids:

      keyid = Keyid().subtype(explicitTag=tag.Tag(
          tag.tagClassContext, tag.tagFormatConstructed, 0))
      keyid['octetString'] = univ.OctetString(hexValue=json_keyid).subtype(
          implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))

      # Some damned bug in pyasn1 I could not care less to fix right now.
      keyids.setComponentByPosition(numberOfKeyids, keyid, False)
      numberOfKeyids += 1

    role['numberOfKeyids'] = numberOfKeyids
    role['keyids'] = keyids
    role['threshold'] = json_role['threshold']

    roles[numberOfRoles] = role
    numberOfRoles += 1

    pathsToRoles['numberOfRoles'] = numberOfRoles
    pathsToRoles['roles'] = roles

    pathsToRoles['terminating'] = json_role['backtrack']

    prioritizedPathsToRoles[numberOfDelegations] = pathsToRoles
    numberOfDelegations += 1

  delegations['numberOfDelegations'] = numberOfDelegations
  delegations['delegations'] = prioritizedPathsToRoles


def set_asn_targets(json_signed, targetsMetadata):
  targets = Targets().subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                  tag.tagFormatSimple, 1))
  numberOfTargets = 0

  # Sort first to ensure a deterministic list in ASN.1.
  sorted_filenames = sorted(json_signed['targets'])
  for filename in sorted_filenames:
    filemeta = json_signed['targets'][filename]

    targetAndCustom = TargetAndCustom()

    target = Target().subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                  tag.tagFormatConstructed, 0))
    target['filename'] = filename
    target['length'] = filemeta['length']

    hashes = Hashes().subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                  tag.tagFormatSimple, 3))
    numberOfHashes = 0

    # Sort first to ensure a deterministic list in ASN.1.
    sorted_hash_functions = sorted(filemeta['hashes'])
    for hash_function in sorted_hash_functions:
      hash_value = filemeta['hashes'][hash_function]
      hash = Hash()
      hash['function'] = int(HashFunction(hash_function))
      digest = BinaryData()\
               .subtype(explicitTag=tag.Tag(tag.tagClassContext,
                                            tag.tagFormatConstructed, 1))
      octetString = univ.OctetString(hexValue=hash_value)\
                    .subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                 tag.tagFormatSimple, 1))
      digest['octetString'] = octetString
      hash['digest'] = digest
      hashes[numberOfHashes] = hash
      numberOfHashes += 1

    target['numberOfHashes'] = numberOfHashes
    target['hashes'] = hashes
    targetAndCustom['target'] = target

    # Optional bit.
    if 'custom' in filemeta:
      custom = Custom().subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                    tag.tagFormatConstructed,
                                                    1))

      # Sort first to ensure a deterministic list in ASN.1.
      sorted_customkeys = sorted(filemeta['custom'])
      for customkey in sorted_customkeys:
        #
        #   # TODO: Support arbitrary custom keys....
        #
        if customkey == 'ecu_serial':
          # ecu_serial field name currently goes from ecu_serial to ecuIdentifier
          custom['ecuIdentifier'] = filemeta['custom'][customkey]
        # TODO: Include other cases specific to Uptane here (release counter
        # and hardware identifier.)
        # elif customkey == 'release_counter':
        #   pass
        # elif customkey == 'hardware_identifier':
        #   pass
        else:
          custom[customkey] = filemeta['custom'][customkey] # Will probably break.

      targetAndCustom['custom'] = custom

    targets[numberOfTargets] = targetAndCustom
    numberOfTargets += 1

  targetsMetadata['numberOfTargets'] = numberOfTargets
  targetsMetadata['targets'] = targets


def set_json_delegations(json_signed, targetsMetadata):
  delegations = targetsMetadata['delegations']

  # Optional bit.
  if delegations:
    json_keys = set_json_keys(json_signed, delegations)
    json_roles = set_json_roles(json_signed, delegations)
    json_signed['delegations'] = {
      'keys': json_keys,
      'roles': json_roles
    }


def set_json_keys(json_signed, delegations):
  numberOfKeys = int(delegations['numberOfKeys'])
  keys = delegations['keys']
  json_keys = {}

  for i in range(numberOfKeys):
    key = keys[i]
    keyid = key['publicKeyid']['octetString'].prettyPrint() #str(key['publicKeyid'])
    assert keyid.startswith('0x')
    keyid = keyid[2:]
    keytype = int(key['publicKeyType'])
    # FIXME: Only ed25519 keys allowed for now.
    assert keytype == 1
    keytype = 'ed25519'
    octetString =  key['publicKeyValue']['octetString'].prettyPrint()
    assert octetString.startswith('0x')
    keyval = octetString[2:]
    json_keys[keyid] = {
      "keyid_hash_algorithms": [
        "sha256",
        "sha512"
      ],
      "keytype": keytype,
      "keyval": {
        "public": keyval
      }
    }

  return json_keys


def set_json_roles(json_signed, delegations):
  json_roles = []

  numberOfDelegations = int(delegations['numberOfDelegations'])
  delegations = delegations['delegations']

  for i in range(numberOfDelegations):
    pathsToRoles = delegations[i]

    numberOfPaths = int(pathsToRoles['numberOfPaths'])
    paths = pathsToRoles['paths']
    json_paths = []

    for j in range(numberOfPaths):
      json_paths.append(str(paths[j]))

    numberOfRoles = int(pathsToRoles['numberOfRoles'])
    # FIXME: Multi-role delegations (i.e., TAP 3) not yet allowed!
    assert numberOfRoles == 1
    roles = pathsToRoles['roles']
    role = roles[0]

    name = str(role['rolename'])

    numberOfKeyids = int(role['numberOfKeyids'])
    keyids = role['keyids']
    json_keyids = []
    for j in range(numberOfKeyids):
      keyid = keyids[j]
      json_keyids.append(str(keyid))

    threshold = int(role['threshold'])

    backtrack = bool(pathsToRoles['terminating'])

    json_role = {
      'backtrack': backtrack,
      'keyids': json_keyids,
      'name': name,
      'paths': json_paths,
      'threshold': threshold
    }
    json_roles.append(json_role)

  return json_roles


def set_json_targets(json_signed, targetsMetadata):
  numberOfTargets = int(targetsMetadata['numberOfTargets'])
  targets = targetsMetadata['targets']
  json_targets = {}

  for i in range(numberOfTargets):
    targetAndCustom = targets[i]

    target = targetAndCustom['target']
    filename = str(target['filename'])
    filemeta = {'length': int(target['length'])}

    numberOfHashes = int(target['numberOfHashes'])
    # Quick workaround for now.
    hashenum_to_hashfunction = {
      1: 'sha256',
      3: 'sha512'
    }
    hashes = target['hashes']
    json_hashes = {}
    for j in range(numberOfHashes):
      hash = hashes[j]
      hash_function = hashenum_to_hashfunction[int(hash['function'])]
      octetString = hash['digest']['octetString'].prettyPrint()
      assert octetString.startswith('0x')
      hash_value = octetString[2:]
      json_hashes[hash_function] = hash_value
    filemeta['hashes'] = json_hashes

    # Optional bit.
    custom = targetAndCustom['custom']
    if custom:
      json_custom = {
        'ecu_serial': str(custom['ecuIdentifier'])
      }
      filemeta['custom'] = json_custom

    json_targets[filename] = filemeta

  json_signed['targets'] = json_targets
