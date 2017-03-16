#!/usr/bin/env python

"""
<Author>
  Trishank Karthik Kuppusamy
"""

from pyasn1.type import univ, tag

from tuf.encoding.metadata_asn1_definitions import *

import calendar
from datetime import datetime #import datetime


def get_asn_signed(json_signed):
  rootMetadata = RootMetadata()\
                 .subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                              tag.tagFormatConstructed, 0))

  rootPublicKeyid = json_signed['roles']['root']['keyids'][0]
  timestampPublicKeyid = json_signed['roles']['timestamp']['keyids'][0]
  snapshotPublicKeyid = json_signed['roles']['snapshot']['keyids'][0]
  targetsPublicKeyid = json_signed['roles']['targets']['keyids'][0]

  keys = set_keys(json_signed, rootPublicKeyid, timestampPublicKeyid,
                  snapshotPublicKeyid, targetsPublicKeyid, rootMetadata)
  roles = set_roles(json_signed, rootPublicKeyid, timestampPublicKeyid,
                  snapshotPublicKeyid, targetsPublicKeyid, rootMetadata)

  signedBody = SignedBody()\
               .subtype(explicitTag=tag.Tag(tag.tagClassContext,
                                            tag.tagFormatConstructed, 3))
  signedBody['rootMetadata'] = rootMetadata

  signed = Signed().subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                tag.tagFormatConstructed, 0))
  signed['type'] = int(RoleType('root'))
  signed['expires'] = calendar.timegm(datetime.strptime(
      json_signed['expires'], "%Y-%m-%dT%H:%M:%SZ").timetuple())
  signed['version'] = json_signed['version']
  signed['body'] = signedBody

  return signed


def get_json_signed(asn_metadata):
  json_signed = {
    '_type': 'Root',
    'compression_algorithms': ['gz'],
    'consistent_snapshot': False
  }

  asn_signed = asn_metadata['signed']
  json_signed['expires'] = datetime.utcfromtimestamp(
    asn_signed['expires']).isoformat()+'Z'
  json_signed['version'] = int(asn_signed['version'])

  rootMetadata = asn_signed['body']['rootMetadata']

  assert rootMetadata['numberOfKeys'] == 4 # TODO: <~> Remove this hardcoding. This has to be TUF-compliant. It can't assume no Targets delegations.
  keys = rootMetadata['keys']
  json_keys = {}
  for i in range(4):
    publicKey = keys[i]
    publicKeyid = publicKey['publicKeyid']['octetString'].prettyPrint()
    assert publicKeyid.startswith('0x')
    publicKeyid = publicKeyid[2:]
    # Only ed25519 keys allowed for now.
    publicKeyType = int(publicKey['publicKeyType'])
    assert publicKeyType == 1
    publicKeyType = 'ed25519'
    publicKeyValue = publicKey['publicKeyValue']['octetString'].prettyPrint()
    assert publicKeyValue.startswith('0x')
    publicKeyValue = publicKeyValue[2:]
    json_keys[publicKeyid] = {
      'keyid_hash_algorithms': ['sha256', 'sha512'], # TODO: <~> This was hard-coded. Fix it.
      'keytype': publicKeyType,
      'keyval': {
        'public': publicKeyValue
      }
    }
  json_signed['keys'] = json_keys

  assert rootMetadata['numberOfRoles'] == 4
  roles = rootMetadata['roles']
  json_roles = {}
  # Quick workaround for now.
  roletype_to_rolename = {
    0: 'root',
    1: 'targets',
    2: 'snapshot',
    3: 'timestamp'
  }
  for i in range(4):
    topLevelRole = roles[i]
    rolename = roletype_to_rolename[int(topLevelRole['role'])]
    assert topLevelRole['numberOfKeyids'] == 1
    #keyids = [str(topLevelRole['keyids'][0])]
    keyid = topLevelRole['keyids'][0]['octetString'].prettyPrint()
    assert keyid.startswith('0x')
    keyid = keyid[2:]
    keyids = [keyid]
    threshold = int(topLevelRole['threshold'])
    assert threshold == 1
    json_roles[rolename] = {
      'keyids': keyids,
      'threshold': threshold
    }
  json_signed['roles'] = json_roles

  return json_signed


def set_keys(json_signed, rootPublicKeyid, timestampPublicKeyid,
             snapshotPublicKeyid, targetsPublicKeyid, rootMetadata):
  keys = PublicKeys().subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                  tag.tagFormatSimple, 1))

  rootPublicKey = PublicKey()
  # NOTE: Only 1 key allowed for now!
  keyid = Keyid().subtype(explicitTag=tag.Tag(tag.tagClassContext,
                                              tag.tagFormatConstructed, 0))
  keyid['octetString'] = univ.OctetString(hexValue=rootPublicKeyid)\
                         .subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                      tag.tagFormatSimple, 1))
  rootPublicKey['publicKeyid'] = keyid
  rootPublicKeyType = json_signed['keys'][rootPublicKeyid]['keytype']
  rootPublicKey['publicKeyType'] = int(PublicKeyType(rootPublicKeyType))
  rootPublicKeyValue = BinaryData()\
                       .subtype(explicitTag=tag.Tag(tag.tagClassContext,
                                                    tag.tagFormatConstructed,
                                                    2))
  rootPublicKeyHexString = json_signed['keys'][rootPublicKeyid]['keyval']\
                                      ['public']
  rootPublicKeyValue['octetString'] = \
    univ.OctetString(hexValue=rootPublicKeyHexString)\
    .subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
  rootPublicKey['publicKeyValue'] = rootPublicKeyValue
  keys[0] = rootPublicKey

  timestampPublicKey = PublicKey()
  # NOTE: Only 1 key allowed for now!
  keyid = Keyid().subtype(explicitTag=tag.Tag(tag.tagClassContext,
                                              tag.tagFormatConstructed, 0))
  keyid['octetString'] = univ.OctetString(hexValue=timestampPublicKeyid)\
                         .subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                      tag.tagFormatSimple, 1))
  timestampPublicKey['publicKeyid'] = keyid
  timestampPublicKeyType = json_signed['keys'][timestampPublicKeyid]['keytype']
  timestampPublicKey['publicKeyType'] = \
                                      int(PublicKeyType(timestampPublicKeyType))
  timestampPublicKeyValue = \
                BinaryData().subtype(explicitTag=tag.Tag(tag.tagClassContext,
                                                 tag.tagFormatConstructed, 2))
  timestampPublicKeyHexString = json_signed['keys'][timestampPublicKeyid]\
                                           ['keyval']['public']
  timestampPublicKeyValue['octetString'] = \
    univ.OctetString(hexValue=timestampPublicKeyHexString)\
    .subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
  timestampPublicKey['publicKeyValue'] = timestampPublicKeyValue
  keys[1] = timestampPublicKey

  snapshotPublicKey = PublicKey()
  # NOTE: Only 1 key allowed for now!
  keyid = Keyid().subtype(explicitTag=tag.Tag(tag.tagClassContext,
                                              tag.tagFormatConstructed, 0))
  keyid['octetString'] = univ.OctetString(hexValue=snapshotPublicKeyid)\
                         .subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                      tag.tagFormatSimple, 1))
  snapshotPublicKey['publicKeyid'] = keyid
  snapshotPublicKeyType = json_signed['keys'][snapshotPublicKeyid]['keytype']
  snapshotPublicKey['publicKeyType'] = \
                                      int(PublicKeyType(snapshotPublicKeyType))
  snapshotPublicKeyValue = \
          BinaryData().subtype(explicitTag=tag.Tag(tag.tagClassContext,
                                                   tag.tagFormatConstructed, 2))
  snapshotPublicKeyHexString = json_signed['keys'][snapshotPublicKeyid]\
                                          ['keyval']['public']
  snapshotPublicKeyValue['octetString'] = \
    univ.OctetString(hexValue=snapshotPublicKeyHexString)\
    .subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
  snapshotPublicKey['publicKeyValue'] = snapshotPublicKeyValue
  keys[2] = snapshotPublicKey

  targetsPublicKey = PublicKey()
  # NOTE: Only 1 key allowed for now!
  keyid = Keyid().subtype(explicitTag=tag.Tag(tag.tagClassContext,
                                              tag.tagFormatConstructed, 0))
  keyid['octetString'] = univ.OctetString(hexValue=targetsPublicKeyid)\
                         .subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                      tag.tagFormatSimple, 1))
  targetsPublicKey['publicKeyid'] = keyid
  targetsPublicKeyType = json_signed['keys'][targetsPublicKeyid]['keytype']
  targetsPublicKey['publicKeyType'] = \
                                      int(PublicKeyType(targetsPublicKeyType))
  targetsPublicKeyValue = BinaryData()\
                          .subtype(explicitTag=tag.Tag(tag.tagClassContext,
                                                       tag.tagFormatConstructed,
                                                       2))
  targetsPublicKeyHexString = json_signed['keys'][targetsPublicKeyid]\
                                          ['keyval']['public']
  targetsPublicKeyValue['octetString'] = \
    univ.OctetString(hexValue=targetsPublicKeyHexString)\
    .subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
  targetsPublicKey['publicKeyValue'] = targetsPublicKeyValue
  keys[3] = targetsPublicKey

  rootMetadata['numberOfKeys'] = 4
  rootMetadata['keys'] = keys


def set_roles(json_signed, rootPublicKeyid, timestampPublicKeyid,
              snapshotPublicKeyid, targetsPublicKeyid, rootMetadata):
  roles = TopLevelRoles().subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                      tag.tagFormatConstructed,
                                                      3))

  rootRole = TopLevelRole()
  rootRole['role'] = int(RoleType('root'))
  rootRoleKeyids = Keyids().subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                        tag.tagFormatSimple, 4))
  rootRoleKeyid = Keyid()
  rootRoleKeyid['octetString'] = \
    univ.OctetString(hexValue=rootPublicKeyid)\
    .subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
  # Some damned bug in pyasn1 I could not care less to fix right now.
  rootRoleKeyids.setComponentByPosition(0, rootRoleKeyid, False)
  rootRole['numberOfKeyids'] = 1
  rootRole['keyids'] = rootRoleKeyids
  rootRole['threshold'] = 1
  # Some damned bug in pyasn1 I could not care less to fix right now.
  roles.setComponentByPosition(0, rootRole, False)

  snapshotRole = TopLevelRole()
  snapshotRole['role'] = int(RoleType('snapshot'))
  snapshotRoleKeyids = Keyids().subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                            tag.tagFormatSimple,
                                                            4))
  snapshotRoleKeyid = Keyid()
  snapshotRoleKeyid['octetString'] = \
    univ.OctetString(hexValue=snapshotPublicKeyid)\
    .subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
  # Some damned bug in pyasn1 I could not care less to fix right now.
  snapshotRoleKeyids.setComponentByPosition(0, snapshotRoleKeyid, False)
  snapshotRole['numberOfKeyids'] = 1
  snapshotRole['keyids'] = snapshotRoleKeyids
  snapshotRole['threshold'] = 1
  # Some damned bug in pyasn1 I could not care less to fix right now.
  roles.setComponentByPosition(1, snapshotRole, False)

  targetsRole = TopLevelRole()
  targetsRole['role'] = int(RoleType('targets'))
  targetsRoleKeyids = Keyids().subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                           tag.tagFormatSimple,
                                                           4))
  targetsRoleKeyid = Keyid()
  targetsRoleKeyid['octetString'] = \
    univ.OctetString(hexValue=targetsPublicKeyid)\
    .subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
  # Some damned bug in pyasn1 I could not care less to fix right now.
  targetsRoleKeyids.setComponentByPosition(0, targetsRoleKeyid, False)
  targetsRole['numberOfKeyids'] = 1
  targetsRole['keyids'] = targetsRoleKeyids
  targetsRole['threshold'] = 1
  # Some damned bug in pyasn1 I could not care less to fix right now.
  roles.setComponentByPosition(2, targetsRole, False)

  timestampRole = TopLevelRole()
  timestampRole['role'] = int(RoleType('timestamp'))
  timestampRoleKeyids = Keyids()\
                        .subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                     tag.tagFormatSimple, 4))
  timestampRoleKeyid = Keyid()
  timestampRoleKeyid['octetString'] = \
    univ.OctetString(hexValue=timestampPublicKeyid)\
    .subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
  # Some damned bug in pyasn1 I could not care less to fix right now.
  timestampRoleKeyids.setComponentByPosition(0, timestampRoleKeyid, False)
  timestampRole['numberOfKeyids'] = 1
  timestampRole['keyids'] = timestampRoleKeyids
  timestampRole['threshold'] = 1
  # Some damned bug in pyasn1 I could not care less to fix right now.
  roles.setComponentByPosition(3, timestampRole, False)

  rootMetadata['numberOfRoles'] = 4
  rootMetadata['roles'] = roles
