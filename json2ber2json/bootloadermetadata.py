#!/usr/bin/env python

from pyasn1.type import univ, char, namedtype, namedval, tag, constraint, useful

from bootloadermodule import *

import metadata


def get_asn_signed(json_signed):
  signed = ECUVersionManifestSigned()\
           .subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                        tag.tagFormatConstructed, 0))

  signed['ecuIdentifier'] = json_signed['ecu_serial']
  signed['previousTime'] = \
            metadata.iso8601_to_epoch(json_signed['previous_timeserver_time'])
  signed['currentTime'] = \
                    metadata.iso8601_to_epoch(json_signed['timeserver_time'])

  # Optional bit.
  if 'attacks_detected' in json_signed:
    attacks_detected = json_signed['attacks_detected']
    assert len(attacks_detected) > 0,\
           'attacks_detected cannot be an empty string!'
    signed['securityAttack'] = attacks_detected

  target = Target().subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                tag.tagFormatConstructed, 4))
  filename = json_signed['installed_image']['filepath']
  filemeta = json_signed['installed_image']['fileinfo']
  target['filename'] = filename
  target['length'] = filemeta['length']

  hashes = Hashes().subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                tag.tagFormatSimple, 3))
  numberOfHashes = 0

  for hash_function, hash_value in filemeta['hashes'].items():
    hash = Hash()
    hash['function'] = int(HashFunction(hash_function.encode('ascii')))
    digest = BinaryData()\
             .subtype(explicitTag=tag.Tag(tag.tagClassContext,
                                          tag.tagFormatConstructed, 1))
    digest['hexString'] = hash_value
    hash['digest'] = digest
    hashes[numberOfHashes] = hash
    numberOfHashes += 1

  target['numberOfHashes'] = numberOfHashes
  target['hashes'] = hashes
  signed['installedImage'] = target

  return signed


def get_json_signed(asn_metadata):
  asn_signed = asn_metadata['signed']

  timeserver_time = metadata.epoch_to_iso8601(asn_signed['currentTime'])
  previous_timeserver_time = \
          metadata.epoch_to_iso8601(asn_signed['previousTime'])
  ecu_serial = str(asn_signed['ecuIdentifier'])

  target = asn_signed['installedImage']
  filepath = str(target['filename'])
  fileinfo = {'length': int(target['length'])}

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
    hash_value = str(hash['digest']['hexString'])
    json_hashes[hash_function] = hash_value
  fileinfo['hashes'] = json_hashes

  installed_image = {
    'filepath': filepath,
    'fileinfo': fileinfo
  }

  json_signed = {
    'ecu_serial': ecu_serial,
    'installed_image': installed_image,
    'previous_timeserver_time': previous_timeserver_time,
    'timeserver_time': timeserver_time
  }

  # Optional bit.
  attacks_detected = asn_signed['securityAttack']
  if attacks_detected:
    json_signed['attacks_detected'] = str(attacks_detected)

  return json_signed


if __name__ == '__main__':
  metadata.test('ecuversionmanifest.json', 'ecuversionmanifest.ber',
                  get_asn_signed, get_json_signed,
                  metadata.identity_update_json_signature,
                  ECUVersionManifest)
