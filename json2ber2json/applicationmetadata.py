#!/usr/bin/env python

from pyasn1.type import univ, char, namedtype, namedval, tag, constraint, useful

from applicationmodule import *

import metadata

import bootloadermodule
import bootloadermetadata


def get_asn_signed(json_signed):
  signed = VehicleVersionManifestSigned()\
           .subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                        tag.tagFormatConstructed, 0))

  signed['vehicleIdentifier'] = json_signed['vin']
  signed['primaryIdentifier'] = json_signed['primary-serial']

  ecuVersionManifests = ECUVersionManifests()\
                        .subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                     tag.tagFormatSimple, 3))
  numberOfECUVersionManifests = 0

  for manifest in json_signed['ecu-version-manifests']:
    json_signed, json_signatures = manifest['signed'], manifest['signatures']
    asn_signed, ber_signed = \
              metadata.get_asn_and_ber_signed(bootloadermetadata.get_asn_signed,
                                              json_signed)
    ecuVersionManifest = \
        metadata.json_to_asn_metadata(asn_signed, ber_signed, json_signatures,
                                      bootloadermodule.ECUVersionManifest)
    ecuVersionManifests[numberOfECUVersionManifests] = ecuVersionManifest
    numberOfECUVersionManifests += 1

  signed['numberOfECUVersionManifests'] = numberOfECUVersionManifests
  signed['ecuVersionManifests'] = ecuVersionManifests

  return signed


def get_json_signed(asn_metadata):
  asn_signed = asn_metadata['signed']

  json_signed = {
      'vin': str(asn_signed['vehicleIdentifier']),
      'primary-serial': str(asn_signed['primaryIdentifier'])
  }

  json_manifests = []
  numberOfECUVersionManifests = int(asn_signed['numberOfECUVersionManifests'])
  ecuVersionManifests = asn_signed['ecuVersionManifests']
  for i in range(numberOfECUVersionManifests):
    manifest = ecuVersionManifests[i]
    json_manifest = \
              metadata.asn_to_json_metadata(bootloadermetadata.get_json_signed,
                                            manifest)
    json_manifests.append(json_manifest)
  json_signed['ecu-version-manifests'] = json_manifests

  return json_signed


if __name__ == '__main__':
  metadata.test('vehicleversionmanifest.json', 'vehicleversionmanifest.ber',
                get_asn_signed, get_json_signed,
                metadata.identity_update_json_signature,
                VehicleVersionManifest)
