#!/usr/bin/env python

"""
<Author>
  Trishank Karthik Kuppusamy
"""

from pyasn1.type import univ, char, namedtype, namedval, tag, constraint, useful

from uptane.encoding.metadataverificationmodule import *

import uptane.encoding.metadata as metadata


def get_asn_signed(json_signed):
  snapshotMetadataFiles = SnapshotMetadataFiles()\
                          .subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                       tag.tagFormatSimple, 1))
  meta = json_signed['meta']
  numberOfSnapshotMetadataFiles = 0

  for filename, filemeta in meta.items():
    snapshotMetadataFile = SnapshotMetadataFile()
    snapshotMetadataFile['filename'] = filename
    snapshotMetadataFile['version'] = filemeta['version']
    snapshotMetadataFiles[numberOfSnapshotMetadataFiles] = snapshotMetadataFile
    numberOfSnapshotMetadataFiles += 1

  snapshotMetadata = SnapshotMetadata()\
                     .subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                  tag.tagFormatConstructed, 2))
  snapshotMetadata['numberOfSnapshotMetadataFiles'] = \
                                                  numberOfSnapshotMetadataFiles
  snapshotMetadata['snapshotMetadataFiles'] = snapshotMetadataFiles

  signedBody = SignedBody()\
               .subtype(explicitTag=tag.Tag(tag.tagClassContext,
                                            tag.tagFormatConstructed, 3))
  signedBody['snapshotMetadata'] = snapshotMetadata

  signed = Signed().subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                tag.tagFormatConstructed, 0))
  signed['type'] = int(RoleType('snapshot'))
  signed['expires'] = metadata.iso8601_to_epoch(json_signed['expires'])
  signed['version'] = json_signed['version']
  signed['body'] = signedBody

  return signed


def get_json_signed(asn_metadata):
  json_signed = {
    '_type': 'Snapshot'
  }

  asn_signed = asn_metadata['signed']
  json_signed['expires'] = metadata.epoch_to_iso8601(asn_signed['expires'])
  json_signed['version'] = int(asn_signed['version'])

  snapshotMetadata = asn_signed['body']['snapshotMetadata']
  numberOfSnapshotMetadataFiles = \
                          int(snapshotMetadata['numberOfSnapshotMetadataFiles'])
  snapshotMetadataFiles = snapshotMetadata['snapshotMetadataFiles']
  json_meta = {}

  for i in range(numberOfSnapshotMetadataFiles):
    snapshotMetadataFile = snapshotMetadataFiles[i]
    filename = str(snapshotMetadataFile['filename'])
    filemeta = {'version': int(snapshotMetadataFile['version'])}
    json_meta[filename] = filemeta

  json_signed['meta'] = json_meta

  return json_signed


if __name__ == '__main__':
  metadata.test('snapshot.json', 'snapshot.ber', get_asn_signed,
                get_json_signed, metadata.identity_update_json_signature,
                Metadata)
