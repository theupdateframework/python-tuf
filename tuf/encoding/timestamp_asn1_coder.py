"""
<Name>
  tuf/encoding/timestamp_asn1_coder.py

<Purpose>
  This module contains conversion functions (get_asn_signed and get_json_signed)
  for converting Timestamp role metadata to and from TUF's standard
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
  timestampMetadata = TimestampMetadata()\
                      .subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                   tag.tagFormatConstructed, 3))
  if len(json_signed['meta']) != 1:
    raise tuf.Error('Expecting only one file to be identified in timestamp '
        'metadata: snapshot. Contents of timestamp metadata: ' +
        repr(json_signed['meta']))

  # Get the only key in the dictionary, the filename of the file timestamp
  # contains a hash for (snapshot.*).
  filename = list(json_signed['meta'])[0]

  meta = json_signed['meta'][filename]
  timestampMetadata['filename'] = filename
  timestampMetadata['version'] = meta['version']
  timestampMetadata['length'] = meta['length']
  timestampMetadata['numberOfHashes'] = 1
  hashes = Hashes().subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                tag.tagFormatSimple, 4))
  hash = Hash()
  # TODO: Remove hardcoded hash assumptions here: type and number.
  # Model on code added to snapshotmetadata.py
  hash['function'] = int(HashFunction('sha256'))
  digest = BinaryData().subtype(explicitTag=tag.Tag(tag.tagClassContext,
                                                    tag.tagFormatConstructed,
                                                    1))
  octetString = univ.OctetString(hexValue=meta['hashes']['sha256'])\
                .subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                             tag.tagFormatSimple, 1))
  digest['octetString'] = octetString
  hash['digest'] = digest
  hashes[0] = hash
  timestampMetadata['hashes'] = hashes

  signedBody = SignedBody()\
               .subtype(explicitTag=tag.Tag(tag.tagClassContext,
                                            tag.tagFormatConstructed, 3))
  signedBody['timestampMetadata'] = timestampMetadata

  signed = Signed().subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                tag.tagFormatConstructed, 0))
  signed['type'] = int(RoleType('timestamp'))
  signed['expires'] = calendar.timegm(datetime.strptime(
      json_signed['expires'], "%Y-%m-%dT%H:%M:%SZ").timetuple())
  signed['version'] = json_signed['version']
  signed['body'] = signedBody

  return signed


def get_json_signed(asn_metadata):
  json_signed = {
    '_type': 'Timestamp'
  }

  asn_signed = asn_metadata['signed']
  json_signed['expires'] = datetime.utcfromtimestamp(
    asn_signed['expires']).isoformat()+'Z'
  json_signed['version'] = int(asn_signed['version'])

  timestampMetadata = asn_signed['body']['timestampMetadata']
  filename = str(timestampMetadata['filename'])
  # TODO: Remove hardcoded hash assumptions here.
  sha256 = timestampMetadata['hashes'][0]['digest']['octetString'].prettyPrint() # TODO: Probably not the way to go long-term.
  assert sha256.startswith('0x')
  sha256 = sha256[2:]
  json_signed['meta'] = {
    filename : {
      'hashes': {
        'sha256': sha256
      },
      'length': int(timestampMetadata['length']),
      'version': int(timestampMetadata['version'])
    }
  }

  return json_signed
