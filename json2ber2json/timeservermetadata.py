#!/usr/bin/env python

from pyasn1.type import univ, char, namedtype, namedval, tag, constraint, useful

from timeservermodule import *

import metadata


def get_asn_signed(json_signed):
  signed = NoncesAndTimestamp()\
           .subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                        tag.tagFormatConstructed, 0))
  numberOfNonces = 0
  nonces = Nonces().subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                tag.tagFormatSimple, 1))
  for nonce in json_signed['nonces']:
    # Some damned bug in pyasn1 I could not care less to fix right now.
    nonces.setComponentByPosition(numberOfNonces, nonce, False)
    numberOfNonces += 1
  signed['numberOfNonces'] = numberOfNonces
  signed['nonces'] = nonces
  signed['timestamp'] = metadata.iso8601_to_epoch(json_signed['time'])
  return signed


def get_json_signed(asn_metadata):
  asn_signed = asn_metadata['signed']

  json_signed = {
    'time': metadata.epoch_to_iso8601(asn_signed['timestamp'])
  }

  numberOfNonces = int(asn_signed['numberOfNonces'])
  nonces = asn_signed['nonces']
  json_nonces = []
  for i in range(numberOfNonces):
    json_nonces.append(int(nonces[i]))
  json_signed['nonces'] = json_nonces

  return json_signed


if __name__ == '__main__':
  metadata.test('timeserver.json', 'timeserver.ber', get_asn_signed,
                get_json_signed, metadata.identity_update_json_signature,
                CurrentTime)
