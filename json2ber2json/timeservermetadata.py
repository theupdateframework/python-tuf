#!/usr/bin/env python

"""
<Author>
  Trishank Karthik Kuppusamy
"""

from pyasn1.type import univ, char, namedtype, namedval, tag, constraint, useful

from timeservermodule import *

import metadata


def get_asn_signed(json_signed):
  signed = TokensAndTimestamp()\
           .subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                        tag.tagFormatConstructed, 0))
  numberOfTokens = 0
  tokens = Tokens().subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                tag.tagFormatSimple, 1))
  for token in json_signed['tokens']:
    # Some damned bug in pyasn1 I could not care less to fix right now.
    tokens.setComponentByPosition(numberOfTokens, token, False)
    numberOfTokens += 1
  signed['numberOfTokens'] = numberOfTokens
  signed['tokens'] = tokens
  signed['timestamp'] = metadata.iso8601_to_epoch(json_signed['time'])
  return signed


def get_json_signed(asn_metadata):
  asn_signed = asn_metadata['signed']

  json_signed = {
    'time': metadata.epoch_to_iso8601(asn_signed['timestamp'])
  }

  numberOfTokens = int(asn_signed['numberOfTokens'])
  tokens = asn_signed['tokens']
  json_tokens = []
  for i in range(numberOfTokens):
    json_tokens.append(int(tokens[i]))
  json_signed['tokens'] = json_tokens

  return json_signed


if __name__ == '__main__':
  metadata.test('timeserver.json', 'timeserver.ber', get_asn_signed,
                get_json_signed, metadata.identity_update_json_signature,
                CurrentTime)
