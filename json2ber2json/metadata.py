#!/usr/bin/env python

from __future__ import print_function

from pyasn1.type import univ, char, namedtype, namedval, tag, constraint, useful

from pyasn1.codec.ber import encoder, decoder

from metadataverificationmodule import *

from datetime import datetime
import calendar
import hashlib
import json


def asn_to_json_metadata(get_json_signed, asn_metadata):
  asn_signed = asn_metadata['signed']
  ber_signed = get_ber_signed(asn_signed)
  ber_signed_digest = hashlib.sha256(ber_signed).hexdigest()

  json_signatures = []
  asn_signatures = asn_metadata['signatures']

  for i in range(asn_metadata['numberOfSignatures']):
    asn_signature = asn_signatures[i]
    asn_digest = asn_signature['hash']['digest']['hexString']
    # NOTE: Ensure that hash(BER(Metadata.signed)==Metadata.signatures[i].hash).
    assert asn_digest == ber_signed_digest

    # Cheap hack.
    method = int(asn_signature['method'])
    assert method == 1
    method = 'ed25519'

    json_signature = {
      # NOTE: Check that signatures are for hash instead of signed.
      'hash': ber_signed_digest,
      'keyid': str(asn_signature['keyid']),
      'method': method,
      'sig': str(asn_signature['value'])
    }
    json_signatures.append(json_signature)

  return {
    'signatures': json_signatures,
    'signed': get_json_signed(asn_metadata)
  }


def ber_to_json_metadata(get_json_signed, ber_metadata, asn1Spec):
  asn_metadata = decoder.decode(ber_metadata, asn1Spec=asn1Spec())[0]
  return asn_to_json_metadata(get_json_signed, asn_metadata)


def epoch_to_iso8601(timestamp):
  return datetime.utcfromtimestamp(timestamp).isoformat()+'Z'


def get_asn_and_ber_signed(get_asn_signed, json_signed):
  asn_signed = get_asn_signed(json_signed)
  ber_signed = get_ber_signed(asn_signed)
  return asn_signed, ber_signed


def get_ber_signed(asn_signed):
  return encoder.encode(asn_signed)


def identity_update_json_signature(ber_signed_digest, json_signature):
  # NOTE: Replace this signature with sign(private_key, ber_signed_digest).
  json_signature['sig'] = json_signature['sig']


def iso8601_to_epoch(datestring):
  return calendar.timegm(datetime.strptime(datestring,
                                           "%Y-%m-%dT%H:%M:%SZ").timetuple())


def json_to_asn_metadata(asn_signed, ber_signed, json_signatures, asn1Spec):
  metadata = asn1Spec()
  metadata['signed'] = asn_signed
  signedDigest = hashlib.sha256(ber_signed).hexdigest()

  asn_signatures = Signatures()\
                   .subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                tag.tagFormatSimple, 2))
  numberOfSignatures = 0

  for json_signature in json_signatures:
    asn_signature = Signature()
    asn_signature['keyid'] = json_signature['keyid']
    asn_signature['method'] = \
                  int(SignatureMethod(json_signature['method'].encode('ascii')))
    asn_hash = Hash().subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                  tag.tagFormatConstructed, 2))
    asn_hash['function'] = int(HashFunction('sha256'))
    asn_digest = BinaryData()\
                 .subtype(explicitTag=tag.Tag(tag.tagClassContext,
                                              tag.tagFormatConstructed, 1))
    asn_digest['hexString'] = signedDigest
    asn_hash['digest'] = asn_digest
    asn_signature['hash'] = asn_hash
    asn_signature['value'] = json_signature['sig']
    asn_signatures[numberOfSignatures] = asn_signature
    numberOfSignatures += 1

  metadata['numberOfSignatures'] = numberOfSignatures
  metadata['signatures'] = asn_signatures
  return metadata


def json_to_ber_metadata(asn_signed, ber_signed, json_signatures, asn1Spec):
  metadata = json_to_asn_metadata(asn_signed, ber_signed, json_signatures,
                                  asn1Spec)
  return encoder.encode(metadata)


def pretty_print(json_metadata):
  # http://stackoverflow.com/a/493399
  print(json.dumps(json_metadata, sort_keys=True, indent=1,
                   separators=(',', ': ')), end='')


def test(json_filename, ber_filename, get_asn_signed, get_json_signed,
         update_json_signature, asn1Spec):
  # 1. Read from JSON.
  with open(json_filename, 'rb') as jsonFile:
    before_json = json.load(jsonFile)
  json_signed = before_json['signed']
  json_signatures = before_json['signatures']

  # 2. Write the signed encoding.
  asn_signed, ber_signed = get_asn_and_ber_signed(get_asn_signed, json_signed)
  ber_signed_digest = hashlib.sha256(ber_signed).hexdigest()
  # NOTE: Use ber_signed_digest to *MODIFY* json_signatures.
  for json_signature in json_signatures:
    update_json_signature(ber_signed_digest, json_signature)
  with open (ber_filename, 'wb') as berFile:
    ber_metadata = json_to_ber_metadata(asn_signed, ber_signed, json_signatures,
                                        asn1Spec)
    berFile.write(ber_metadata)

  # 3. Read it back to check the signed hash.
  with open(ber_filename, 'rb') as berFile:
    ber_metadata = berFile.read()
  # NOTE: In after_json, check that signatures match signed_hash.
  after_json = ber_to_json_metadata(get_json_signed, ber_metadata, asn1Spec)
  pretty_print(after_json)
