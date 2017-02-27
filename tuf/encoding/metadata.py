#!/usr/bin/env python

"""
<Author>
  Trishank Karthik Kuppusamy
"""

from __future__ import print_function

from pyasn1.type import univ, char, namedtype, namedval, tag, constraint, useful

from pyasn1.codec.der import encoder, decoder

from tuf.encoding.metadataverificationmodule import *

from datetime import datetime
import calendar
import hashlib
import json


def asn_to_json_metadata(get_json_signed, asn_metadata):
  asn_signed = asn_metadata['signed']
  der_signed = get_der_signed(asn_signed)
  der_signed_digest = hashlib.sha256(der_signed).hexdigest()

  json_signatures = []
  asn_signatures = asn_metadata['signatures']

  for i in range(asn_metadata['numberOfSignatures']):
    asn_signature = asn_signatures[i]
    asn_digest = asn_signature['hash']['digest']['octetString'].prettyPrint()
    assert asn_digest.startswith('0x')
    asn_digest = asn_digest[2:]
    # NOTE: Ensure that hash(DER(Metadata.signed)==Metadata.signatures[i].hash).
    assert asn_digest == der_signed_digest

    keyid = asn_signature['keyid']['octetString'].prettyPrint()
    assert keyid.startswith('0x')
    keyid = keyid[2:]

    # Cheap hack.
    method = int(asn_signature['method'])
    assert method == 1
    method = 'ed25519'

    value = asn_signature['value']['octetString'].prettyPrint()
    assert value.startswith('0x')
    value = value[2:]

    json_signature = {
      # NOTE: Check that signatures are for hash instead of signed.
      'hash': der_signed_digest,
      'keyid': keyid,
      'method': method,
      'sig': value
    }
    json_signatures.append(json_signature)

  return {
    'signatures': json_signatures,
    'signed': get_json_signed(asn_metadata)
  }


def der_to_json_metadata(get_json_signed, der_metadata, asn1Spec):
  asn_metadata = decoder.decode(der_metadata, asn1Spec=asn1Spec())[0]
  return asn_to_json_metadata(get_json_signed, asn_metadata)


def epoch_to_iso8601(timestamp):
  return datetime.utcfromtimestamp(timestamp).isoformat()+'Z'


def get_asn_and_der_signed(get_asn_signed, json_signed):
  asn_signed = get_asn_signed(json_signed)
  der_signed = get_der_signed(asn_signed)
  return asn_signed, der_signed


def get_der_signed(asn_signed):
  return encoder.encode(asn_signed)


def identity_update_json_signature(der_signed_digest, json_signature):
  # NOTE: Replace this signature with sign(private_key, der_signed_digest).
  json_signature['sig'] = json_signature['sig']


def iso8601_to_epoch(datestring):
  return calendar.timegm(datetime.strptime(datestring,
                                           "%Y-%m-%dT%H:%M:%SZ").timetuple())


def json_to_asn_metadata(asn_signed, der_signed, json_signatures, asn1Spec):
  metadata = asn1Spec()
  metadata['signed'] = asn_signed
  signedDigest = hashlib.sha256(der_signed).hexdigest()

  asn_signatures = Signatures()\
                   .subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                tag.tagFormatSimple, 2))
  numberOfSignatures = 0

  for json_signature in json_signatures:
    asn_signature = Signature()
    keyid = Keyid().subtype(explicitTag=tag.Tag(tag.tagClassContext,
                                                tag.tagFormatConstructed, 0))
    keyid['octetString'] = univ.OctetString(hexValue=json_signature['keyid'])\
                           .subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                        tag.tagFormatSimple, 1))
    asn_signature['keyid'] = keyid
    asn_signature['method'] = \
                  int(SignatureMethod(json_signature['method'].encode('ascii')))
    asn_hash = Hash().subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                  tag.tagFormatConstructed, 2))
    asn_hash['function'] = int(HashFunction('sha256'))
    asn_digest = BinaryData()\
                 .subtype(explicitTag=tag.Tag(tag.tagClassContext,
                                              tag.tagFormatConstructed, 1))
    asn_digest['octetString'] = \
      univ.OctetString(hexValue=signedDigest)\
      .subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
    asn_hash['digest'] = asn_digest
    asn_signature['hash'] = asn_hash
    value = BinaryData().subtype(explicitTag=tag.Tag(tag.tagClassContext,
                                                     tag.tagFormatConstructed,
                                                     3))
    value['octetString'] = univ.OctetString(hexValue=json_signature['sig'])\
                           .subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                tag.tagFormatSimple, 1))
    asn_signature['value'] = value
    asn_signatures[numberOfSignatures] = asn_signature
    numberOfSignatures += 1

  metadata['numberOfSignatures'] = numberOfSignatures
  metadata['signatures'] = asn_signatures
  return metadata


def json_to_der_metadata(asn_signed, der_signed, json_signatures, asn1Spec):
  metadata = json_to_asn_metadata(asn_signed, der_signed, json_signatures,
                                  asn1Spec)
  return encoder.encode(metadata)


def pretty_print(json_metadata):
  # http://stackoverflow.com/a/493399
  print(json.dumps(json_metadata, sort_keys=True, indent=1,
                   separators=(',', ': ')), end='')


def test(json_filename, der_filename, get_asn_signed, get_json_signed,
         update_json_signature, asn1Spec):
  # 1. Read from JSON.
  with open(json_filename, 'rb') as jsonFile:
    before_json = json.load(jsonFile)
  json_signed = before_json['signed']
  json_signatures = before_json['signatures']

  # 2. Write the signed encoding.
  asn_signed, der_signed = get_asn_and_der_signed(get_asn_signed, json_signed)
  der_signed_digest = hashlib.sha256(der_signed).hexdigest()
  # NOTE: Use der_signed_digest to *MODIFY* json_signatures.
  for json_signature in json_signatures:
    update_json_signature(der_signed_digest, json_signature)
  with open (der_filename, 'wb') as derFile:
    der_metadata = json_to_der_metadata(asn_signed, der_signed, json_signatures,
                                        asn1Spec)
    derFile.write(der_metadata)

  # 3. Read it back to check the signed hash.
  with open(der_filename, 'rb') as derFile:
    der_metadata = derFile.read()
  # NOTE: In after_json, check that signatures match signed_hash.
  after_json = der_to_json_metadata(get_json_signed, der_metadata, asn1Spec)
  pretty_print(after_json)
