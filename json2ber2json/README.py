#!/usr/bin/env python

import hashlib
import json

import tuf.repository_tool
import tuf.keys

# "Base" utility module.
import metadata

# Modules for TUF metadata.
import rootmetadata
import snapshotmetadata
import targetsmetadata
import timestampmetadata
import metadataverificationmodule

# Module for time server.
import timeservermetadata
import timeservermodule

# Module for ECU version manifest.
import bootloadermetadata
import bootloadermodule

# Module for the vehicle version manifest.
import applicationmetadata
import applicationmodule


def seamless_transport_of_json_over_ber(json_in_filename, ber_filename,
                                        json_out_filename, get_asn_signed,
                                        get_json_signed, asn1Spec):
  '''This function demonstrates how to seamlessly transport JSON over BER
  without modifying JSON signatures.
  This is useful for TUF metadata (root, timestamp, snapshot, targets) that need
  to be exchanged between repositories and primaries, or primaries and
  secondaries, and that are signed and verified using the TUF Python reference
  implementation.

  The first three parameters are: (1) the input JSON filename, (2) the
  intermediary BER filename, and (3) the output JSON filename.
  The fourth and fifth parameters are the get_asn_signed and get_json_signed
  functions from either the timestampmetadata, snapshotmetadata, rootmetadata,
  or targetsmetadata module, depending on which type of JSON metadata is being
  converted.
  The sixth parameter specifies the ASN.1 data structure for the message.
  For timestamp, snapshot, root, targets metadata, it is
  metadataverificationmodule.Metadata.
  For the signed time server response, it is timeservermodule.CurrentTime.
  For an ECU version manifest, it is bootloadermodule.ECUVersionManifest.
  For the vehicle version manifest, it is
  applicationmodule.VehicleVersionManifest.'''

  # 1. Read from JSON.
  with open(json_in_filename, 'rb') as json_in_file:
    before_json = json.load(json_in_file)
  print('Read {}'.format(json_in_filename))
  json_signed = before_json['signed']
  json_signatures = before_json['signatures']

  # 2. Write the BER encoding of the JSON.
  asn_signed, ber_signed = metadata.get_asn_and_ber_signed(get_asn_signed,
                                                           json_signed)
  with open (ber_filename, 'wb') as ber_file:
    ber_metadata = metadata.json_to_ber_metadata(asn_signed, ber_signed,
                                                 json_signatures, asn1Spec)
    ber_file.write(ber_metadata)
  print('Wrote {}'.format(ber_filename))

  # 3. Read it back to check the signed hash.
  with open(ber_filename, 'rb') as ber_file:
    ber_metadata = ber_file.read()
  print('Read {}'.format(ber_filename))

  after_json = metadata.ber_to_json_metadata(get_json_signed, ber_metadata,
                                             asn1Spec)
  with open(json_out_filename, 'wb') as json_out_file:
    json.dump(after_json, json_out_file, sort_keys=True, indent=1,
              separators=(',', ': '))
  print('Wrote {}'.format(json_out_filename))


def sign_the_ber_not_the_json(json_in_filename, ber_filename, json_out_filename,
                              get_asn_signed, get_json_signed, asn1Spec):
  '''This function demonstrates how to encode JSON in BER, but *replacing* the
  signatures with the hash of the BER signed message, rather than of the entire
  JSON signed message.
  This is useful for exchanging time server messages, ECU version manifests,
  or vehicle version manifests between repositories and primaries, or primaries
  and secondaries.

  The first three parameters are: (1) the input JSON filename, (2) the
  intermediary BER filename, and (3) the output JSON filename.
  The fourth and fifth parameters are the get_asn_signed and get_json_signed
  functions from either the timestampmetadata, snapshotmetadata, rootmetadata,
  or targetsmetadata module, depending on which type of JSON metadata is being
  converted.
  The sixth parameter specifies the ASN.1 data structure for the message.
  For timestamp, snapshot, root, targets metadata, it is
  metadataverificationmodule.Metadata.
  For the signed time server response, it is timeservermodule.CurrentTime.
  For an ECU version manifest, it is bootloadermodule.ECUVersionManifest.
  For the vehicle version manifest, it is
  applicationmodule.VehicleVersionManifest.'''

  # Setup keys.
  with open(json_in_filename) as json_in_file:
    json_signatures = json.load(json_in_file)['signatures']
  for json_signature in json_signatures:
    tuf.repository_tool\
       .generate_and_write_ed25519_keypair(json_signature['keyid'],
                                           password='')

  def update_json_signature(ber_signed_digest, json_signature):
    keyid = json_signature['keyid']
    private_key = tuf.repository_tool\
                     .import_ed25519_privatekey_from_file(keyid,
                                                          password='')
    signature = tuf.keys.create_signature(private_key, ber_signed_digest)
    # NOTE: Update the original JSON signature object!
    json_signature['sig'] = signature['sig']

  def check_json_signature(json_signature):
    keyid = json_signature['keyid']
    public_key = tuf.repository_tool\
                    .import_ed25519_publickey_from_file('{}.pub'.format(keyid))
    hash = json_signature['hash']

    assert tuf.keys.verify_signature(public_key, json_signature, hash)

  # 1. Read from JSON.
  with open(json_in_filename, 'rb') as json_in_file:
    before_json = json.load(json_in_file)
  print('Read {}'.format(json_in_filename))
  json_signed = before_json['signed']
  json_signatures = before_json['signatures']

  # 2. Write the signed BER.
  asn_signed, ber_signed = metadata.get_asn_and_ber_signed(get_asn_signed,
                                                           json_signed)
  ber_signed_digest = hashlib.sha256(ber_signed).hexdigest()

  # NOTE: Use ber_signed_digest to *MODIFY* json_signatures.
  for json_signature in json_signatures:
    update_json_signature(ber_signed_digest, json_signature)

  with open (ber_filename, 'wb') as ber_file:
    ber_metadata = metadata.json_to_ber_metadata(asn_signed, ber_signed,
                                                 json_signatures, asn1Spec)
    ber_file.write(ber_metadata)
  print('Wrote {}'.format(ber_filename))

  # 3. Read it back to check the signed hash.
  with open(ber_filename, 'rb') as ber_file:
    ber_metadata = ber_file.read()
  print('Read {}'.format(ber_filename))

  # This function checks that, indeed,
  # Metadata.signatures[i].hash==hash(BER(Metadata.signed)).
  after_json = metadata.ber_to_json_metadata(get_json_signed, ber_metadata,
                                             asn1Spec)

  # NOTE: In after_json, check that each signature is of that hash.
  for json_signature in after_json['signatures']:
    check_json_signature(json_signature)

  with open(json_out_filename, 'wb') as json_out_file:
    json.dump(after_json, json_out_file, sort_keys=True, indent=1,
              separators=(',', ': '))
  print('Wrote {}'.format(json_out_filename))


if __name__ == '__main__':
  # These two functions are almost identical, except for a subtle difference.
  seamless_transport_of_json_over_ber('timestamp.json',
                                      'timestamp2.ber',
                                      'timestamp2.json',
                                      timestampmetadata.get_asn_signed,
                                      timestampmetadata.get_json_signed,
                                      metadataverificationmodule.Metadata)

  sign_the_ber_not_the_json('timestamp.json',
                            'timestamp3.ber',
                            'timestamp3.json',
                            timestampmetadata.get_asn_signed,
                            timestampmetadata.get_json_signed,
                            metadataverificationmodule.Metadata)
