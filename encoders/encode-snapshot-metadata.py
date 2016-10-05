#!/usr/bin/env python

from pyasn1.type import univ, char, namedtype, namedval, tag, constraint, useful

from pyasn1.codec.cer import encoder, decoder

from metadataverificationmodule import BinaryData,          \
                                       FilenameAndVersion,  \
                                       Hash,                \
                                       HashFunction,        \
                                       Metadata,            \
                                       RoleType,            \
                                       Signed,              \
                                       SignedBody,          \
                                       Signature,           \
                                       SignatureMethod,     \
                                       Signatures,          \
                                       SnapshotMetadata

metadata = Metadata()

signed = Signed().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
signed['type'] = int(RoleType('snapshot'))
signed['expires'] = "2030-01-01T00:00:00Z"
signed['version'] = 1

snapshotMetadata = SnapshotMetadata().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2))

targetsFilenameAndVersion = FilenameAndVersion()
targetsFilenameAndVersion['filename'] = 'targets.cer'
targetsFilenameAndVersion['version'] = 1
snapshotMetadata.setComponentByPosition(0, targetsFilenameAndVersion)

supplierOneFilenameAndVersion = FilenameAndVersion()
supplierOneFilenameAndVersion['filename'] = 'supplier1.cer'
supplierOneFilenameAndVersion['version'] = 1
snapshotMetadata.setComponentByPosition(1, supplierOneFilenameAndVersion)

supplierTwoFilenameAndVersion = FilenameAndVersion()
supplierTwoFilenameAndVersion['filename'] = 'supplier2.cer'
supplierTwoFilenameAndVersion['version'] = 1
snapshotMetadata.setComponentByPosition(2, supplierTwoFilenameAndVersion)

signedBody = SignedBody().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3))
signedBody.setComponentByName('snapshotMetadata', snapshotMetadata)
signed['body'] = signedBody
metadata['signed'] = signed

signatures = Signatures().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
signature = Signature()
signature['keyid'] = 'fce9cf1cc86b0945d6a042f334026f31ed8e4ee1510218f198e8d3f191d15309'
signature['method'] = int(SignatureMethod('ed25519'))
hash = Hash().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2))
hash['function'] = int(HashFunction('sha256'))
digest = BinaryData().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))
digest.setComponentByName('hexString', '16a0eeb0791b6c92451fd284dd9f599e0a7dbe7f6ebea6e2d2d06c7f74aec112')
hash['digest'] = digest
signature['hash'] = hash
signature['value'] = 'f7f03b13e3f4a78a23561419fc0dd741a637e49ee671251be9f8f3fceedfc112e44ee3aaff2278fad9164ab039118d4dc53f22f94900dae9a147aa4d35dcfc0f'
signatures.setComponentByPosition(0, signature)
metadata['signatures'] = signatures

print(metadata.prettyPrint())
before = encoder.encode(metadata)
filename = 'snapshotMetadata.cer'
with open(filename, 'wb') as a:
  a.write(before)

with open(filename, 'rb') as b:
  after = b.read()

tuples = decoder.decode(after, asn1Spec=Metadata())
recovered = tuples[0]
print(recovered.prettyPrint())
