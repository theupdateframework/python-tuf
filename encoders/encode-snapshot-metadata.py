#!/usr/bin/env python

from pyasn1.type import univ, char, namedtype, namedval, tag, constraint, useful

from pyasn1.codec.ber import encoder, decoder

from metadataverificationmodule import *

metadata = Metadata()

signed = Signed().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
signed['type'] = int(RoleType('snapshot'))
signed['expires'] = 1893474000
signed['version'] = 1

filenameAndVersions = FilenameAndVersions().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))

targetsFilenameAndVersion = FilenameAndVersion()
targetsFilenameAndVersion['filename'] = 'targets.ber'
targetsFilenameAndVersion['version'] = 1
filenameAndVersions[0] = targetsFilenameAndVersion

supplierOneFilenameAndVersion = FilenameAndVersion()
supplierOneFilenameAndVersion['filename'] = 'supplier1.ber'
supplierOneFilenameAndVersion['version'] = 1
filenameAndVersions[1] = supplierOneFilenameAndVersion

supplierTwoFilenameAndVersion = FilenameAndVersion()
supplierTwoFilenameAndVersion['filename'] = 'supplier2.ber'
supplierTwoFilenameAndVersion['version'] = 1
filenameAndVersions[2] = supplierTwoFilenameAndVersion

signedBody = SignedBody().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3))
snapshotMetadata = SnapshotMetadata().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2))
snapshotMetadata['length'] = 3
snapshotMetadata['filenameAndVersions'] = filenameAndVersions
signedBody['snapshotMetadata'] = snapshotMetadata
signed['body'] = signedBody
metadata['signed'] = signed

signatures = Signatures().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
signature = Signature()
signature['keyid'] = 'fce9cf1cc86b0945d6a042f334026f31ed8e4ee1510218f198e8d3f191d15309'
signature['method'] = int(SignatureMethod('ed25519'))
hash = Hash().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2))
hash['function'] = int(HashFunction('sha256'))
digest = BinaryData().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))
digest['hexString'] = '16a0eeb0791b6c92451fd284dd9f599e0a7dbe7f6ebea6e2d2d06c7f74aec112'
hash['digest'] = digest
signature['hash'] = hash
signature['value'] = 'f7f03b13e3f4a78a23561419fc0dd741a637e49ee671251be9f8f3fceedfc112e44ee3aaff2278fad9164ab039118d4dc53f22f94900dae9a147aa4d35dcfc0f'
signatures[0] = signature
sequenceOfSignatures = SequenceOfSignatures().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))
sequenceOfSignatures['length'] = 1
sequenceOfSignatures['signatures'] = signatures
metadata['signatures'] = sequenceOfSignatures

before = encoder.encode(metadata)
filename = 'snapshotMetadata.ber'
with open(filename, 'wb') as a:
  a.write(before)

with open(filename, 'rb') as b:
  after = b.read()

tuples = decoder.decode(after, asn1Spec=Metadata())
recovered = tuples[0]
print(recovered.prettyPrint())
