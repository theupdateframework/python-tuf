#!/usr/bin/env python

from pyasn1.type import univ, char, namedtype, namedval, tag, constraint, useful

from pyasn1.codec.cer import encoder, decoder

from applicationmodule import BinaryData,                   \
                              ECUVersionManifest,           \
                              ECUVersionManifests,          \
                              ECUVersionManifestSigned,     \
                              Hash,                         \
                              HashFunction,                 \
                              Hashes,                       \
                              ImageBlock,                   \
                              ImageFile,                    \
                              Metadata,                     \
                              MetadataBroadcast,            \
                              MetadataFile,                 \
                              RoleType,                     \
                              Signed,                       \
                              SignedBody,                   \
                              Signature,                    \
                              SignatureMethod,              \
                              Signatures,                   \
                              Target,                       \
                              TimestampMetadata,            \
                              VehicleVersionManifest,       \
                              VehicleVersionManifestSigned

# VehicleVersionManifest
ecuVersionManifestSigned = ECUVersionManifestSigned().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
ecuVersionManifestSigned['ecuIdentifier'] = 'ABC1234567890'
ecuVersionManifestSigned['previousTime'] = "2016-01-01T00:00:00Z"
ecuVersionManifestSigned['currentTime'] = "2016-10-06T18:28:00Z"
ecuVersionManifestSigned['securityAttack'] = "Freeze attack detected."
installedImage = Target().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 4))
installedImage['filename'] = 'supplier1.img'
installedImage['length'] = 3948340
firstHashes = Hashes().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))
firstHash = Hash()
firstHash['function'] = int(HashFunction('sha256'))
firstDigest = BinaryData().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))
firstDigest['hexString'] = '753c5cab1e64c76c9601d9ea2a64f31bf6b0109ec36c15cecc38beacddc8a728'
firstHash['digest'] = firstDigest
firstHashes[0] = firstHash
installedImage['hashes'] = firstHashes
ecuVersionManifestSigned['installedImage'] = installedImage

secondarySignature = Signature().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))
secondarySignature['keyid'] = '1a2b4110927d4cba257262f614896179ff85ca1f1353a41b5224ac474ca71cb4'
secondarySignature['method'] = int(SignatureMethod('ed25519'))
secondaryHash = Hash().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2))
secondaryHash['function'] = int(HashFunction('sha256'))
secondaryDigest = BinaryData().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))
secondaryDigest['hexString'] = '323748f86a762247e6631bc01c26fb22c63fd0176a2e1db7b0d5b78de228cd86'
secondaryHash['digest'] = secondaryDigest
secondarySignature['hash'] = secondaryHash
secondarySignature['value'] = '90d2a06c7a6c2a6a93a9f5771eb2e5ce0c93dd580bebc2080d10894623cfd6eaedf4df84891d5aa37ace3ae3736a698e082e12c300dfe5aee92ea33a8f461f02'

ecuVersionManifest = ECUVersionManifest()
ecuVersionManifest['signed'] = ecuVersionManifestSigned
ecuVersionManifest['signature'] = secondarySignature

ecuVersionManifests = ECUVersionManifests().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))
ecuVersionManifests[0] = ecuVersionManifest

vehicleVersionManifestSigned = VehicleVersionManifestSigned().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
# http://randomvin.com/
vehicleVersionManifestSigned['vehicleIdentifier'] = '1XPCDB9X5RN345827'
vehicleVersionManifestSigned['primaryIdentifier'] = 'ABC0000000000'
vehicleVersionManifestSigned['ecuVersionManifests'] = ecuVersionManifests

vehicleVersionManifest = VehicleVersionManifest()
vehicleVersionManifest['signed'] = vehicleVersionManifestSigned
primarySignature = Signature().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))
primarySignature['keyid'] = '986a1b7135f4986150aa5fa0028feeaa66cdaf3ed6a00a355dd86e042f7fb494'
primarySignature['method'] = int(SignatureMethod('ed25519'))
primaryHash = Hash().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2))
primaryHash['function'] = int(HashFunction('sha256'))
primaryDigest = BinaryData().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))
primaryDigest['hexString'] = 'e8a9b7e87cba370aab1f100d64065ef6a5e95bee4decb582489319cce8565b0a'
primaryHash['digest'] = primaryDigest
primarySignature['hash'] = primaryHash
primarySignature['value'] = '90d2a06c7a6c2a6a93a9f5771eb2e5ce0c93dd580bebc2080d10894623cfd6eaedf4df84891d5aa37ace3ae3736a698e082e12c300dfe5aee92ea33a8f461f02'
vehicleVersionManifest['signature'] = primarySignature

print(vehicleVersionManifest.prettyPrint())
before = encoder.encode(vehicleVersionManifest)
filename = 'vehicleVersionManifest.cer'
with open(filename, 'wb') as a:
  a.write(before)

with open(filename, 'rb') as b:
  after = b.read()

tuples = decoder.decode(after, asn1Spec=VehicleVersionManifest())
recovered = tuples[0]
print(recovered.prettyPrint())

# MetadataBroadcast
metadataBroadcast = MetadataBroadcast()
metadataBroadcast['broadcastGUID'] = 21409173649268048596096
metadataBroadcast['numberOfMetadataFiles'] = 9

print(metadataBroadcast.prettyPrint())
before = encoder.encode(metadataBroadcast)
filename = 'metadataBroadcast.cer'
with open(filename, 'wb') as a:
  a.write(before)

with open(filename, 'rb') as b:
  after = b.read()

tuples = decoder.decode(after, asn1Spec=MetadataBroadcast())
recovered = tuples[0]
print(recovered.prettyPrint())

# MetadataFile
metadataFile = MetadataFile()
metadataFile['broadcastGUID'] = 21409173649268048596096
metadataFile['fileNumber'] = 1
metadataFile['filename'] = 'timestamp.cer'

# TODO: figure out how to decode from file, and assign this damned subtype
metadata = Metadata().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3))

signed = Signed().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
signed['type'] = int(RoleType('timestamp'))
signed['expires'] = "2030-01-01T00:00:00Z"
signed['version'] = 1

timestampMetadata = TimestampMetadata().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3))
timestampMetadata['filename'] = 'snapshot.ber'
timestampMetadata['version'] = 1

signedBody = SignedBody().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3))
signedBody['timestampMetadata'] = timestampMetadata
signed['body'] = signedBody
metadata['signed'] = signed

signatures = Signatures().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
signature = Signature()
signature['keyid'] = '1a2b4110927d4cba257262f614896179ff85ca1f1353a41b5224ac474ca71cb4'
signature['method'] = int(SignatureMethod('ed25519'))
hash = Hash().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2))
hash['function'] = int(HashFunction('sha256'))
digest = BinaryData().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))
digest['hexString'] = '323748f86a762247e6631bc01c26fb22c63fd0176a2e1db7b0d5b78de228cd86'
hash['digest'] = digest
signature['hash'] = hash
signature['value'] = '90d2a06c7a6c2a6a93a9f5771eb2e5ce0c93dd580bebc2080d10894623cfd6eaedf4df84891d5aa37ace3ae3736a698e082e12c300dfe5aee92ea33a8f461f02'
signatures[0] = signature
metadata['signatures'] = signatures
metadataFile['metadata'] = metadata

print(metadataFile.prettyPrint())
before = encoder.encode(metadataFile)
filename = 'metadataFile.cer'
with open(filename, 'wb') as a:
  a.write(before)

with open(filename, 'rb') as b:
  after = b.read()

tuples = decoder.decode(after, asn1Spec=MetadataFile())
recovered = tuples[0]
print(recovered.prettyPrint())

# ImageFile
imageFile = ImageFile()
imageFile['filename'] = 'supplier1.img'
imageFile['numberOfBlocks'] = 3
imageFile['blockSize'] = 1024

print(imageFile.prettyPrint())
before = encoder.encode(imageFile)
filename = 'imageFile.cer'
with open(filename, 'wb') as a:
  a.write(before)

with open(filename, 'rb') as b:
  after = b.read()

tuples = decoder.decode(after, asn1Spec=ImageFile())
recovered = tuples[0]
print(recovered.prettyPrint())

# ImageBlock
imageBlock = ImageBlock()
imageBlock['filename'] = 'supplier1.img'
imageBlock['blockNumber'] = 2
block = BinaryData().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2))
block['hexString'] = '496aca80e4d8f29fb8e8cd816c3afb48d3f103970b3a2ee1600c08ca67326dee'
imageBlock['block'] = block

print(imageBlock.prettyPrint())
before = encoder.encode(imageBlock)
filename = 'imageBlock.cer'
with open(filename, 'wb') as a:
  a.write(before)

with open(filename, 'rb') as b:
  after = b.read()

tuples = decoder.decode(after, asn1Spec=ImageBlock())
recovered = tuples[0]
print(recovered.prettyPrint())
