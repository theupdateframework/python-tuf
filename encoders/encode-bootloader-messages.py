#!/usr/bin/env python

from pyasn1.type import univ, char, namedtype, namedval, tag, constraint, useful

from pyasn1.codec.ber import encoder, decoder

from bootloadermodule import  *

# ImageRequest
imageRequest = ImageRequest()
imageRequest['filename'] = 'supplier1.img'

print(imageRequest.prettyPrint())
before = encoder.encode(imageRequest)
filename = 'imageRequest.ber'
with open(filename, 'wb') as a:
  a.write(before)

with open(filename, 'rb') as b:
  after = b.read()

tuples = decoder.decode(after, asn1Spec=ImageRequest())
recovered = tuples[0]
print(recovered.prettyPrint())

# VersionReport
ecuVersionManifestSigned = ECUVersionManifestSigned().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
ecuVersionManifestSigned['ecuIdentifier'] = 'ABC1234567890'
ecuVersionManifestSigned['previousTime'] = 1451624400
ecuVersionManifestSigned['currentTime'] = 1475956320
ecuVersionManifestSigned['securityAttack'] = "Freeze attack detected."
installedImage = Target().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 4))
installedImage['filename'] = 'supplier1.img'
installedImage['length'] = 3948340
firstHashes = Hashes().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))
firstHash = Hash()
firstHash['function'] = int(HashFunction('sha256'))
firstDigest = BinaryData().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))
firstDigest['hexString'] = '753c5cab1e64c76c9601d9ea2a64f31bf6b0109ec36c15cecc38beacddc8a728'
firstHash['digest'] = firstDigest
firstHashes[0] = firstHash
installedImage['numberOfHashes'] = 1
installedImage['hashes'] = firstHashes
ecuVersionManifestSigned['installedImage'] = installedImage

signature = Signature().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))
signature['keyid'] = '1a2b4110927d4cba257262f614896179ff85ca1f1353a41b5224ac474ca71cb4'
signature['method'] = int(SignatureMethod('ed25519'))
hash = Hash().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2))
hash['function'] = int(HashFunction('sha256'))
digest = BinaryData().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))
digest['hexString'] = '323748f86a762247e6631bc01c26fb22c63fd0176a2e1db7b0d5b78de228cd86'
hash['digest'] = digest
signature['hash'] = hash
signature['value'] = '90d2a06c7a6c2a6a93a9f5771eb2e5ce0c93dd580bebc2080d10894623cfd6eaedf4df84891d5aa37ace3ae3736a698e082e12c300dfe5aee92ea33a8f461f02'

ecuVersionManifest = ECUVersionManifest().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))
ecuVersionManifest['signed'] = ecuVersionManifestSigned
ecuVersionManifest['signature'] = signature

versionReport = VersionReport()
versionReport['nonceForTimeServer'] = 42
versionReport['ecuVersionManifest'] = ecuVersionManifest

before = encoder.encode(versionReport)
filename = 'versionReport.ber'
with open(filename, 'wb') as a:
  a.write(before)

with open(filename, 'rb') as b:
  after = b.read()

tuples = decoder.decode(after, asn1Spec=VersionReport())
recovered = tuples[0]
print(recovered.prettyPrint())
