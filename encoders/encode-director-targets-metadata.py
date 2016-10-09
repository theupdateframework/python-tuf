#!/usr/bin/env python

from pyasn1.type import univ, char, namedtype, namedval, tag, constraint, useful

from pyasn1.codec.ber import encoder, decoder

from metadataverificationmodule import *

metadata = Metadata()

signed = Signed().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
signed['type'] = int(RoleType('targets'))
signed['expires'] = 1893474000
signed['version'] = 1

targetsMetadata = TargetsMetadata().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))
targets = Targets().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))

firstTargetAndCustom = TargetAndCustom()

firstTarget = Target().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
firstTarget['filename'] = 'supplier1.img'
firstTarget['length'] = 3948340
firstHashes = Hashes().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
firstHash = Hash()
firstHash['function'] = int(HashFunction('sha256'))
firstDigest = BinaryData().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))
firstDigest['hexString'] = '753c5cab1e64c76c9601d9ea2a64f31bf6b0109ec36c15cecc38beacddc8a728'
firstHash['digest'] = firstDigest
firstHashes[0] = firstHash
firstSequenceOfHashes = SequenceOfHashes().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2))
firstSequenceOfHashes['length'] = 1
firstSequenceOfHashes['hashes'] = firstHashes
firstTarget['hashes'] = firstSequenceOfHashes
firstTargetAndCustom['target'] = firstTarget

firstCustom = Custom().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))
firstCustom['ecuIdentifier'] = 'ABC1234567890'
firstEncryptedTarget = Target().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))
firstEncryptedTarget['filename'] = 'supplier1.encrypted.img'
firstEncryptedTarget['length'] = 4053028
firstEncryptedHashes = Hashes().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
firstEncryptedHash = Hash()
firstEncryptedHash['function'] = int(HashFunction('sha256'))
firstEncryptedDigest = BinaryData().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))
firstEncryptedDigest['hexString'] = '10274046037ef8d263117170bcc940411276303a0e496c130ae3f13ecac2c808'
firstEncryptedHash['digest'] = firstEncryptedDigest
firstEncryptedHashes[0] = firstEncryptedHash
firstEncryptedSequenceOfHashes = SequenceOfHashes().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2))
firstEncryptedSequenceOfHashes['length'] = 1
firstEncryptedSequenceOfHashes['hashes'] = firstEncryptedHashes
firstEncryptedTarget['hashes'] = firstEncryptedSequenceOfHashes
firstCustom['encryptedTarget'] = firstEncryptedTarget
firstEncryptedSymmetricKey = EncryptedSymmetricKey().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2))
firstEncryptedSymmetricKey['encryptedSymmetricKeyType'] = EncryptedSymmetricKeyType('aes128').subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
firstEncryptedSymmetricKeyValue = BinaryData().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))
firstEncryptedSymmetricKeyValue['base64String'] = 'YWJjZGVmZ2gxMjM0NTY3OA=='
firstEncryptedSymmetricKey['encryptedSymmetricKeyValue'] = firstEncryptedSymmetricKeyValue
firstCustom['encryptedSymmetricKey'] = firstEncryptedSymmetricKey
firstTargetAndCustom['custom'] = firstCustom

targets[0] = firstTargetAndCustom
sequenceOfTargets = SequenceOfTargets().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
sequenceOfTargets['length'] = 1
sequenceOfTargets['targets'] = targets
targetsMetadata['targets'] = sequenceOfTargets

signedBody = SignedBody().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3))
signedBody['targetsMetadata'] = targetsMetadata
signed['body'] = signedBody
metadata['signed'] = signed

signatures = Signatures().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
signature = Signature()
signature['keyid'] = '93ec2c3dec7cc08922179320ccd8c346234bf7f21705268b93e990d5273a2a3b'
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
filename = 'directorTargetsMetadata.ber'
with open(filename, 'wb') as a:
  a.write(before)

with open(filename, 'rb') as b:
  after = b.read()

tuples = decoder.decode(after, asn1Spec=Metadata())
recovered = tuples[0]
print(recovered.prettyPrint())
