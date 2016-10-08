#!/usr/bin/env python

from pyasn1.type import univ, char, namedtype, namedval, tag, constraint, useful

from pyasn1.codec.ber import encoder, decoder

from metadataverificationmodule import BinaryData,              \
                                       DelegatedTargetsRoles,   \
                                       DelegatedTargetsRole,    \
                                       Hash,                    \
                                       HashFunction,            \
                                       Hashes,                  \
                                       Keyid,                   \
                                       Keyids,                  \
                                       Metadata,                \
                                       Path,                    \
                                       Paths,                   \
                                       PathsToRoles,            \
                                       PrioritizedPathsToRoles, \
                                       PublicKey,               \
                                       PublicKeyType,           \
                                       PublicKeys,              \
                                       RoleName,                \
                                       RoleNames,               \
                                       RoleType,                \
                                       Signed,                  \
                                       SignedBody,              \
                                       Signature,               \
                                       SignatureMethod,         \
                                       Signatures,              \
                                       Targets,                 \
                                       Target,                  \
                                       TargetAndCustom,         \
                                       TargetsDelegations,      \
                                       TargetsMetadata

metadata = Metadata()

signed = Signed().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
signed['type'] = int(RoleType('targets'))
signed['expires'] = "2030-01-01T00:00:00Z"
signed['version'] = 1

targetsMetadata = TargetsMetadata().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))
targets = Targets().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
delegations = TargetsDelegations().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))

firstTargetAndCustom = TargetAndCustom()
firstTarget = Target().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
firstTarget['filename'] = 'supplier1.img'
firstTarget['length'] = 3948340
firstHashes = Hashes().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))
firstHash = Hash()
firstHash['function'] = int(HashFunction('sha256'))
firstDigest = BinaryData().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))
firstDigest['hexString'] = '753c5cab1e64c76c9601d9ea2a64f31bf6b0109ec36c15cecc38beacddc8a728'
firstHash['digest'] = firstDigest
firstHashes[0] = firstHash
firstTarget['hashes'] = firstHashes
firstTargetAndCustom['target'] = firstTarget
targets[0] = firstTargetAndCustom

keys = PublicKeys().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
firstPublicKey = PublicKey()
firstPublicKey['publicKeyid'] = 'e0685506e51ad56014771e465188a327cab597953c30789e294ebb3d274a251f'
firstPublicKey['publicKeyType'] = int(PublicKeyType('ed25519'))
firstPublicKeyValue = BinaryData().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2))
firstPublicKeyValue['hexString'] = '66dd78c5c2a78abc6fc6b267ff1a8017ba0e8bfc853dd97af351949bba021275'
firstPublicKey['publicKeyValue'] = firstPublicKeyValue
keys[0] = firstPublicKey
delegations['keys'] = keys

roles = DelegatedTargetsRoles().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
firstRole = DelegatedTargetsRole()
firstRole['rolename'] = 'supplier2'
firstRoleKeyids = Keyids().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))
firstRoleKeyid = Keyid('e0685506e51ad56014771e465188a327cab597953c30789e294ebb3d274a251f')
firstRoleKeyids[0] = firstRoleKeyid
firstRole['keyids'] = firstRoleKeyids
firstRole['threshold'] = 1
roles[0] = firstRole
delegations['roles'] = roles

prioritizedPathsToRoles = PrioritizedPathsToRoles().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))
firstPathsToRoles = PathsToRoles()
firstPaths = Paths().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
firstPath = Path('*supplier2*')
firstPaths[0] = firstPath
firstPathsToRoles['paths'] = firstPaths
firstRoles = RoleNames().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
firstRole = RoleName('supplier2')
firstRoles[0] = firstRole
firstPathsToRoles['roles'] = firstRoles
firstPathsToRoles['terminating'] = True
prioritizedPathsToRoles[0] = firstPathsToRoles
delegations['prioritizedPathsToRoles'] = prioritizedPathsToRoles

targetsMetadata['targets'] = targets
targetsMetadata['delegations'] = delegations

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
metadata['signatures'] = signatures

print(metadata.prettyPrint())
before = encoder.encode(metadata)
filename = 'supplierTargetsMetadata.ber'
with open(filename, 'wb') as a:
  a.write(before)

with open(filename, 'rb') as b:
  after = b.read()

tuples = decoder.decode(after, asn1Spec=Metadata())
recovered = tuples[0]
print(recovered.prettyPrint())
