#!/usr/bin/env python

from pyasn1.type import univ, char, namedtype, namedval, tag, constraint, useful

from pyasn1.codec.ber import encoder, decoder

from metadataverificationmodule import BinaryData,      \
                                       Hash,            \
                                       HashFunction,    \
                                       Keyid,           \
                                       Keyids,          \
                                       Metadata,        \
                                       PublicKey,       \
                                       PublicKeyType,   \
                                       PublicKeys,      \
                                       RoleType,        \
                                       RootMetadata,    \
                                       Signed,          \
                                       SignedBody,      \
                                       Signature,       \
                                       SignatureMethod, \
                                       Signatures,      \
                                       TopLevelRole,    \
                                       TopLevelRoles

metadata = Metadata()

signed = Signed().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
signed['type'] = int(RoleType('root'))
signed['expires'] = 1893474000
signed['version'] = 1

rootMetadata = RootMetadata().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))

keys = PublicKeys().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))

rootPublicKey = PublicKey()
rootPublicKey['publicKeyid'] = 'f2d5020d08aea06a0a9192eb6a4f549e17032ebefa1aa9ac167c1e3e727930d6'
rootPublicKey['publicKeyType'] = int(PublicKeyType('ed25519'))
rootPublicKeyValue = BinaryData().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2))
rootPublicKeyValue['hexString'] = '66dd78c5c2a78abc6fc6b267ff1a8017ba0e8bfc853dd97af351949bba021275'
rootPublicKey['publicKeyValue'] = rootPublicKeyValue
keys[0] = rootPublicKey

timestampPublicKey = PublicKey()
timestampPublicKey['publicKeyid'] = '1a2b4110927d4cba257262f614896179ff85ca1f1353a41b5224ac474ca71cb4'
timestampPublicKeyValue = BinaryData().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2))
timestampPublicKey['publicKeyType'] = int(PublicKeyType('ed25519'))
timestampPublicKeyValue['hexString'] = '72378e5bc588793e58f81c8533da64a2e8f1565c1fcc7f253496394ffc52542c'
timestampPublicKey['publicKeyValue'] = timestampPublicKeyValue
keys[1] = timestampPublicKey

snapshotPublicKey = PublicKey()
snapshotPublicKey['publicKeyid'] = 'fce9cf1cc86b0945d6a042f334026f31ed8e4ee1510218f198e8d3f191d15309'
snapshotPublicKey['publicKeyType'] = int(PublicKeyType('ed25519'))
snapshotPublicKeyValue = BinaryData().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2))
snapshotPublicKeyValue['hexString'] = '01c61f8dc7d77fcef973f4267927541e355e8ceda757e2c402818dad850f856e'
snapshotPublicKey['publicKeyValue'] = snapshotPublicKeyValue
keys[2] = snapshotPublicKey

targetsPublicKey = PublicKey()
targetsPublicKey['publicKeyid'] = '93ec2c3dec7cc08922179320ccd8c346234bf7f21705268b93e990d5273a2a3b'
targetsPublicKey['publicKeyType'] = int(PublicKeyType('ed25519'))
targetsPublicKeyValue = BinaryData().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2))
targetsPublicKeyValue['hexString'] = '68ead6e54a43f8f36f9717b10669d1ef0ebb38cee6b05317669341309f1069cb'
targetsPublicKey['publicKeyValue'] = targetsPublicKeyValue
keys[3] = targetsPublicKey

rootMetadata['keys'] = keys

roles = TopLevelRoles().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))

rootRole = TopLevelRole()
rootRole['role'] = int(RoleType('root'))
rootRoleKeyids = Keyids().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))
rootRoleKeyid = Keyid('f2d5020d08aea06a0a9192eb6a4f549e17032ebefa1aa9ac167c1e3e727930d6')
# Some damned bug in pyasn1 I could not care less to fix right now.
rootRoleKeyids.setComponentByPosition(0, rootRoleKeyid, False)
rootRole['keyids'] = rootRoleKeyids
rootRole['threshold'] = 1
roles[0] = rootRole

snapshotRole = TopLevelRole()
snapshotRole['role'] = int(RoleType('snapshot'))
snapshotRoleKeyids = Keyids().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))
snapshotRoleKeyid = Keyid('fce9cf1cc86b0945d6a042f334026f31ed8e4ee1510218f198e8d3f191d15309')
# Some damned bug in pyasn1 I could not care less to fix right now.
snapshotRoleKeyids.setComponentByPosition(0, snapshotRoleKeyid, False)
snapshotRole['keyids'] = snapshotRoleKeyids
snapshotRole['threshold'] = 1
roles[1] = snapshotRole

targetsRole = TopLevelRole()
targetsRole['role'] = int(RoleType('targets'))
targetsRoleKeyids = Keyids().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))
targetsRoleKeyid = Keyid('93ec2c3dec7cc08922179320ccd8c346234bf7f21705268b93e990d5273a2a3b')
# Some damned bug in pyasn1 I could not care less to fix right now.
targetsRoleKeyids.setComponentByPosition(0, targetsRoleKeyid, False)
targetsRole['keyids'] = targetsRoleKeyids
targetsRole['threshold'] = 1
roles[2] = targetsRole

timestampRole = TopLevelRole()
timestampRole['role'] = int(RoleType('timestamp'))
timestampRoleKeyids = Keyids().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))
timestampRoleKeyid = Keyid('1a2b4110927d4cba257262f614896179ff85ca1f1353a41b5224ac474ca71cb4')
# Some damned bug in pyasn1 I could not care less to fix right now.
timestampRoleKeyids.setComponentByPosition(0, timestampRoleKeyid, False)
timestampRole['keyids'] = timestampRoleKeyids
timestampRole['threshold'] = 1
roles[3] = timestampRole

rootMetadata['roles'] = roles

signedBody = SignedBody().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3))
signedBody['rootMetadata'] = rootMetadata
signed['body'] = signedBody
metadata['signed'] = signed

signatures = Signatures().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
signature = Signature()
signature['keyid'] = rootPublicKey['publicKeyid']
signature['method'] = int(SignatureMethod('ed25519'))
hash = Hash().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2))
hash['function'] = int(HashFunction('sha256'))
digest = BinaryData().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))
digest['hexString'] = '4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2'
hash['digest'] = digest
signature['hash'] = hash
signature['value'] = 'a312b9c3cb4a1b693e8ebac5ee1ca9cc01f2661c14391917dcb111517f72370809f32c890c6b801e30158ac4efe0d4d87317223077784c7a378834249d048306'
signatures[0] = signature
metadata['signatures'] = signatures

print(metadata.prettyPrint())
before = encoder.encode(metadata)
filename = 'rootMetadata.ber'
with open(filename, 'wb') as a:
  a.write(before)

with open(filename, 'rb') as b:
  after = b.read()

tuples = decoder.decode(after, asn1Spec=Metadata())
recovered = tuples[0]
print(recovered.prettyPrint())
