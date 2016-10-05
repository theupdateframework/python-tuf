#!/usr/bin/env python

from pyasn1.type import univ, char, namedtype, namedval, tag, constraint, useful

from pyasn1.codec.cer import encoder, decoder

from metadataverificationmodule import BinaryData,      \
                                       Hash,            \
                                       HashFunction,    \
                                       Metadata,        \
                                       RoleType,        \
                                       Signed,          \
                                       SignedBody,      \
                                       Signature,       \
                                       SignatureMethod, \
                                       Signatures,      \
                                       TimestampMetadata

metadata = Metadata()

signed = Signed().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
signed['type'] = int(RoleType('timestamp'))
signed['expires'] = "2030-01-01T00:00:00Z"
signed['version'] = 1

timestampMetadata = TimestampMetadata().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3))
timestampMetadata['filename'] = 'snapshot.ber'
timestampMetadata['version'] = 1
signedBody = SignedBody().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3))
signedBody.setComponentByName('timestampMetadata', timestampMetadata)
signed['body'] = signedBody

metadata['signed'] = signed

signatures = Signatures().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
signature = Signature()
signature['keyid'] = '47e327152bab6f2ede2922a9805124d2f5d42087a34003048cf068c00a1285d2'
signature['method'] = int(SignatureMethod('ed25519'))
hash = Hash().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2))
hash['function'] = int(HashFunction('sha256'))
digest = BinaryData().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))
digest.setComponentByName('hexString', 'f0af17449a83681de22db7ce16672f16f37131bec0022371d4ace5d1854301e0')
hash['digest'] = digest
signature['hash'] = hash
signatures.setComponentByPosition(0, signature)

metadata['signatures'] = signatures

print(metadata.prettyPrint())
before = encoder.encode(metadata)
filename = 'timestampMetadata.cer'
with open(filename, 'wb') as a:
  a.write(before)

with open(filename, 'rb') as b:
  after = b.read()

tuples = decoder.decode(after, asn1Spec=Metadata())
recovered = tuples[0]
print(recovered.prettyPrint())
