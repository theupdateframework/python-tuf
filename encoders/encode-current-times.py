#!/usr/bin/env python

from pyasn1.type import univ, char, namedtype, namedval, tag, constraint, useful

from pyasn1.codec.cer import encoder, decoder

from timeservermodule import  BinaryData,         \
                              CurrentTime,        \
                              CurrentTimes,       \
                              Hash,               \
                              HashFunction,       \
                              NonceAndTimestamp,  \
                              Signature,          \
                              SignatureMethod,    \
                              Signatures

currentTimes = CurrentTimes()

firstNonceAndTimeStamp = NonceAndTimestamp().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
firstNonceAndTimeStamp['nonce'] = 42
firstNonceAndTimeStamp['timestamp'] = "2030-01-01T00:00:00Z"

firstSignatures = Signatures().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
firstSignature = Signature()
firstSignature['keyid'] = '521cbdaa188030b3c06f60f6271b4e22d4f3dcfcfaa5969e73c645da3228eaec'
firstSignature['method'] = int(SignatureMethod('ed25519'))
firstHash = Hash().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2))
firstHash['function'] = int(HashFunction('sha256'))
firstDigest = BinaryData().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))
firstDigest['hexString'] = 'e8e0be17af502722c78dbaf99017b43816f63bab9aacc77558c38115622a4871'
firstHash['digest'] = firstDigest
firstSignature['hash'] = firstHash
firstSignature['value'] = '90d2a06c7a6c2a6a93a9f5771eb2e5ce0c93dd580bebc2080d10894623cfd6eaedf4df84891d5aa37ace3ae3736a698e082e12c300dfe5aee92ea33a8f461f02'
firstSignatures[0] = firstSignature

firstCurrentTime = CurrentTime()
firstCurrentTime['signed'] = firstNonceAndTimeStamp
firstCurrentTime['signatures'] = firstSignatures
currentTimes[0] = firstCurrentTime

secondNonceAndTimeStamp = NonceAndTimestamp().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
secondNonceAndTimeStamp['nonce'] = 2016
secondNonceAndTimeStamp['timestamp'] = "2030-01-01T00:00:00Z"

secondSignatures = Signatures().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
secondSignature = Signature()
secondSignature['keyid'] = '521cbdaa188030b3c06f60f6271b4e22d4f3dcfcfaa5969e73c645da3228eaec'
secondSignature['method'] = int(SignatureMethod('ed25519'))
secondHash = Hash().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2))
secondHash['function'] = int(HashFunction('sha256'))
secondDigest = BinaryData().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))
secondDigest['hexString'] = 'e8e0be17af502722c78dbaf99017b43816f63bab9aacc77558c38115622a4871'
secondHash['digest'] = secondDigest
secondSignature['hash'] = secondHash
secondSignature['value'] = '90d2a06c7a6c2a6a93a9f5771eb2e5ce0c93dd580bebc2080d10894623cfd6eaedf4df84891d5aa37ace3ae3736a698e082e12c300dfe5aee92ea33a8f461f02'
secondSignatures[0] = secondSignature

secondCurrentTime = CurrentTime()
secondCurrentTime['signed'] = secondNonceAndTimeStamp
secondCurrentTime['signatures'] = secondSignatures
currentTimes[1] = secondCurrentTime

print(currentTimes.prettyPrint())
before = encoder.encode(currentTimes)
filename = 'currentTimes.cer'
with open(filename, 'wb') as a:
  a.write(before)

with open(filename, 'rb') as b:
  after = b.read()

tuples = decoder.decode(after, asn1Spec=CurrentTimes())
recovered = tuples[0]
print(recovered.prettyPrint())
