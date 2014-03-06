from ed25519 import *

assert b >= 10
assert 8 * len(H("hash input")) == 2 * b
assert expmod(2,q-1,q) == 1
assert q % 4 == 1
assert expmod(2,l-1,l) == 1
assert l >= 2**(b-4)
assert l <= 2**(b-3)
assert expmod(d,(q-1)/2,q) == q-1
assert expmod(I,2,q) == q-1
assert isoncurve(B)
assert scalarmult(B,l) == [0,1]
