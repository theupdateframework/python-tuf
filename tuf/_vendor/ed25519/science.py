import os
import timeit

import ed25519


seed = os.urandom(32)

data = "The quick brown fox jumps over the lazy dog"
private_key = seed
public_key = ed25519.publickey(seed)
signature = ed25519.signature(data, private_key, public_key)


print('Time generate')
print(timeit.timeit("ed25519.publickey(seed)",
    setup="from __main__ import ed25519, seed",
    number=10,
))

print('\nTime create signature')
print(timeit.timeit("ed25519.signature(data, private_key, public_key)",
    setup="from __main__ import ed25519, data, private_key, public_key",
    number=10,
))


print('\nTime verify signature')
print(timeit.timeit("ed25519.checkvalid(signature, data, public_key)",
    setup="from __main__ import ed25519, signature, data, public_key",
    number=10,
))
