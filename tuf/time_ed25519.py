from __future__ import print_function, absolute_import, division
import timeit

import tuf
from tuf.ed25519_key import *

print('Timing ed25519.generate()')
print(timeit.timeit('generate()',
                    setup='from __main__ import generate',
                    number=1))

print('\nTiming ed25519.create_signature()')
print(timeit.timeit('create_signature(ed25519_key, data)',
                    setup='from __main__ import generate, create_signature;\
                          ed25519_key = generate();\
                          data = "The quick brown fox jumps over the lazy dog"',
                    number=1))

print('\nTiming ed25519.verify_signature()')
print(timeit.timeit('verify_signature(ed25519_key, signature, data)',
                    setup='from __main__ import generate, create_signature, verify_signature;\
                          ed25519_key = generate();\
                          data = "The quick brown fox jumps over the lazy dog";\
                          signature = create_signature(ed25519_key, data)',
                    number=1))
