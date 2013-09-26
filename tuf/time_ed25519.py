from __future__ import absolute_import, division, print_function 
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
                          data = "The quick brown fox jumped over the dog"',
                    number=1))

print('\nTiming ed25519.verify_signature()')
print(timeit.timeit('verify_signature(ed25519_key, signature, data)',
                    setup='from __main__ import generate, create_signature, verify_signature;\
                          ed25519_key = generate();\
                          data = "The quick brown fox jumped over the dog";\
                          signature = create_signature(ed25519_key, data)',
                    number=1))
