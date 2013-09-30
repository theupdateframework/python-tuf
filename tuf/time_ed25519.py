from __future__ import print_function, absolute_import, division
import sys
import timeit

import tuf
from tuf.ed25519_key import *

use_pynacl = False
if '--pynacl' in sys.argv:
  use_pynacl = True
  
print('Time generate()')
print(timeit.timeit('generate(use_pynacl)',
                    setup='from __main__ import generate, use_pynacl',
                    number=1))

print('\nTime create_signature()')
print(timeit.timeit('create_signature(ed25519_key, data, use_pynacl)',
                    setup='from __main__ import generate, create_signature, \
                                                use_pynacl; \
                          ed25519_key = generate(use_pynacl);\
                          data = "The quick brown fox jumps over the lazy dog"',
                    number=1))

print('\nTime verify_signature()')
print(timeit.timeit('verify_signature(ed25519_key, signature, data, use_pynacl)',
                    setup='from __main__ import generate, create_signature, \
                                                verify_signature, use_pynacl;\
                          ed25519_key = generate(use_pynacl);\
                          data = "The quick brown fox jumps over the lazy dog";\
                          signature = create_signature(ed25519_key, data, use_pynacl)',
                    number=1))
