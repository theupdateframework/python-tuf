from __future__ import print_function, absolute_import, division
import sys
import timeit

import tuf
from tuf.ed25519_keys import *

use_pynacl = False
if '--pynacl' in sys.argv:
  use_pynacl = True
  
print('Time generate_public_and_private()')
print(timeit.timeit('generate_public_and_private(use_pynacl)',
                    setup='from __main__ import generate_public_and_private, \
                                                use_pynacl',
                    number=1))

print('\nTime create_signature()')
print(timeit.timeit('create_signature(public, private, data, use_pynacl)',
                    setup='from __main__ import generate_public_and_private, \
                                                create_signature, \
                                                use_pynacl; \
                          public, private = \
                            generate_public_and_private(use_pynacl); \
                          data = "The quick brown fox jumps over the lazy dog"',
                    number=1))

print('\nTime verify_signature()')
print(timeit.timeit('verify_signature(public, method, signature, data, use_pynacl)',
                    setup='from __main__ import generate_public_and_private, \
                                                create_signature, \
                                                verify_signature, use_pynacl; \
                          public, private = \
                            generate_public_and_private(use_pynacl); \
                          data = "The quick brown fox jumps over the lazy dog";\
                          signature, method = \
                            create_signature(public, private, data, use_pynacl)',
                    number=1))
