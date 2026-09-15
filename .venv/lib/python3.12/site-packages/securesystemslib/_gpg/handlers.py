"""
<Module Name>
  handlers.py

<Author>
  Santiago Torres-Arias <santiago@nyu.edu>

<Started>
  Jan 15, 2020

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Provides links from signatures/algorithms to modules implementing
  the signature verification and key parsing.
"""

from securesystemslib._gpg import dsa, eddsa, rsa

# See section 9.1. (public-key algorithms) of RFC4880 (-bis8)
SUPPORTED_SIGNATURE_ALGORITHMS = {
    0x01: {"type": "rsa", "method": "pgp+rsa-pkcsv1.5", "handler": rsa},
    0x11: {"type": "dsa", "method": "pgp+dsa-fips-180-2", "handler": dsa},
    0x16: {"type": "eddsa", "method": "pgp+eddsa-ed25519", "handler": eddsa},
}

SIGNATURE_HANDLERS = {"rsa": rsa, "dsa": dsa, "eddsa": eddsa}
