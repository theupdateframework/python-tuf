"""
<Program Name>
  conf.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  April 4, 2012.  Based a previous version by Geremy Condra.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  A central location for TUF configuration settings.  Example options include
  setting the destination of temporary files and downloaded content, the maximum
  length of downloaded metadata (unknown file attributes), download behavior,
  and cryptography libraries clients wish to use.
"""

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

# Set a directory that should be used for all temporary files. If this
# is None, then the system default will be used. The system default
# will also be used if a directory path set here is invalid or
# unusable.
temporary_directory = None

# The directory under which metadata for all repositories will be
# stored. This is not a simple cache because each repository's root of
# trust (root.json) will need to already be stored below here and should
# not be deleted. At a minimum, each key in the mirrors dictionary
# below should have a directory under 'repository_directory'
# which already exists and within that directory should have the file
# 'metadata/current/root.json'. This MUST be set.
repository_directory = None

# A PEM (RFC 1422) file where you may find SSL certificate authorities
# https://en.wikipedia.org/wiki/Certificate_authority
# http://docs.python.org/2/library/ssl.html#certificates
ssl_certificates = None

# Since the timestamp role does not have signed metadata about itself, we set a
# default but sane upper bound for the number of bytes required to download it.
DEFAULT_TIMESTAMP_REQUIRED_LENGTH = 16384 #bytes

# The Root role may be updated without knowing its hash if top-level metadata
# cannot be safely downloaded (e.g., keys may have been revoked, thus requiring
# a new Root file that includes the updated keys).  Set a default upper bound
# for the maximum total bytes that may be downloaded for Root metadata.
DEFAULT_ROOT_REQUIRED_LENGTH = 512000 #bytes

# Set a timeout value in seconds (float) for non-blocking socket operations.
SOCKET_TIMEOUT = 2 #seconds

# The maximum chunk of data, in bytes, we would download in every round.
CHUNK_SIZE = 8192 #bytes

# The minimum average of download speed (bytes/second) that must be met to
# avoid being considered as a slow retrieval attack.
MIN_AVERAGE_DOWNLOAD_SPEED = CHUNK_SIZE #bytes/second

# The time (in seconds) we ignore a server with a slow initial retrieval speed.
SLOW_START_GRACE_PERIOD = 3 #seconds

# The current "good enough" number of PBKDF2 passphrase iterations.
# We recommend that important keys, such as root, be kept offline.
# 'tuf.conf.PBKDF2_ITERATIONS' should increase as CPU speeds increase, set here
# at 100,000 iterations by default (in 2013).  The repository maintainer may opt
# to modify the default setting according to their security needs and
# computational restrictions.  A strong user password is still important.
# Modifying the number of iterations will result in a new derived key+PBDKF2
# combination if the key is loaded and re-saved, overriding any previous
# iteration setting used in the old '<keyid>' key file.
# https://en.wikipedia.org/wiki/PBKDF2
PBKDF2_ITERATIONS = 100000

# The user client may set the specific cryptography library used by The Update
# Framework updater, or the software updater integrating TUF.  
# Supported RSA cryptography libraries:  ['pycrypto']
RSA_CRYPTO_LIBRARY = 'pycrypto'

# Supported ed25519 cryptography libraries: ['pynacl', 'ed25519']
ED25519_CRYPTO_LIBRARY = 'ed25519'

# General purpose cryptography. Algorithms and functions that fall under general
# purpose include AES, PBKDF2, cryptographically strong random number
# generators, and cryptographic hash functions.  The majority of the general
# cryptography is needed by the repository and developer tools.
# RSA_CRYPTO_LIBRARY and ED25519_CRYPTO_LIBRARY are needed on the client side
# of the software updater.
GENERAL_CRYPTO_LIBRARY = 'pycrypto'

# The algorithm(s) in REPOSITORY_HASH_ALGORITHMS are chosen by the repository tool
# to generate the digests listed in metadata and prepended to the filenames of
# consistent snapshots.
REPOSITORY_HASH_ALGORITHMS = ['sha256']
