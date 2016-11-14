"""
<Program Name>
  settings.py

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

# The 'log.py' module manages TUF's logging system.  Users have the option to
# enable/disable logging to a file via 'ENABLE_FILE_LOGGING'
ENABLE_FILE_LOGGING = True

# If file logging is enabled via 'ENABLE_FILE_LOGGING', TUF log messages will
# be saved to 'LOG_FILENAME'
LOG_FILENAME = 'tuf.log'

# Since the timestamp role does not have signed metadata about itself, we set a
# default but sane upper bound for the number of bytes required to download it.
DEFAULT_TIMESTAMP_REQUIRED_LENGTH = 16384 #bytes

# The Root role may be updated without knowing its version if top-level
# metadata cannot be safely downloaded (e.g., keys may have been revoked, thus
# requiring a new Root file that includes the updated keys).  Set a default
# upper bound for the maximum total bytes that may be downloaded for Root
# metadata.
DEFAULT_ROOT_REQUIRED_LENGTH = 512000 #bytes

# Set a default, but sane, upper bound for the number of bytes required to
# download Snapshot metadata.
DEFAULT_SNAPSHOT_REQUIRED_LENGTH = 2000000 #bytes 

# Set a default, but sane, upper bound for the number of bytes required to
# download Targets metadata.
DEFAULT_TARGETS_REQUIRED_LENGTH = 5000000 #bytes 

# Set a timeout value in seconds (float) for non-blocking socket operations.
SOCKET_TIMEOUT = 2 #seconds

# The maximum chunk of data, in bytes, we would download in every round.
CHUNK_SIZE = 8192 #bytes

# The minimum average download speed (bytes/second) that must be met to
# avoid being considered as a slow retrieval attack.
MIN_AVERAGE_DOWNLOAD_SPEED = 100 #bytes/second

# The time (in seconds) we ignore a server with a slow initial retrieval speed.
SLOW_START_GRACE_PERIOD = 3 #seconds

# The current "good enough" number of PBKDF2 passphrase iterations.
# We recommend that important keys, such as root, be kept offline.
# 'settings.PBKDF2_ITERATIONS' should increase as CPU speeds increase, set here
# at 100,000 iterations by default (in 2013).  The repository maintainer may opt
# to modify the default setting according to their security needs and
# computational restrictions.  A strong user password is still important.
# Modifying the number of iterations will result in a new derived key+PBDKF2
# combination if the key is loaded and re-saved, overriding any previous
# iteration setting used in the old '<keyid>' key file.
# https://en.wikipedia.org/wiki/PBKDF2
PBKDF2_ITERATIONS = 100000

# The client, or the software updater that is integrating TUF, may set the
# specific cryptography library used by The Update Framework updater.  Only a
# subset of the supported crypto libraries are used for general-purpose
# cryptography (PyCrypto and PyCA Cryptography).

# Supported cryptography libraries that can be used to generate and verify RSA
# keys and signatures:  ['pycrypto', 'pyca-cryptography']
RSA_CRYPTO_LIBRARY = 'pyca-cryptography'

# Supported Ed25519 cryptography libraries: ['pynacl', 'ed25519']
ED25519_CRYPTO_LIBRARY = 'pynacl'

# General purpose cryptography. Algorithms and functions that fall under
# general purpose include AES, PBKDF2, cryptographically strong random number
# generators, and cryptographic hash functions.  The majority of the general
# cryptography is needed by the repository and developer tools.
# RSA_CRYPTO_LIBRARY and ED25519_CRYPTO_LIBRARY are needed on the client side
# of the software updater.
# Supported libraries for general-purpose cryptography:  ['pycrypto',
# 'pyca-cryptography']
GENERAL_CRYPTO_LIBRARY = 'pyca-cryptography'

# The Root and Targets roles specify the public keys of either the top-level
# roles (by Root) or roles that they delegate trust (by Targets roles).  By
# default, a single key ID is generated for each public key, with the option of
# supporting multiple hash algorithms via the REPOSITORY_HASH_ALGORITHM
# configuration.  When multiple hash algorithms (and thus multiple key IDs)
# are used, the "keys" field lists one single key ID
# (generated with DEFAULT_HASH_ALGORITHM) for each unique key, and also lists 
# the recognized hash algorithms.  For example:
# {keyid: '1234abc', "keyid_multihash_algorithms": 'sha256', 'sha512', ...}
DEFAULT_HASH_ALGORITHM = 'sha256'

# The algorithm(s) in REPOSITORY_HASH_ALGORITHMS are chosen by the repository
# tool to generate the digests listed in metadata, prepended to the
# filenames of consistent snapshots, or used to generate key IDs.
REPOSITORY_HASH_ALGORITHMS = ['sha256', 'sha512']

# Software updaters that integrate the framework are required to specify
# the URL prefix for the mirrors that clients can contact to download updates.
# The following URI schemes are those that download.py support.  By default,
# the ['http', 'https'] URI schemes are supported, but may be modified by
# integrators to schemes that they wish to support for their integration.
SUPPORTED_URI_SCHEMES = ['http', 'https']

# By default, limit number of delegatees we visit for any target.
MAX_NUMBER_OF_DELEGATIONS = 2**5

# This configuration is for indicating how consistent files should be created.
# There are two options: "copy" and "hard_link".  For "copy", the consistent
# file with be a copy of root.json.  This approach will require the most disk
# space out of the two options.  For "hard_link", the latest root.json will be
# a hard link to 2.root.json (for example).  This approach is more efficient in
# terms of disk space usage.  By default, we use 'copy'.
CONSISTENT_METHOD = 'copy'
