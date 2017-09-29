#!/usr/bin/env python

"""
<Program Name>
  settings.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  January 11, 2017

<Copyright>
  See LICENSE for licensing information.

<Purpose>
 A central location for TUF configuration settings.  Example options include
 setting the destination of temporary files and downloaded content, the maximum
 length of downloaded metadata (unknown file attributes), and download
 behavior.
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

# Set a local directory to store metadata that is requested from mirrors.  This
# directory contains subdirectories for different repositories, where each
# subdirectory contains a different set of metadata.  For example:
# tuf.settings.repositories_directory = /tmp/repositories.  The root file for a
# repository named 'django_repo' can be found at:
# /tmp/repositories/django_repo/metadata/current/root.METADATA_EXTENSION
repositories_directory = None

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

# A setting for the instances where a default hashing algorithm is needed.
# This setting is currently used to calculate the path hash prefixes of hashed
# bin delegations.  The other instances (e.g., digest of files) that require a
# hashing algorithm rely on settings in the securesystemslib external library.
DEFAULT_HASH_ALGORITHM = 'sha256'
