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
  A central location for TUF configuration settings.

"""


# Set a directory that should be used for all temporary files. If this
# is None, then the system default will be used. The system default
# will also be used if a directory path set here is invalid or
# unusable.
temporary_directory = None

# The directory under which metadata for all repositories will be
# stored. This is not a simple cache because each repository's root of
# trust (root.txt) will need to already be stored below here and should
# not be deleted. At a minimum, each key in the mirrors dictionary
# below should have a directory under 'repository_directory'
# which already exists and within that directory should have the file
# 'metadata/current/root.txt'.  This must be set!
repository_directory = None

# A PEM (RFC 1422) file where you may find SSL certificate authorities
# https://en.wikipedia.org/wiki/Certificate_authority
# http://docs.python.org/2/library/ssl.html#certificates
ssl_certificates = None

# Since the timestamp role does not have signed metadata about itself, we set a
# default but sane upper bound for the number of bytes required to download it.
DEFAULT_TIMESTAMP_REQUIRED_LENGTH = 2048

# set the maximum waiting time for the socket.recv() before receives anything.
recv_timeout = 2

# the maximum tolorated number of times that receive data with shorter length than required
# when download a file. 
maximum_abnormal_length_count = 5