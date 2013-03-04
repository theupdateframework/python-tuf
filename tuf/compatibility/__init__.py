"""
We copy some backwards compatibility from pip.

https://github.com/pypa/pip/tree/d0fa66ecc03ab20b7411b35f7c7b423f31f77761/pip/backwardcompat
"""


import sys


if sys.version_info >= (3,):
    import http.client as httplib
    import urllib.parse as urlparse
    import urllib.request as urllib2
else:
    import httplib
    import urllib2
    import urlparse


## py25 has no builtin ssl module
## only >=py32 has ssl.match_hostname and ssl.CertificateError
try:
    import ssl
    try:
        from ssl import match_hostname, CertificateError
    except ImportError:
        from tuf.compatibility.ssl_match_hostname import match_hostname, CertificateError
except ImportError:
    ssl = None


# patch for py25 socket to work with http://pypi.python.org/pypi/ssl/
import socket
if not hasattr(socket, 'create_connection'): # for Python 2.5
    # monkey-patch socket module
    from tuf.compatibility.socket_create_connection import create_connection
    socket.create_connection = create_connection

