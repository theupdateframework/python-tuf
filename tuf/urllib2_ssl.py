# Thanks to https://gist.github.com/zed/1347055

"""SSL client/server certificates verification for `urllib2`.

It works on Python 2.6, 2.7, 3.1, 3.2
It also works on Python 2.4, 2.5 if `ssl` is installed (``pip install ssl``)

Example::

   >>> import urllib2, urllib2_ssl
   >>> opener = urllib2.build_opener(urllib2_ssl.HTTPSHandler(
   ...     key_file='clientkey.pem',
   ...     cert_file='clientcert.pem',
   ...     ca_certs='cacrt.pem'))
   >>> opener.open('https://example.com/').read()
"""
__all__ = ['match_hostname', 'CertificateError']


import sys
import socket

if not hasattr(socket, 'create_connection'): # for Python 2.4
    _GLOBAL_DEFAULT_TIMEOUT = getattr(socket, '_GLOBAL_DEFAULT_TIMEOUT', object())
    # copy-paste from stdlib's socket.py (py2.6)
    def create_connection(address, timeout=_GLOBAL_DEFAULT_TIMEOUT,
                          source_address=None):
        """Connect to *address* and return the socket object.

        Convenience function.  Connect to *address* (a 2-tuple ``(host,
        port)``) and return the socket object.  Passing the optional
        *timeout* parameter will set the timeout on the socket instance
        before attempting to connect.  If no *timeout* is supplied, the
        global default timeout setting returned by :func:`getdefaulttimeout`
        is used.
        """

        host, port = address
        err = None
        for res in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
            af, socktype, proto, canonname, sa = res
            sock = None
            try:
                sock = socket.socket(af, socktype, proto)
                if timeout is not _GLOBAL_DEFAULT_TIMEOUT:
                    sock.settimeout(timeout)
                if source_address:
                    sock.bind(source_address)
                sock.connect(sa)
                return sock

            except socket.error:
                err = sys.exc_info()[1]
                if sock is not None:
                    sock.close()

        if err is not None:
            raise err
        else:
            raise socket.error("getaddrinfo returns an empty list")

    # monkey-patch socket module
    socket.create_connection = create_connection


# copy-paste from stdlib's ssl.py (py3.2)
class CertificateError(ValueError):
    pass


def match_hostname(cert, hostname):
    """Verify that *cert* (in decoded format as returned by
    SSLSocket.getpeercert()) matches the *hostname*.  RFC 2818 rules
    are mostly followed, but IP addresses are not accepted for *hostname*.

    CertificateError is raised on failure. On success, the function
    returns nothing.

    XXX this version differ from ssl.match_hostname in python 3.2
    it checks subject even if subjectAltName is not empty
    """
    if not cert:
        raise ValueError("empty or no certificate")
    dnsnames = []
    san = cert.get('subjectAltName', ())
    for key, value in san:
        if key == 'DNS':
            if _dnsname_to_pat(value).match(hostname):
                return
            dnsnames.append(value)
    if not dnsnames:
        #XXX check subject even if subjectAltName is not empty
        for sub in cert.get('subject', ()):
            for key, value in sub:
                # XXX according to RFC 2818, the most specific Common Name
                # must be used.
                if key == 'commonName':
                    if _dnsname_to_pat(value).match(hostname):
                        return
                    dnsnames.append(value)
    if len(dnsnames) > 1:
        raise CertificateError("hostname %r "
            "doesn't match either of %s"
            % (hostname, ', '.join(map(repr, dnsnames))))
    elif len(dnsnames) == 1:
        raise CertificateError("hostname %r "
            "doesn't match %r"
            % (hostname, dnsnames[0]))
    else:
        raise CertificateError("no appropriate commonName or "
            "subjectAltName fields were found")

def _dnsname_to_pat(dn):
    pats = []
    for frag in dn.split(r'.'):
        if frag == '*':
            # When '*' is a fragment by itself, it matches a non-empty dotless
            # fragment.
            pats.append('[^.]+')
        else:
            # Otherwise, '*' matches any dotless fragment.
            frag = re.escape(frag)
            pats.append(frag.replace(r'\*', '[^.]*'))
    return re.compile(r'\A' + r'\.'.join(pats) + r'\Z', re.IGNORECASE)


try: import ssl
except ImportError:
    ssl = None
    import warnings
    msg = ("Can't import ssl. HTTPS won't work."
           "Run `pip install ssl` if Python < 2.6")
    # use python -Wd to see this warning (it is ignored by default)
    try:
        ImportWarning
    except NameError:
        warnings.warn(msg) # Python < 2.5
    else:
        warnings.warn(msg, ImportWarning)
else: # ssl is available
    # see http://www.muchtooscrawled.com/2010/03/https-certificate-verification-in-python-with-urllib2/

    try: from http import client # py3k
    except ImportError:
        import httplib as client # py < 3.x

    import re

    try: import urllib2 as request # py < 3.x
    except ImportError:
        from urllib import request # py3k


    class HTTPSConnection(client.HTTPSConnection):
        def __init__(self, host, **kwargs):         
            self.ca_certs = kwargs.pop('ca_certs', None)
            self.checker = kwargs.pop('checker', match_hostname)

            # for python < 2.6
            self.timeout = kwargs.get('timeout', socket.getdefaulttimeout())

            client.HTTPSConnection.__init__(self, host, **kwargs)


        def connect(self):
            # overrides the version in httplib so that we do
            #    certificate verification
            args = [(self.host, self.port), self.timeout,]
            if hasattr(self, 'source_address'):
                args.append(self.source_address)
            sock = socket.create_connection(*args)

            if getattr(self, '_tunnel_host', None):
                self.sock = sock
                self._tunnel()
            # wrap the socket using verification with the root
            #    certs in self.ca_certs
            kwargs = {}
            if self.ca_certs is not None:
                kwargs.update(
                    cert_reqs=ssl.CERT_REQUIRED,
                    ca_certs=self.ca_certs)
            self.sock = ssl.wrap_socket(sock,
                                        keyfile=self.key_file,
                                        certfile=self.cert_file,
                                        **kwargs)
            if self.checker is not None:
                try:
                    self.checker(self.sock.getpeercert(), self.host)
                except CertificateError:
                    self.sock.shutdown(socket.SHUT_RDWR)
                    self.sock.close()
                    raise

    # wraps https connections with ssl certificate verification
    class HTTPSHandler(request.HTTPSHandler):
        # see http://www.threepillarglobal.com/soap_client_auth
        # HTTPS Client Auth solution for urllib2, inspired by
        #   http://bugs.python.org/issue3466 and improved by David
        #   Norton of Three Pillar Software. In this implementation,
        #   we use properties passed in rather than static module
        #   fields.
        def __init__(self, key_file=None, cert_file=None, ca_certs=None,
                     checker=match_hostname):
            request.HTTPSHandler.__init__(self)
            # see http://docs.python.org/library/ssl.html#certificates
            self.key_file = key_file
            self.cert_file = cert_file
            self.ca_certs = ca_certs
            self.checker = checker

        def https_open(self, req):
            # Rather than pass in a reference to a connection class, we pass in
            #   a reference to a function which, for all intents and purposes,
            #   will behave as a constructor
            return self.do_open(self.getConnection, req)

        def getConnection(self, host, **kwargs):
            d = dict(cert_file=self.cert_file,
                     key_file=self.key_file,
                     ca_certs=self.ca_certs,
                     checker=self.checker)
            d.update(kwargs)
            return HTTPSConnection(host, **d)
    __all__.append('HTTPSHandler')
