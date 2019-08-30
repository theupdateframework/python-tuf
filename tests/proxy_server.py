#!/usr/bin/env python

# This code is taken from: github.com/inaz2/proxy2
# Credit goes to the author. It has been very slightly modified here to use
# IPv4 instead of IPv6, and to only attempt interception of HTTPS traffic
# (instead of relaying via HTTP CONNECT) if new global variable INTERCEPT is
# set to True. (Modified sections are marked '# MODIFIED'.)
#
# Because this is a helper module for a test, the style is less important, and
# so to minimize changes from the source, it has NOT been changed to match the
# TUF project's code style outside of rewritten sections.

"""
<Program>
  proxy_server.py

<Copyright>
  Taken from a repository set to BSD 3-Clause "New" or "Revised" License. See:
  https://github.com/inaz2/proxy2/blob/b2bab648173ac69f0a10421750125517accdfe26/LICENSE

<Purpose>
  Serves as an HTTP, HTTP CONNECT (TCP), and HTTPS proxy, for testing purposes.
  This is used by test_proxy_use.py.

  In Python versions < 2.7.9, this proxy does not perform certificate
  validation of the target server. As that is not part of what the current
  tests using this script require, that is currently OK. In Python
  versions > 2.7.9 (SSLContext was added in 2.7.9), the same code actually does
  check the certificate, using the system's trusted CAs. As a result, since we
  are using custom certificates, we need to either disable certificate
  checking in 2.7.9 or load the specific CA for target test server, using the
  SSLContext and create_default_context functionality also added in 2.7.9. It
  is easier to do the latter, so the behavior in 2.7.9+ is to check the cert
  and below 2.7.9 is not to. Note that we do not support Python < 2.7.
  SSLContext is also available in all Python3 versions that we support.

  This module requires Python2.7 and does not support Python3.

  Note that this is not thread-safe, in part due to its use of globals.
"""

import sys
import os
import socket
import ssl
import select
import httplib
import urlparse
import threading
import gzip
import zlib
import time
import json
import re
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
from cStringIO import StringIO
from subprocess import Popen, PIPE
from HTMLParser import HTMLParser

# MODIFIED: (added) three globals
# INTERCEPT: A boolean:
#  False: normal HTTP proxy. Support HTTP & HTTPS connections to target server
#  True:  intercepting MITM transparent HTTPS proxy. Makes own TLS connections
#         and has its own cert; must be trusted by the client and is able to
#         modify requests.
# TARGET_SERVER_CA_FILEPATH: location of certificate to use as CA for
#   connections to target servers (to constrain certs to trust from target
#   servers).
# The remaining globals define the certs and keys to be used in communications
# with the client, with the proxy's CA signing new certs for individual hosts
# the client wishes to connect to, and placing them in dir PROXY_CERTS_DIR.
INTERCEPT = False
CERTS_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'ssl_certs')
TARGET_SERVER_CA_FILEPATH = os.path.join(CERTS_DIR, 'ssl_cert.crt')
PROXY_CA_KEY = os.path.join(CERTS_DIR, 'proxy_ca.key') # was cakey
PROXY_CA_CERT = os.path.join(CERTS_DIR, 'proxy_ca.crt') # was cacert
PROXY_CERTS_KEY = os.path.join(CERTS_DIR, 'proxy_cert.key') # was certkey
PROXY_CERTS_DIR = os.path.join(CERTS_DIR, 'proxy_certs') # was certdir


def with_color(c, s):
    return "\x1b[%dm%s\x1b[0m" % (c, s)

# MODIFIED: removed join_with_script_dir
# def get_cert_filepath(path):
#   return os.path.join(CERTS_DIR, path)


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    address_family = socket.AF_INET # MODIFIED to use IPv4 instead of IPv6
    daemon_threads = True

    def handle_error(self, request, client_address):
        # suppress socket/ssl related errors
        cls, e = sys.exc_info()[:2]
        if cls is socket.error or cls is ssl.SSLError:
            pass
        else:
            return HTTPServer.handle_error(self, request, client_address)


class ProxyRequestHandler(BaseHTTPRequestHandler):
    # MODIFIED: Variables here made into globals.
    #Calls below modified: filenames changed, function changed to
    # include ssl_certs directory.
    timeout = 5
    lock = threading.Lock()

    def __init__(self, *args, **kwargs):
        self.tls = threading.local()
        self.tls.conns = {}

        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

    def log_error(self, format, *args):
        # suppress "Request timed out: timeout('timed out',)"
        if isinstance(args[0], socket.timeout):
            return

        self.log_message(format, *args)

    def do_CONNECT(self):
      # MODIFIED: This function has been modified to use new global INTERCEPT
      # and to issue an error if the necessary certificate/key files are
      # missing for interception attempts.
      if not INTERCEPT:
        print('\n\nRELAYING\n\n')
        self.connect_relay()

      else:
        assert os.path.isfile(PROXY_CA_KEY) \
            and os.path.isfile(PROXY_CA_CERT) \
            and os.path.isfile(PROXY_CERTS_KEY) \
            and os.path.isdir(PROXY_CERTS_DIR), \
            '\nMissing key or certificate files; unable to perform TLS ' \
            'handshake with client to intercept traffic.\n'
        print('\n\nINTERCEPTING\n\n')
        self.connect_intercept()

    def connect_intercept(self):
        hostname = self.path.split(':')[0]
        certpath = os.path.join(PROXY_CERTS_DIR, hostname + '.crt') # MODIFIED for Windows compatibility and to use new globals

        with self.lock:
            if not os.path.isfile(certpath):
                epoch = "%d" % (time.time() * 1000)
                p1 = Popen(["openssl", "req", "-new", "-key", PROXY_CERTS_KEY, "-subj", "/CN=%s" % hostname], stdout=PIPE)
                p2 = Popen(["openssl", "x509", "-req", "-days", "3650", "-CA", PROXY_CA_CERT, "-CAkey", PROXY_CA_KEY, "-set_serial", epoch, "-out", certpath], stdin=p1.stdout, stderr=PIPE) # MODIFIED to use the new globals
                p2.communicate()

        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, 200, 'Connection Established'))
        self.end_headers()

        self.connection = ssl.wrap_socket(self.connection, keyfile=PROXY_CERTS_KEY, certfile=certpath, server_side=True) # MODIFIED: Updated to use new globals
        self.rfile = self.connection.makefile("rb", self.rbufsize)
        self.wfile = self.connection.makefile("wb", self.wbufsize)

        conntype = self.headers.get('Proxy-Connection', '')
        if self.protocol_version == "HTTP/1.1" and conntype.lower() != 'close':
            self.close_connection = 0
        else:
            self.close_connection = 1

    def connect_relay(self):
        address = self.path.split(':', 1)
        address[1] = int(address[1]) or 443
        try:
            s = socket.create_connection(address, timeout=self.timeout)
        except Exception as e:
            self.send_error(502)
            return
        self.send_response(200, 'Connection Established')
        self.end_headers()

        conns = [self.connection, s]
        self.close_connection = 0
        while not self.close_connection:
            rlist, wlist, xlist = select.select(conns, [], conns, self.timeout)
            if xlist or not rlist:
                break
            for r in rlist:
                other = conns[1] if r is conns[0] else conns[0]
                data = r.recv(8192)
                if not data:
                    self.close_connection = 1
                    break
                other.sendall(data)

    def do_GET(self):
        if self.path == 'http://proxy2.test/':
            self.send_cacert()
            return

        req = self
        content_length = int(req.headers.get('Content-Length', 0))
        req_body = self.rfile.read(content_length) if content_length else None

        if req.path[0] == '/':
            if isinstance(self.connection, ssl.SSLSocket):
                req.path = "https://%s%s" % (req.headers['Host'], req.path)
            else:
                req.path = "http://%s%s" % (req.headers['Host'], req.path)

        req_body_modified = self.request_handler(req, req_body)
        if req_body_modified is False:
            self.send_error(403)
            return
        elif req_body_modified is not None:
            req_body = req_body_modified
            req.headers['Content-length'] = str(len(req_body))

        u = urlparse.urlsplit(req.path)
        scheme, netloc, path = u.scheme, u.netloc, (u.path + '?' + u.query if u.query else u.path)
        assert scheme in ('http', 'https')
        if netloc:
            req.headers['Host'] = netloc
        setattr(req, 'headers', self.filter_headers(req.headers))

        try:
            origin = (scheme, netloc)
            if not origin in self.tls.conns:
                if scheme == 'https':
                  # MODIFIED: Added Python version checking and changed behavior
                  # in Python2.7.9+ to use custom certificate for target server
                  # inherited from command line argument.
                  # In Python versions < 2.7.9, there is no certificate
                  # validation through this method of the target server.
                  # In supported Python versions > 2.7.9, we check the target
                  # server's certificate against our expected custom cert.
                  # See this script's docstring.
                  if sys.version_info.major == 2 \
                      and sys.version_info.minor == 7 \
                      and sys.version_info.micro < 9:
                    self.tls.conns[origin] = httplib.HTTPSConnection(
                        netloc, timeout=self.timeout)
                  else:
                    self.tls.conns[origin] = httplib.HTTPSConnection(
                        netloc, timeout=self.timeout,
                        context=ssl.create_default_context( # reqs Python2.7.9+
                        cafile=TARGET_SERVER_CA_FILEPATH))
                else:
                    self.tls.conns[origin] = httplib.HTTPConnection(netloc, timeout=self.timeout)
            conn = self.tls.conns[origin]
            conn.request(self.command, path, req_body, dict(req.headers))
            res = conn.getresponse()

            version_table = {10: 'HTTP/1.0', 11: 'HTTP/1.1'}
            setattr(res, 'headers', res.msg)
            setattr(res, 'response_version', version_table[res.version])

            # support streaming
            if not 'Content-Length' in res.headers and 'no-store' in res.headers.get('Cache-Control', ''):
                self.response_handler(req, req_body, res, '')
                setattr(res, 'headers', self.filter_headers(res.headers))
                self.relay_streaming(res)
                with self.lock:
                    self.save_handler(req, req_body, res, '')
                return

            res_body = res.read()
        except Exception as e:
            if origin in self.tls.conns:
                del self.tls.conns[origin]
            self.send_error(502)
            return

        content_encoding = res.headers.get('Content-Encoding', 'identity')
        res_body_plain = self.decode_content_body(res_body, content_encoding)

        res_body_modified = self.response_handler(req, req_body, res, res_body_plain)
        if res_body_modified is False:
            self.send_error(403)
            return
        elif res_body_modified is not None:
            res_body_plain = res_body_modified
            res_body = self.encode_content_body(res_body_plain, content_encoding)
            res.headers['Content-Length'] = str(len(res_body))

        setattr(res, 'headers', self.filter_headers(res.headers))

        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, res.status, res.reason))
        for line in res.headers.headers:
            self.wfile.write(line)
        self.end_headers()
        self.wfile.write(res_body)
        self.wfile.flush()

        with self.lock:
            self.save_handler(req, req_body, res, res_body_plain)

    def relay_streaming(self, res):
        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, res.status, res.reason))
        for line in res.headers.headers:
            self.wfile.write(line)
        self.end_headers()
        try:
            while True:
                chunk = res.read(8192)
                if not chunk:
                    break
                self.wfile.write(chunk)
            self.wfile.flush()
        except socket.error:
            # connection closed by client
            pass

    do_HEAD = do_GET
    do_POST = do_GET
    do_PUT = do_GET
    do_DELETE = do_GET
    do_OPTIONS = do_GET

    def filter_headers(self, headers):
        # http://tools.ietf.org/html/rfc2616#section-13.5.1
        hop_by_hop = ('connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade')
        for k in hop_by_hop:
            del headers[k]

        # accept only supported encodings
        if 'Accept-Encoding' in headers:
            ae = headers['Accept-Encoding']
            filtered_encodings = [x for x in re.split(r',\s*', ae) if x in ('identity', 'gzip', 'x-gzip', 'deflate')]
            headers['Accept-Encoding'] = ', '.join(filtered_encodings)

        return headers

    def encode_content_body(self, text, encoding):
        if encoding == 'identity':
            data = text
        elif encoding in ('gzip', 'x-gzip'):
            io = StringIO()
            with gzip.GzipFile(fileobj=io, mode='wb') as f:
                f.write(text)
            data = io.getvalue()
        elif encoding == 'deflate':
            data = zlib.compress(text)
        else:
            raise Exception("Unknown Content-Encoding: %s" % encoding)
        return data

    def decode_content_body(self, data, encoding):
        if encoding == 'identity':
            text = data
        elif encoding in ('gzip', 'x-gzip'):
            io = StringIO(data)
            with gzip.GzipFile(fileobj=io) as f:
                text = f.read()
        elif encoding == 'deflate':
            try:
                text = zlib.decompress(data)
            except zlib.error:
                text = zlib.decompress(data, -zlib.MAX_WBITS)
        else:
            raise Exception("Unknown Content-Encoding: %s" % encoding)
        return text

    def send_cacert(self):
        with open(PROXY_CA_CERT, 'rb') as f: # MODIFIED to use new globals
            data = f.read()

        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, 200, 'OK'))
        self.send_header('Content-Type', 'application/x-x509-ca-cert')
        self.send_header('Content-Length', len(data))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(data)

    def print_info(self, req, req_body, res, res_body):
        def parse_qsl(s):
            return '\n'.join("%-20s %s" % (k, v) for k, v in urlparse.parse_qsl(s, keep_blank_values=True))

        req_header_text = "%s %s %s\n%s" % (req.command, req.path, req.request_version, req.headers)
        res_header_text = "%s %d %s\n%s" % (res.response_version, res.status, res.reason, res.headers)

        print with_color(33, req_header_text)

        u = urlparse.urlsplit(req.path)
        if u.query:
            query_text = parse_qsl(u.query)
            print with_color(32, "==== QUERY PARAMETERS ====\n%s\n" % query_text)

        cookie = req.headers.get('Cookie', '')
        if cookie:
            cookie = parse_qsl(re.sub(r';\s*', '&', cookie))
            print with_color(32, "==== COOKIE ====\n%s\n" % cookie)

        auth = req.headers.get('Authorization', '')
        if auth.lower().startswith('basic'):
            token = auth.split()[1].decode('base64')
            print with_color(31, "==== BASIC AUTH ====\n%s\n" % token)

        if req_body is not None:
            req_body_text = None
            content_type = req.headers.get('Content-Type', '')

            if content_type.startswith('application/x-www-form-urlencoded'):
                req_body_text = parse_qsl(req_body)
            elif content_type.startswith('application/json'):
                try:
                    json_obj = json.loads(req_body)
                    json_str = json.dumps(json_obj, indent=2)
                    if json_str.count('\n') < 50:
                        req_body_text = json_str
                    else:
                        lines = json_str.splitlines()
                        req_body_text = "%s\n(%d lines)" % ('\n'.join(lines[:50]), len(lines))
                except ValueError:
                    req_body_text = req_body
            elif len(req_body) < 1024:
                req_body_text = req_body

            if req_body_text:
                print with_color(32, "==== REQUEST BODY ====\n%s\n" % req_body_text)

        print with_color(36, res_header_text)

        cookies = res.headers.getheaders('Set-Cookie')
        if cookies:
            cookies = '\n'.join(cookies)
            print with_color(31, "==== SET-COOKIE ====\n%s\n" % cookies)

        if res_body is not None:
            res_body_text = None
            content_type = res.headers.get('Content-Type', '')

            if content_type.startswith('application/json'):
                try:
                    json_obj = json.loads(res_body)
                    json_str = json.dumps(json_obj, indent=2)
                    if json_str.count('\n') < 50:
                        res_body_text = json_str
                    else:
                        lines = json_str.splitlines()
                        res_body_text = "%s\n(%d lines)" % ('\n'.join(lines[:50]), len(lines))
                except ValueError:
                    res_body_text = res_body
            elif content_type.startswith('text/html'):
                m = re.search(r'<title[^>]*>\s*([^<]+?)\s*</title>', res_body, re.I)
                if m:
                    h = HTMLParser()
                    print with_color(32, "==== HTML TITLE ====\n%s\n" % h.unescape(m.group(1).decode('utf-8')))
            elif content_type.startswith('text/') and len(res_body) < 1024:
                res_body_text = res_body

            if res_body_text:
                print with_color(32, "==== RESPONSE BODY ====\n%s\n" % res_body_text)

    def request_handler(self, req, req_body):
        pass

    def response_handler(self, req, req_body, res, res_body):
        pass

    def save_handler(self, req, req_body, res, res_body):
        self.print_info(req, req_body, res, res_body)


def test(HandlerClass=ProxyRequestHandler, ServerClass=ThreadingHTTPServer, protocol="HTTP/1.1"):
    # MODIFIED: Added these globals.
    global INTERCEPT
    global TARGET_SERVER_CA_FILEPATH

    if sys.argv[1:]:
        port = int(sys.argv[1])
    else:
        port = 8080
    server_address = ('127.0.0.1', port) # MODIFIED: changed from '::1'

    # MODIFIED: Argument added, conditional below added to control INTERCEPT
    # setting.
    if len(sys.argv) > 2:
      if sys.argv[2].lower() == 'intercept':
        INTERCEPT = True

    # MODIFIED: Argument added to control certificate(s) the proxy expects of
    # the target server(s), and added default value.
    if len(sys.argv) > 3:
      if os.path.exists(sys.argv[3]):
        TARGET_SERVER_CA_FILEPATH = sys.argv[3]
      else:
        raise Exception('Target server cert file not found: ' + sys.argv[3])

    # MODIFIED: Create the target-host-specific proxy certificates directory if
    # it doesn't already exist.
    if not os.path.exists(PROXY_CERTS_DIR):
      os.mkdir(PROXY_CERTS_DIR)


    HandlerClass.protocol_version = protocol
    httpd = ServerClass(server_address, HandlerClass)

    sa = httpd.socket.getsockname()
    print "Serving HTTP Proxy on", sa[0], "port", sa[1], "..."
    httpd.serve_forever()


if __name__ == '__main__':
    test()
