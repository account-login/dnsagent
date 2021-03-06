from ipaddress import IPv4Address, IPv6Address, ip_address
from itertools import chain
import logging
import os
import re
import socket
import sys
from typing import NamedTuple, Tuple, Sequence, Callable

from twisted.internet._sslverify import IOpenSSLTrustRoot, Certificate, platformTrust
from twisted.internet import defer, address as taddress
from twisted.internet.endpoints import (
    connectProtocol, TCP4ClientEndpoint, TCP6ClientEndpoint, HostnameEndpoint,
)
from twisted.internet.protocol import Protocol
from twisted.names import dns
from watchdog.events import FileSystemEventHandler, FileModifiedEvent
from watchdog.observers import Observer
from zope.interface import implementer


logger = logging.getLogger(__name__)


class WatcherHandler(FileSystemEventHandler):
    def __init__(self, filename, callback):
        self.path = os.path.normpath(os.path.realpath(filename))
        self.callback = callback

    def on_modified(self, event: FileModifiedEvent):
        path = os.path.normpath(os.path.realpath(event.src_path))
        if path == self.path:
            self.callback()


def watch_modification(filename, callback):
    observer = Observer()
    dirname = os.path.dirname(os.path.realpath(filename))
    observer.schedule(WatcherHandler(filename, callback), dirname)
    observer.start()
    return observer


class PrefixedLogger:
    def __init__(self, logger, prefix: str):
        self.logger = logger
        self.prefix = prefix

    def debug(self, msg, *args, **kwargs):
        self.logger.debug(self.prefix + msg, *args, **kwargs)

    def info(self, msg, *args, **kwargs):
        self.logger.info(self.prefix + msg, *args, **kwargs)

    def warning(self, msg, *args, **kwargs):
        self.logger.warning(self.prefix + msg, *args, **kwargs)

    def error(self, msg, *args, **kwargs):
        self.logger.error(self.prefix + msg, *args, **kwargs)

    def exception(self, msg, *args, **kwargs):
        self.logger.exception(self.prefix + msg, *args, **kwargs)

    def critical(self, msg, *args, **kwargs):
        self.logger.critical(self.prefix + msg, *args, **kwargs)


def rrheader_to_ip(rr):
    payload = rr.payload
    if isinstance(payload, dns.Record_A):
        return IPv4Address(payload.dottedQuad())
    elif isinstance(payload, dns.Record_AAAA):
        return IPv6Address(socket.inet_ntop(socket.AF_INET6, payload.address))
    else:
        return None


def get_reactor(reactor=None):
    if reactor is None:
        from twisted.internet import reactor
    return reactor


class BadURL(Exception):
    pass


ParsedURL = NamedTuple('ParsedURL', [('scheme', str), ('host', str), ('port', int)])


def parse_url(string: str) -> ParsedURL:
    scheme, host, port = None, None, None

    matched = re.match('^(.+)://(.+)', string)
    if matched:
        scheme, string = matched.group(1), matched.group(2)

    host, string = _parse_host(string, scheme=scheme)

    if string:
        if string[0] != ':':
            raise BadURL(':port expected, got %r' % string)
        string = string[1:]

        try:
            port = int(string)
        except ValueError:
            raise BadURL('bad port number: %s' % string)

    return ParsedURL(scheme, host, port)


def _parse_host(string: str, scheme=None) -> Tuple[str, str]:
    matched = re.match(r'\[(.+)\](.*)', string)
    if matched:
        host, string = matched.group(1), matched.group(2)
        try:
            IPv6Address(host)
        except ValueError:
            raise BadURL('bad host: %s' % host )
        return host, string

    if not scheme:
        try:
            IPv6Address(string)
        except ValueError:
            pass
        else:
            return string, ''

    matched = re.match('([^:]+)(.*)', string)
    if not matched:
        raise BadURL
    return matched.group(1), matched.group(2)


def repr_short(obj):
    try:
        method = obj._repr_short_
    except AttributeError:
        return repr(obj)
    else:
        return method()


@defer.inlineCallbacks
def wait_for_tcp(addr: Tuple[str, int], retries=20, timeout=0.2, logger=None, reactor=None):
    while True:
        reactor = get_reactor(reactor)
        logger = logger or logging.getLogger(__name__)
        plogger = PrefixedLogger(logger, 'wait_for_tcp(%r): ' % (addr,))

        endpoint = get_client_endpoint(reactor, addr, timeout=timeout)
        protocol = Protocol()
        try:
            yield connectProtocol(endpoint, protocol)
        except:
            plogger.debug('server is down. retries left: %d', retries)
            if retries <= 0:
                raise Exception('wait_for_tcp(%r): server not started' % (addr,))
            retries -= 1
            yield async_sleep(timeout, reactor=reactor)
        else:
            plogger.debug('server is up')
            protocol.transport.loseConnection()
            return addr


def get_client_endpoint(reactor, addr: Tuple[str, int], **kwargs):
    host, port = addr
    shost = host
    try:
        shost = ip_address(host)
    except ValueError:
        pass
    if isinstance(shost, IPv4Address):
        return TCP4ClientEndpoint(reactor, host, port, **kwargs)
    elif isinstance(shost, IPv6Address):
        return TCP6ClientEndpoint(reactor, host, port, **kwargs)
    else:
        return HostnameEndpoint(reactor, host.encode(), port, **kwargs)


def to_twisted_addr(host: str, port: int, type_='TCP'):
    try:
        host = ip_address(host)
    except ValueError:
        pass
    if isinstance(host, IPv4Address):
        return taddress.IPv4Address(type_, str(host), port)
    elif isinstance(host, IPv6Address):
        return taddress.IPv6Address(type_, str(host), port)
    else:
        assert isinstance(host, str)
        return taddress.HostnameAddress(host.encode(), port)


@implementer(IOpenSSLTrustRoot)
class OpenSSLWindowsCertificateAuthorities:
    """
    Use wincertstore package to interface with the Windows CA certificates.
    """

    def _addCACertsToContext(self, context):
        from wincertstore import CertSystemStore
        from OpenSSL.crypto import Error as OpenSSLError

        store = context.get_cert_store()
        certificates = chain.from_iterable(
            CertSystemStore(name).itercerts()
            for name in ('ROOT', 'CA', 'MY')
        )
        # use set to remove duplicates
        encoded_certs = set(cert.get_encoded() for cert in certificates)
        for encoded in encoded_certs:
            try:
                store.add_cert(Certificate.load(encoded).original)
            except OpenSSLError:
                logger.exception('error in adding certificate to store')


def patched_platform_trust():
    """
    Attempt to discover a set of trusted certificate authority certificates

    @raise NotImplementedError: if this platform is not yet supported by Twisted. 
        At present, only OpenSSL and native Windows trusted CA database is supported.
    """
    if sys.platform.lower().startswith('win'):
        return OpenSSLWindowsCertificateAuthorities()
    else:
        return platformTrust()


def patch_twisted_ssl_root_bug():
    """
    Add native Windows trusted CA database support for SSL certificate validation
    
    from: https://twistedmatrix.com/trac/ticket/6371
    """
    import twisted.internet._sslverify as mod
    mod.platformTrust = patched_platform_trust


class HTTPConnectionPoolBugFixMixin:
    def _removeConnection(self, key, connection):
        """
        Remove a connection from the cache and disconnect it.
        """
        # avoid calling loseConnection() when connection is disconnected already.
        if connection.state != 'CONNECTION_LOST':
            connection.transport.loseConnection()
        self._connections[key].remove(connection)
        del self._timeouts[connection]


def patch_twisted_http_connection_pool_bug():
    from twisted.web.client import HTTPConnectionPool
    HTTPConnectionPool._removeConnection = HTTPConnectionPoolBugFixMixin._removeConnection


def get_treq():
    """
    treq should be lazy imported since importing treq will install reactor.
    twisted.web.client.HTTPConnectionPool is patched here too.
    """
    patch_twisted_http_connection_pool_bug()
    import treq
    return treq


# This is an unique object used to distinguish between None and unused argument
_NONE = object()


@defer.inlineCallbacks
def sequence_deferred_call(funcs: Sequence[Callable], result=_NONE):
    for func in funcs:
        if result is _NONE:
            yield defer.maybeDeferred(func)
        else:
            result = yield defer.maybeDeferred(func, result)

    if result is _NONE:
        return
    else:
        return result


def async_sleep(seconds: float, reactor=None):
    reactor = get_reactor(reactor)
    d = defer.Deferred()
    reactor.callLater(seconds, d.callback, seconds)
    return d
