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


def wait_for_tcp(addr: Tuple[str, int], retries=20, timeout=0.2, d=None, logger=None):
    def connected(result):
        plogger.debug('server is up')
        protocol.transport.loseConnection()
        d.callback(addr)
        return result

    def failed(ignore):
        plogger.debug('server is down. retries left: %d', retries - 1)
        reactor.callLater(
            timeout, wait_for_tcp,
            addr=addr, retries=(retries - 1), timeout=timeout, d=d, logger=logger,
        )

    reactor = get_reactor()
    d = d or defer.Deferred()
    logger = logger or logging.getLogger(__name__)
    plogger = PrefixedLogger(logger, 'wait_for_tcp(%r): ' % (addr,))

    if retries <= 0:
        d.errback(Exception('wait_for_tcp(%r): server not started' % (addr,)))
    else:
        protocol = Protocol()
        connect_d = connectProtocol(
            get_client_endpoint(
                reactor, addr, timeout=timeout),
            protocol,
        )
        connect_d.addCallbacks(connected, failed)

    return d


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


def patch_twisted_bugs():
    """
    Add native Windows trusted CA database support for SSL certificate validation
    
    from: https://twistedmatrix.com/trac/ticket/6371
    """
    import twisted.internet._sslverify as mod
    mod.platformTrust = patched_platform_trust


# This is an unique object used to distinguish between None and unused argument
_NONE = object()


def chain_deferred_call(
        funcs: Sequence[Callable], final_d: defer.Deferred = None, result=_NONE
):
    final_d = final_d or defer.Deferred()

    if len(funcs) == 0:
        if result is _NONE:
            final_d.callback(None)
        else:
            final_d.callback(result)
    else:
        first, *remainds = funcs
        if result is _NONE:
            d = defer.maybeDeferred(first)
            d.addCallback(lambda ignore: chain_deferred_call(remainds, final_d))
        else:
            d = defer.maybeDeferred(first, result)
            d.addCallback(lambda result: chain_deferred_call(remainds, final_d, result))
        d.addErrback(final_d.errback)

    return final_d
