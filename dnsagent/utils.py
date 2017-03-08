from ipaddress import IPv4Address, IPv6Address, ip_address
import logging
import os
import re
import socket
from typing import NamedTuple, Tuple

from twisted.internet import defer
from twisted.internet.endpoints import connectProtocol, TCP4ClientEndpoint, TCP6ClientEndpoint, \
    HostnameEndpoint
from twisted.internet.protocol import Protocol
from twisted.names import dns
from watchdog.events import FileSystemEventHandler, FileModifiedEvent
from watchdog.observers import Observer


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
        return obj._repr_short_()
    except AttributeError:
        return repr(obj)


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
