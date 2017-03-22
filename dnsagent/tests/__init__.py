from ipaddress import ip_address, IPv4Address, IPv6Address
import logging
import os
import subprocess
from typing import Tuple, Sequence

import pytest
from twisted.internet import defer
from twisted.internet.protocol import (
    DatagramProtocol, Protocol, connectionDone, ServerFactory, ClientFactory,
)
from twisted.names import dns
from twisted.python.failure import Failure
from twisted.trial import unittest

from dnsagent.app import init_log, enable_log
from dnsagent.resolver.base import BaseResolver
from dnsagent.utils import rrheader_to_ip, get_reactor, to_twisted_addr, wait_for_tcp


logger = logging.getLogger(__name__)


init_log()
enable_log()


NO_INTERNET = os.environ.get('NO_INTERNET')


def require_internet(test_cls_or_func):
    """Skip tests that require internet connection."""
    marker = pytest.mark.skipif(NO_INTERNET, reason='requires internet')
    return marker(test_cls_or_func)


def iplist(*lst):
    return [ip_address(ip) for ip in lst]


# noinspection PyPep8Naming
class FakeResolver(BaseResolver):
    def __init__(self, reactor=None):
        super().__init__()
        self.delay = 0
        self.map = dict()
        self.msg_logs = []
        self.query_logs = []
        self.reactor = get_reactor(reactor)

    def query(self, query, timeout=None, **kwargs):
        params = dict(query=query, timeout=timeout)
        params.update(kwargs)
        self.query_logs.append(params)
        return super().query(query, timeout=timeout, **kwargs)

    def _lookup(self, name, cls, type_, timeout, **kwargs):
        def cleanup():
            delay_d.cancel()

        d = defer.Deferred(lambda ignore: cleanup())
        try:
            result = self.map[name, cls, type_]
        except KeyError:
            err = Failure(dns.DomainError(name))
            delay_d = self.reactor.callLater(self.delay, d.errback, err)
        else:
            delay_d = self.reactor.callLater(self.delay, d.callback, result)
        return d

    def set_answer(self, name: str, address: str, ttl=60):
        rr = make_rrheader(name, address, ttl=ttl)
        self.map[rr.name.name, rr.cls, rr.type] = ([rr], [], [])

    def set_multiple_answer(self, name: str, addr_ttl: Sequence[Tuple[str, int]]):
        for addr, ttl in addr_ttl:
            rr = make_rrheader(name, addr, ttl=ttl)
            key = (rr.name.name, rr.cls, rr.type)
            if key not in self.map:
                self.map[key] = ([], [], [])
            self.map[key][0].append(rr)

    # for twisted.names.client.Resolver
    def connectionMade(self, protocol):
        pass

    def connectionLost(self, reason):
        pass

    def messageReceived(self, msg, protocol, addr=None):
        self.msg_logs.append(msg)

    def __repr__(self):
        return '<Fake {:#x}>'.format(id(self))


def make_rrheader(name: str, address: str, ttl=60):
    ip = ip_address(address)
    if isinstance(ip, IPv4Address):
        type_ = dns.A
        record_type = dns.Record_A
    elif isinstance(ip, IPv6Address):
        type_ = dns.AAAA
        record_type = dns.Record_AAAA
    else:
        assert False

    return dns.RRHeader(
        name=name.encode('utf8'), type=type_, cls=dns.IN, ttl=ttl,
        payload=record_type(address=address, ttl=ttl),
    )


class BaseTestResolver(unittest.TestCase):
    def setUp(self):
        self.deferreds = []
        self.resolver = None

    def tearDown(self):
        return defer.DeferredList(self.deferreds, fireOnOneErrback=True)

    def _check_query(self, query: dns.Query, expect=None, fail=None, query_kwargs=None):
        def check_result(result):
            logger.info('query %r got: %r', query, result)
            if fail:
                self.fail('query failure expected')

            ans, auth, add = result
            assert [rrheader_to_ip(rr) for rr in ans] == expect

        def failed(failure: Failure):
            logger.info('query %r failed: %s', query, failure)
            if not fail:
                self.fail('query failed unexpectly')
            if isinstance(fail, type) and issubclass(fail, Exception):
                assert isinstance(failure.value, fail), 'Failure type mismatch'

        query_kwargs = query_kwargs or dict()
        query_kwargs.setdefault('timeout', (0.5,))

        d = self.resolver.query(query, **query_kwargs)
        if fail is not None or expect is not None:
            d.addCallbacks(check_result, failed)
        # else: manual checking
        self.deferreds.append(d)
        return d

    def check_a(self, name: str, expect=None, fail=None, query_kwargs=None):
        return self._check_query(
            dns.Query(name.encode('utf8'), dns.A, dns.IN),
            expect=expect, fail=fail, query_kwargs=query_kwargs,
        )

    def check_aaaa(self, name: str, expect=None, fail=None, query_kwargs=None):
        return self._check_query(
            dns.Query(name.encode('utf8'), dns.AAAA, dns.IN),
            expect=expect, fail=fail, query_kwargs=query_kwargs,
        )

    def check_all(self, name: str, expect=None, fail=None, query_kwargs=None):
        return self._check_query(
            dns.Query(name.encode('utf8'), dns.ALL_RECORDS, dns.IN),
            expect=expect, fail=fail, query_kwargs=query_kwargs,
        )


# noinspection PyPep8Naming
class FakeTransport:
    def __init__(self, addr=('8.7.6.5', 8765)):
        self.write_logs = []
        self.connected = True
        self.addr = addr

    def write(self, data, addr=None):
        self.write_logs.append((data, addr))

    def loseConnection(self):
        assert self.connected
        self.connected = False

    stopListening = loseConnection

    def getHost(self):
        return to_twisted_addr(*self.addr, type_='TCP')

    def poplogs(self):
        logs = self.write_logs
        self.write_logs = []
        return logs


class FakeDatagramProtocol(DatagramProtocol):
    start_count = 0
    stop_count = 0

    def __init__(self):
        self.data_logs = []

    def datagramReceived(self, datagram: bytes, addr):
        self.data_logs.append((datagram, addr))

    def startProtocol(self):
        self.start_count += 1

    def stopProtocol(self):
        self.stop_count += 1


class FakeProtocol(Protocol):
    lost = False

    def __init__(self):
        self.recv_logs = []

    def dataReceived(self, data):
        self.recv_logs.append(data)

    def connectionLost(self, reason=connectionDone):
        self.lost = True


class Reverser(DatagramProtocol):
    def datagramReceived(self, datagram, addr):
        data = bytes(reversed(datagram))
        self.transport.write(data, addr)


class TCPReverser(Protocol):
    def dataReceived(self, data):
        data = bytes(reversed(data))
        self.transport.write(data)


class Greeter(DatagramProtocol):
    def __init__(self, dest_addr):
        self.dest_addr = dest_addr
        self.d = defer.Deferred()

    def startProtocol(self):
        self.transport.connect(*self.dest_addr)
        self.transport.write(b'hello')

    def datagramReceived(self, datagram, addr):
        self.d.callback(datagram)


class TCPGreeter(Protocol):
    def __init__(self):
        self.d = defer.Deferred()

    def connectionMade(self):
        self.transport.write(b'hello')

    def dataReceived(self, data):
        self.d.callback(data)


class OneshotClientFactory(ClientFactory):
    def __init__(self, protocol: Protocol):
        self.proto = protocol

    def buildProtocol(self, addr):
        self.proto.factory = self
        return self.proto


class OneshotServerFactory(ServerFactory):
    def __init__(self, protocol: Protocol):
        self.proto = protocol

    def buildProtocol(self, addr):
        return self.proto


def clean_treq_connection_pool():
    import treq._utils
    pool = treq._utils.get_global_pool()
    if pool:
        return pool.closeCachedConnections()


class SSRunner:
    ss_server_host = '127.0.0.20'
    ss_server_port = 2222
    ss_client_host = '127.0.0.30'
    ss_client_port = 3333
    ss_passwd = '123'

    ss_server = None
    ss_local = None
    _ss_defer = None

    @classmethod
    def start(cls) -> defer.Deferred:
        if cls._ss_defer is None:
            cls.ss_server = subprocess.Popen([
                'ssserver', '-s', cls.ss_server_host, '-p', str(cls.ss_server_port),
                '-k', cls.ss_passwd, '--forbidden-ip', '',
            ])
            cls.ss_local = subprocess.Popen([
                'sslocal', '-s', cls.ss_server_host, '-p', str(cls.ss_server_port),
                '-b', cls.ss_client_host, '-l', str(cls.ss_client_port), '-k', cls.ss_passwd,
            ])

            cls._ss_defer = wait_for_tcp((cls.ss_client_host, cls.ss_client_port))

        return cls._ss_defer

    @classmethod
    def shutdown(cls):
        if cls._ss_defer is not None:
            cls._ss_defer = None
            for popen in (cls.ss_server, cls.ss_local):
                if popen is not None and popen.returncode is None:
                    kill_proccess(popen)
            cls.ss_server, cls.ss_local = None, None


def kill_proccess(popen: subprocess.Popen):
    try:
        import psutil
    except ImportError:
        popen.terminate()
    else:
        # kill process tree
        # since python is a subprocess of sslocal/ssserver on windows
        pid = popen.pid
        parent = psutil.Process(pid)
        children = parent.children(recursive=True)
        for child in children:
            child.kill()
        psutil.wait_procs(children, timeout=2)

        try:
            parent.kill()
            parent.wait(2)
        except Exception:
            logger.exception('failed to kill process: %d', pid)
