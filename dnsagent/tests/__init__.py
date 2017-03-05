from ipaddress import ip_address, IPv4Address, IPv6Address
from typing import Tuple, Sequence
import logging

from twisted.internet import defer
from twisted.names import dns
from twisted.python.failure import Failure
from twisted.trial import unittest

from dnsagent.app import init_log, enable_log
from dnsagent.utils import rrheader_to_ip, get_reactor
from dnsagent.resolver.base import MyResolverBase


logger = logging.getLogger(__name__)


init_log()
enable_log()


def iplist(*lst):
    return [ip_address(ip) for ip in lst]


class FakeResolver(MyResolverBase):
    def __init__(self, reactor=None):
        super().__init__()
        self.delay = 0
        self.map = dict()
        self.reactor = get_reactor(reactor)

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


class TestResolverBase(unittest.TestCase):
    def setUp(self):
        self.defereds = []
        self.resolver = None

    def tearDown(self):
        return defer.DeferredList(self.defereds, fireOnOneErrback=True)

    def _check_query(self, query: dns.Query, expect=None, fail=None):
        if fail:
            assert expect is None

        def check_result(result):
            logger.info('query %r got: %r', query, result)
            if fail:
                self.fail('query failure expected')

            ans, auth, add = result
            assert [rrheader_to_ip(rr) for rr in ans] == expect

        def failed(failure: Failure):
            logger.info('query %r failed: %r', query, failure)
            if not fail:
                self.fail('query failed unexpectly')
            if isinstance(fail, type) and issubclass(fail, Exception):
                assert isinstance(failure.value, fail), 'Failure type mismatch'

        d = self.resolver.query(query, timeout=[0.5])
        d.addCallbacks(check_result, failed)
        self.defereds.append(d)
        return d

    def check_a(self, name: str, expect=None, fail=None):
        return self._check_query(
            dns.Query(name.encode('utf8'), dns.A, dns.IN),
            expect=expect, fail=fail,
        )

    def check_aaaa(self, name: str, expect=None, fail=None):
        return self._check_query(
            dns.Query(name.encode('utf8'), dns.AAAA, dns.IN),
            expect=expect, fail=fail,
        )

    def check_all(self, name: str, expect=None, fail=None):
        return self._check_query(
            dns.Query(name.encode('utf8'), dns.ALL_RECORDS, dns.IN),
            expect=expect, fail=fail,
        )
