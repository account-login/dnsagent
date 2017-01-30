import os
import tempfile
from ipaddress import ip_address, IPv4Address, IPv6Address
from twisted.internet import defer, task
from twisted.names import dns
from twisted.names.common import ResolverBase
from twisted.python.failure import Failure
from twisted.trial import unittest
import pytest

from dnsagent.config import (
    parse_dns_server_string, DnsServerInfo, InvalidDnsServerString,
)
from dnsagent.resolver import (
    parse_hosts_file, rrheader_to_ip,
    HostsResolver, CachingResolver,
)


from dnsagent.__main__ import enable_log
enable_log()


def iplist(*lst):
    return [ip_address(ip) for ip in lst]


class FakeResolver(ResolverBase):
    def __init__(self, map=None):
        super().__init__()
        self.map = map or dict()

    def _lookup(self, name, cls, type_, timeout):
        try:
            return defer.succeed(self.map[name, cls, type_])
        except KeyError:
            return defer.fail(Failure(dns.DomainError(name)))

    def set_answer(self, name: str, address: str, ttl=60):
        rr = make_rrheader(name, address, ttl=ttl)
        self.map[rr.name.name, rr.cls, rr.type] = ([rr], [], [])


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


def test_parse_dns_server_string():
    def R(string, *, proto='udp', host=None, port=53):
        assert parse_dns_server_string(string) == DnsServerInfo(proto, host, port)

    def E(string):
        with pytest.raises(InvalidDnsServerString):
            parse_dns_server_string(string)

    R('127.0.0.1', host='127.0.0.1')
    R('2000::', host='2000::')
    R('[2000::]', host='2000::')

    R('127.0.0.1:88', host='127.0.0.1', port=88)
    E('2000:::88')
    R('[2000::]:88', host='2000::', port=88)

    R('tcp://127.0.0.1', proto='tcp', host='127.0.0.1')
    R('udp://127.0.0.1', proto='udp', host='127.0.0.1')
    E('tcp://2000::')
    R('tcp://[2000::]', proto='tcp', host='2000::')

    E('[200::')
    E('[20u::]')
    E('127.0.0.1:ff')
    E('[2000::]ff')


def test_parse_hosts_file():
    name2ip = parse_hosts_file('''
        127.0.0.1   localhost loopback
        ::1         localhost   # asdf
        127.0.0.1   localhost loopback

        # asdf
        0.0.0.0     a b
        0.0.0.1     c a

        # bad lines
        0.0.0.256 asdf
        0.0.0.0
    '''.splitlines())
    assert name2ip == dict(
        localhost=iplist('127.0.0.1', '::1'),
        loopback=iplist('127.0.0.1'),
        a=iplist('0.0.0.0', '0.0.0.1'),
        b=iplist('0.0.0.0'),
        c=iplist('0.0.0.1'),
    )


class TestResolverBase(unittest.TestCase):
    def setUp(self):
        self.defereds = []
        self.resolver = None

    def tearDown(self):
        return defer.gatherResults(self.defereds)

    def _check_query(self, query: dns.Query, expect=None, fail=False):
        if fail:
            assert expect is None

        d = defer.Deferred()
        self.defereds.append(d)

        def check_result(result):
            try:
                if fail:
                    self.fail('dns failure expected')

                ans, auth, add = result
                assert [rrheader_to_ip(rr) for rr in ans] == expect
            except:
                d.callback(False)
                raise
            else:
                d.callback(True)

        def failed(failure):
            try:
                if not fail:
                    print('query failed: ', query)
                    print(failure)
                    self.fail('query failed')
            except:
                d.callback(False)
                raise
            else:
                d.callback(True)

        self.resolver.query(query, timeout=[0.5]).addCallbacks(check_result, failed)
        return d

    def check_a(self, name: str, expect=None, fail=False):
        return self._check_query(
            dns.Query(name.encode('utf8'), dns.A, dns.IN),
            expect=expect, fail=fail,
        )

    def check_aaaa(self, name: str, expect=None, fail=False):
        return self._check_query(
            dns.Query(name.encode('utf8'), dns.AAAA, dns.IN),
            expect=expect, fail=fail,
        )

    def check_all(self, name: str, expect=None, fail=False):
        return self._check_query(
            dns.Query(name.encode('utf8'), dns.ALL_RECORDS, dns.IN),
            expect=expect, fail=fail,
        )


class TestHostsResolver(TestResolverBase):
    def setUp(self):
        super().setUp()

        self.hosts_file = None
        hosts_string = '''
            127.0.0.1   localhost loopback
            ::1         localhost   # asdf
        '''
        self.setup_resolver(hosts_string)

    def setup_resolver(self, hosts_string):
        fd, self.hosts_file = tempfile.mkstemp(prefix='hosts_', suffix='.txt', text=True)
        os.write(fd, hosts_string.encode('utf8'))
        self.resolver = HostsResolver(self.hosts_file)
        os.close(fd)

    def tearDown(self):
        d = super().tearDown()
        return d.addBoth(lambda ignore: self.cleanup())

    def cleanup(self):
        os.unlink(self.hosts_file)

    def test_resolve(self):
        self.check_a('localhost', iplist('127.0.0.1'))
        self.check_aaaa('localhost', iplist('::1'))
        self.check_all('localhost', iplist('127.0.0.1', '::1'))
        self.check_a('loopback', iplist('127.0.0.1'))

        self.check_a('asdf.asdf', fail=True)


class TestCachingResolver(TestResolverBase):
    def setUp(self):
        super().setUp()
        self.fake_resolver = FakeResolver()
        self.clock = task.Clock()
        self.resolver = CachingResolver(self.fake_resolver, reactor=self.clock)

    def tearDown(self):
        d = super().tearDown()
        # this avoids the error
        # twisted.trial.util.DirtyReactorAggregateError: Reactor was unclean.
        return d.addCallback(lambda ignore: self.resolver.clear())

    def test_caching(self):
        self.fake_resolver.set_answer('asdf', '0.0.0.1', ttl=30)

        def check_cached(succ):
            assert succ
            when, (ans, ns, add) = self.resolver.cache[dns.Query(b'asdf', dns.A, dns.IN)]
            assert rrheader_to_ip(ans[0]) == IPv4Address('0.0.0.1')
            assert len(self.resolver.cancel) == 1

            self.fake_resolver.set_answer('asdf', '0.0.0.2', ttl=30)
            # serve from cached
            self.check_a('asdf', iplist('0.0.0.1')).addCallback(check_expired_1)

        def check_expired_1(succ):
            assert succ
            self.clock.advance(31)
            self.check_a('asdf', iplist('0.0.0.2')).addCallback(check_expired_2)

        def check_expired_2(succ):
            assert succ
            self.clock.advance(31)
            assert len(self.resolver.cache) == len(self.resolver.cancel) == 0

        self.check_a('asdf', iplist('0.0.0.1')).addCallback(check_cached)


del TestResolverBase
