import os
import tempfile
from ipaddress import IPv4Address
from typing import Sequence

from twisted.internet import task, defer
from twisted.names import dns
from twisted.names.error import ResolverError

from dnsagent.config import hosts
from dnsagent.resolver import (
    HostsResolver, CachingResolver, ParallelResolver, CnResolver,
)
from dnsagent.resolver.hosts import parse_hosts_file
from dnsagent.resolver.parallel import (
    PoliciedParallelResolver, BaseParalledResolverPolicy,
)
from dnsagent.utils import rrheader_to_ip
from dnsagent.tests import iplist, FakeResolver, TestResolverBase


def test_parse_hosts_file():
    name2ip = parse_hosts_file('''
        127.0.0.1   localhost loopback
        ::1         localhost   # asdf
        127.0.0.1   localhost loopback  # duplicated

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


class TestHostsResolver(TestResolverBase):
    def setUp(self):
        super().setUp()

        hosts_string = '''
            127.0.0.1   localhost loopback
            ::1         localhost   # asdf
        '''
        self.setup_resolver(hosts_string)

    def setup_resolver(self, hosts_string):
        fd, hosts_file = tempfile.mkstemp(prefix='hosts_', suffix='.txt', text=True)
        os.write(fd, hosts_string.encode('utf8'))
        self.resolver = HostsResolver(filename=hosts_file)
        os.close(fd)
        self.addCleanup(os.unlink, hosts_file)

    def test_resolve(self):
        self.check_a('localhost', iplist('127.0.0.1'))
        self.check_aaaa('localhost', iplist('::1'))
        self.check_all('localhost', iplist('127.0.0.1', '::1'))
        self.check_a('loopback', iplist('127.0.0.1'))

        self.check_a('asdf.asdf', fail=True)


class TestHostResolverMapping(TestResolverBase):
    def setUp(self):
        super().setUp()
        self.resolver = HostsResolver(mapping=dict(ASDF='1.2.3.4', localhost='::1'))

    def test_resolve(self):
        self.check_a('asdf', iplist('1.2.3.4'))
        self.check_aaaa('LocalHost', iplist('::1'))
        self.check_a('qwer', fail=True)


def test_config_hosts():
    # use system hosts file
    resolver = hosts()
    assert os.path.exists(resolver.filename)

    resolver = hosts(dict(ABC='1.2.3.4'))
    assert resolver.name2ip == dict(abc=iplist('1.2.3.4'))


class TestCachingResolver(TestResolverBase):
    def setUp(self):
        super().setUp()
        self.fake_resolver = FakeResolver()
        self.clock = task.Clock()
        self.resolver = CachingResolver(self.fake_resolver, reactor=self.clock)

        # this avoids the error
        # twisted.trial.util.DirtyReactorAggregateError: Reactor was unclean.
        self.addCleanup(self.resolver.clear)

    def test_caching(self):
        # TODO: test ttl
        self.fake_resolver.set_answer('asdf', '0.0.0.1', ttl=30)

        def check_cached(ignore):
            when, (ans, ns, add) = self.resolver.cache[dns.Query(b'asdf', dns.A, dns.IN)]
            assert rrheader_to_ip(ans[0]) == IPv4Address('0.0.0.1')
            assert len(self.resolver.cancel) == 1

            self.fake_resolver.set_answer('asdf', '0.0.0.2', ttl=30)
            # serve from cached
            d = self.check_a('asdf', iplist('0.0.0.1'))
            d.addCallback(check_expired_1).addErrback(final.errback)

        def check_expired_1(ignore):
            self.clock.advance(31)
            d = self.check_a('asdf', iplist('0.0.0.2'))
            d.addCallback(check_expired_2).addErrback(final.errback)

        def check_expired_2(ignore):
            self.clock.advance(31)
            assert len(self.resolver.cache) == len(self.resolver.cancel) == 0
            final.callback(True)

        final = defer.Deferred()
        query_d = self.check_a('asdf', iplist('0.0.0.1'))
        query_d.addCallback(check_cached).addErrback(final.errback)
        return final


class TestParallelResolver(TestResolverBase):
    def setUp(self):
        super().setUp()
        self.upstreams = [FakeResolver(), FakeResolver()]
        self.resolver = ParallelResolver(self.upstreams)

    def setup_upstream(self, index, addr, delay):
        self.upstreams[index].set_answer('asdf', addr)
        self.upstreams[index].delay = delay

    def test_resolve_1(self):
        self.setup_upstream(0, '0.0.0.1', 0.01)
        self.setup_upstream(1, '0.0.0.2', 0.02)
        self.check_a('asdf', iplist('0.0.0.1'))

    def test_resolve_2(self):
        self.setup_upstream(0, '0.0.0.1', 0.02)
        self.setup_upstream(1, '0.0.0.2', 0.01)
        self.check_a('asdf', iplist('0.0.0.2'))

    def test_partial_fail_1(self):
        self.setup_upstream(0, '1.1.1.1', 0.02)
        self.upstreams[1].delay = 0.01
        self.check_a('asdf', iplist('1.1.1.1'))

    def test_partial_fail_2(self):
        self.setup_upstream(1, '1.1.1.2', 0.02)
        self.upstreams[0].delay = 0.01
        self.check_a('asdf', iplist('1.1.1.2'))

    def test_all_fail(self):
        self.upstreams[0].delay = 0.01
        self.upstreams[1].delay = 0.02

        self.check_a('asdfasdf', fail=True)


class TestCnResolver(TestResolverBase):
    def setUp(self):
        super().setUp()
        self.fake_resolver = FakeResolver()
        self.resolver = CnResolver(self.fake_resolver)

    def test_cn(self):
        self.fake_resolver.set_answer('asdf', '114.114.114.114')
        self.check_a('asdf', iplist('114.114.114.114'))

    def test_ab_single_addr(self):
        self.fake_resolver.set_answer('asdf', '8.8.8.8')
        self.check_a('asdf', fail=True)

    def test_ab_multiple_addr(self):
        self.fake_resolver.set_multiple_answer('asdf', [('8.8.8.8', 60), ('8.8.4.4', 60)])
        self.check_a('asdf', iplist('8.8.8.8', '8.8.4.4'))

    def test_ipv6(self):
        self.fake_resolver.set_answer('asdf', '2001:400::')
        self.check_a('asdf', fail=True)


class NullPolicy(BaseParalledResolverPolicy):
    def for_results(self, results: Sequence):
        return None


class ExceptionPolicy(BaseParalledResolverPolicy):
    def __init__(self, exc_value):
        self.exc_value = exc_value

    def for_results(self, results: Sequence):
        raise self.exc_value


class TestPoliciedParallelResolver(TestResolverBase):
    # TODO: more tests

    def setUp(self):
        super().setUp()
        self.upstreams = [FakeResolver(), FakeResolver()]

    def test_no_result_selected(self):
        self.resolver = PoliciedParallelResolver(self.upstreams, NullPolicy())
        for ups in self.upstreams:
            ups.set_answer('asdf', '1.2.3.4')

        self.check_a('asdf', fail=ResolverError)

    def test_all_fail(self):
        self.resolver = PoliciedParallelResolver(self.upstreams, NullPolicy())
        self.check_a('asdf', fail=ResolverError)

    def test_exception(self):
        class MyException(Exception):
            pass

        policy = ExceptionPolicy(MyException('asdf'))
        self.resolver = PoliciedParallelResolver(self.upstreams, policy)
        for ups in self.upstreams:
            ups.set_answer('asdf', '1.2.3.4')

        self.check_a('asdf', fail=MyException)


del TestResolverBase
