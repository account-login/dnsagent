import os
import tempfile
from ipaddress import IPv4Address

from twisted.internet import task
from twisted.names import dns

from dnsagent.resolver import (
    rrheader_to_ip, HostsResolver, CachingResolver, ParallelResolver,
)
from dnsagent.tests import iplist, FakeResolver, TestResolverBase


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


del TestResolverBase
