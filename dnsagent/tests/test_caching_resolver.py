from ipaddress import IPv4Address

from twisted.internet import task
from twisted.names import dns

from dnsagent.resolver import CachingResolver
from dnsagent.tests import BaseTestResolver, FakeResolver, iplist
from dnsagent.utils import rrheader_to_ip, sequence_deferred_call


class TestCachingResolver(BaseTestResolver):
    def setUp(self):
        super().setUp()
        self.fake_resolver = FakeResolver()
        self.clock = task.Clock()
        self.resolver = CachingResolver(self.fake_resolver, reactor=self.clock)

        # this avoids the error
        # twisted.trial.util.DirtyReactorAggregateError: Reactor was unclean.
        self.addCleanup(self.resolver.clear)

    def tearDown(self):
        # Deferreds was waited in self.test_caching(), no clean up needed.
        pass

    def test_caching(self):
        # TODO: test ttl
        self.fake_resolver.set_answer('asdf', '0.0.0.1', ttl=30)

        def check_cached():
            when, (ans, ns, add) = self.resolver.cache[dns.Query(b'asdf', dns.A, dns.IN)]
            assert rrheader_to_ip(ans[0]) == IPv4Address('0.0.0.1')
            assert len(self.resolver.cancel) == 1

            self.fake_resolver.set_answer('asdf', '0.0.0.2', ttl=30)
            # serve from cached
            return self.check_a('asdf', iplist('0.0.0.1'))

        def check_expired_1():
            self.clock.advance(31)
            return self.check_a('asdf', iplist('0.0.0.2'))

        def check_expired_2():
            self.clock.advance(31)
            assert len(self.resolver.cache) == len(self.resolver.cancel) == 0

        return sequence_deferred_call([
            lambda: self.check_a('asdf', iplist('0.0.0.1')),
            check_cached,
            check_expired_1,
            check_expired_2,
        ])


del BaseTestResolver
