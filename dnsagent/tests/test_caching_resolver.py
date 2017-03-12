from ipaddress import IPv4Address

from twisted.internet import task, defer
from twisted.names import dns

from dnsagent.resolver import CachingResolver
from dnsagent.tests import BaseTestResolver, FakeResolver, iplist
from dnsagent.utils import rrheader_to_ip


class TestCachingResolver(BaseTestResolver):
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


del BaseTestResolver
