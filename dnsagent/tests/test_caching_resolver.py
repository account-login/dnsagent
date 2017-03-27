from functools import partial
from ipaddress import IPv4Address

from twisted.internet import task, defer
from twisted.names import dns

from dnsagent.resolver.cache import CachingResolver
from dnsagent.tests import BaseTestResolver, FakeResolver, iplist
from dnsagent.utils import rrheader_to_ip, sequence_deferred_call


# noinspection PyAttributeOutsideInit
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
        self.fake_resolver.set_answer('asdf', '0.0.0.1', ttl=25)

        def check_cached():
            self.clock.advance(2)
            (ans, ns, add), ttl = self.resolver.cache.peek(dns.Query(b'asdf', dns.A, dns.IN))
            assert ttl == 25 - 2
            assert rrheader_to_ip(ans[0]) == IPv4Address('0.0.0.1')

            self.fake_resolver.set_answer('asdf', '0.0.0.2', ttl=30)
            # serve from cached
            return self.check_a('asdf', iplist('0.0.0.1'))

        def check_expired():
            self.clock.advance(31)
            return self.check_a('asdf', iplist('0.0.0.2'))

        return sequence_deferred_call([
            partial(self.check_a, 'asdf', iplist('0.0.0.1')),
            check_cached,
            check_expired,
        ])

    @defer.inlineCallbacks
    def test_zero_ttl(self):
        self.fake_resolver.set_answer('asdf', '1.2.3.4', ttl=0)
        yield self.check_a('asdf', iplist('1.2.3.4'))
        assert len(self.resolver.cache) == 0

    @defer.inlineCallbacks
    def test_ttl_decrease(self):
        self.fake_resolver.set_multiple_answer('asdf', [('1.2.3.4', 10), ('4.3.2.1', 15)])
        yield self.check_a('asdf', iplist('1.2.3.4', '4.3.2.1'))

        self.clock.advance(2)
        ans, ns, add = yield self.check_a('asdf', iplist('1.2.3.4', '4.3.2.1'))
        assert ans[0].ttl == 8
        assert ans[1].ttl == 13


del BaseTestResolver
