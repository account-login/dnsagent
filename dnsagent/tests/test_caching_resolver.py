from ipaddress import IPv4Address

import pytest
from twisted.internet import task, defer
from twisted.names import dns
from twisted.trial import unittest

from dnsagent.resolver.cache import LRUPolicy, TTLCache, CachingResolver
from dnsagent.tests import BaseTestResolver, FakeResolver, iplist
from dnsagent.utils import rrheader_to_ip, sequence_deferred_call


class TestLRUPolicy(unittest.TestCase):
    def setUp(self):
        self.policy = LRUPolicy(3)

    def assert_items(self, items):
        assert list(self.policy.od.keys()) == items

    def test_evict(self):
        assert self.policy.touch(1) is None
        assert self.policy.touch(2) is None
        assert self.policy.touch(1) is None
        assert self.policy.touch(3) is None
        assert self.policy.touch(4) == 2
        self.assert_items([1, 3, 4])

    def test_remove(self):
        self.policy.touch(1)
        self.policy.touch(2)
        self.policy.touch(3)

        self.policy.remove(2)
        self.assert_items([1, 3])


class TestTTLCache(unittest.TestCase):
    def setUp(self):
        self.clock = task.Clock()
        self.cache = TTLCache(clean_inteval=30, reactor=self.clock)

    def tearDown(self):
        assert not self.clock.getDelayedCalls()

    def test_put_get_expire(self):
        self.cache.put('key', 'value', 10)
        assert self.cache.pending_clean[1] == ['key']
        assert len(self.cache.delayed_calls) == 1

        self.clock.advance(9)
        assert self.cache.get('key') == ('value', 1)
        self.clock.advance(2)
        with pytest.raises(KeyError):
            self.cache.get('key')

        self.clock.advance(20)
        assert not self.cache.pending_clean
        assert not self.cache.delayed_calls

    def test_put_clean_get(self):
        self.cache.put('k1', 'v1', 10)
        self.cache.put('k2', 'v2', 20)

        self.clock.advance(31)
        with pytest.raises(KeyError):
            self.cache.get('k1')
        with pytest.raises(KeyError):
            self.cache.get('k2')

        assert not self.cache.pending_clean
        assert not self.cache.delayed_calls

    def test_ttl_increase(self):
        self.cache.put('key', 'v1', 10)
        self.cache.put('key', 'v2', 40)

        self.clock.advance(9)
        assert self.cache.get('key') == ('v2', 31)
        self.clock.advance(30)
        assert self.cache.get('key') == ('v2', 1)

        self.clock.advance(22)
        with pytest.raises(KeyError):
            self.cache.get('key')

    def test_ttl_decrease(self):
        self.cache.put('key', 'v1', 40)
        self.cache.put('key', 'v2', 10)

        self.clock.advance(31)
        with pytest.raises(KeyError):
            self.cache.get('key')

        self.clock.advance(30)

    def test_clean(self):
        self.cache.put('k1', 'v1', 20)
        self.cache.put('k2', 'v2', 40)
        self.cache.clear()

        assert not self.cache.map
        assert not self.cache.pending_clean
        assert not self.cache.delayed_calls

    def test_len(self):
        assert len(self.cache) == 0
        self.cache.put('key', 'v1', 100)
        self.cache.put('key', 'v2', 100)
        assert len(self.cache) == 1

        self.cache.clear()


class TestTTLCacheWithLRUPolicy(unittest.TestCase):
    def setUp(self):
        self.policy = LRUPolicy(3)
        self.clock = task.Clock()
        self.cache = TTLCache(clean_inteval=30, policy=self.policy, reactor=self.clock)

    def tearDown(self):
        assert not self.cache.policy.od
        assert not self.cache.map

    def check_state(self, items):
        assert list(self.policy.od.keys()) == items
        assert set(self.cache.map.keys()) == set(items)

    def test_run(self):
        self.cache.put('k0', 'v0', 500)
        self.cache.put('k1', 'v1', 10)
        self.cache.put('k3', 'v3', 20)
        self.cache.put('k2', 'v2', 100)
        self.cache.put('k3', 'v3', 20)
        self.check_state(['k1', 'k2', 'k3'])

        self.cache.get('k2')
        self.check_state(['k1', 'k3', 'k2'])

        self.clock.advance(31)
        self.check_state(['k2'])

        self.cache.remove('k2')
        self.check_state([])


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
            lambda: self.check_a('asdf', iplist('0.0.0.1')),
            check_cached,
            check_expired,
        ])

    @defer.inlineCallbacks
    def test_zero_ttl(self):
        self.fake_resolver.set_answer('asdf', '1.2.3.4', ttl=0)
        yield self.check_a('asdf', iplist('1.2.3.4'))
        assert len(self.resolver.cache) == 0


del BaseTestResolver
