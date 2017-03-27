from functools import partial
from ipaddress import IPv4Address

import pytest
from twisted.internet import task, defer
from twisted.names import dns
from twisted.trial import unittest

from dnsagent.resolver.cache import (
    heap_left, heap_right, MinSet,
    LFUPolicy, LRUPolicy, TTLCache, CachingResolver,
)
from dnsagent.tests import BaseTestResolver, FakeResolver, iplist
from dnsagent.tests.datagen import gen_sort_case
from dnsagent.utils import rrheader_to_ip, sequence_deferred_call


def verify_heap(heap, key):
    for parent in range(len(heap) // 2):
        for child in (heap_left(parent), heap_right(parent)):
            if child < len(heap):
                assert key(heap[parent]) <= key(heap[child])


# noinspection PyAttributeOutsideInit
class TestMinSet(unittest.TestCase):
    def setUp(self):
        self.key = lambda x: x[0]
        self.minset = MinSet(key=self.key)
        self.refmap = dict()

    def verify(self, values):
        verify_heap(self.minset.heap, self.key)
        assert sorted(self.minset.map.values()) == list(range(len(self.minset.heap)))
        for key, index in self.minset.map.items():
            assert self.key(self.minset.heap[index]) == key

        assert sorted(self.minset.heap, key=self.key) == sorted(values, key=self.key)

    def clear(self):
        self.minset.clear()
        self.refmap.clear()

    def push(self, value):
        self.minset.push(value)
        self.refmap[self.key(value)] = value

    def remove(self, value):
        self.minset.remove(value)
        del self.refmap[self.key(value)]

    def increase(self, index, to):
        old = self.minset.heap[index]
        self.minset.increase(index, to)
        del self.refmap[self.key(old)]
        self.refmap[self.key(to)] = to

    def decrease(self, index, to):
        old = self.minset.heap[index]
        self.minset.decrease(index, to)
        del self.refmap[self.key(old)]
        self.refmap[self.key(to)] = to

    def test_push(self):
        for case in gen_sort_case(7):
            for num in case:
                self.push((num, object()))
                self.verify(self.refmap.values())

            self.clear()

    def test_remove(self):
        for case in gen_sort_case(7):
            for num in case:
                self.push((num, object()))
            minset = self.minset.copy()
            refmap = self.refmap.copy()

            for num in case:
                self.minset = minset.copy()
                self.refmap = refmap.copy()
                self.remove((num, object()))
                self.verify(self.refmap.values())

            self.clear()

    def test_increase(self):
        for case in gen_sort_case(7):
            if len(case) == 0:
                continue
            for num in case:
                self.push((num, object()))

            minset = self.minset.copy()
            refmap = self.refmap.copy()

            for index, value in enumerate(minset.heap):
                for to in range(self.key(value), max(case) + 1):
                    self.minset = minset.copy()
                    self.refmap = refmap.copy()
                    self.increase(index, (to + 0.1, object()))
                    self.verify(self.refmap.values())

            self.clear()

    def test_decrease(self):
        for case in gen_sort_case(7):
            if len(case) == 0:
                continue
            for num in case:
                self.push((num, object()))

            minset = self.minset.copy()
            refmap = self.refmap.copy()

            for index, value in enumerate(minset.heap):
                for to in range(self.key(value), min(case) - 1, -1):
                    self.minset = minset.copy()
                    self.refmap = refmap.copy()
                    self.decrease(index, (to - 0.1, object()))
                    self.verify(self.refmap.values())

            self.clear()

    def test_poppush(self):
        for x in [1, 2, 3]:
            self.minset.push((x, None))
        minset = self.minset.copy()

        assert self.minset.poppush((0, None)) == (1, None)
        self.verify((x, None) for x in [0, 2, 3])

        self.minset = minset.copy()
        assert self.minset.poppush((1, None)) == (1, None)
        self.verify((x, None) for x in [1, 2, 3])

        self.minset = minset.copy()
        assert self.minset.poppush((2.5, None)) == (1, None)
        self.verify((x, None) for x in [2, 2.5, 3])


class TestLFUPolicy(unittest.TestCase):
    def setUp(self):
        self.policy = LFUPolicy(maxsize=3)

    def check_items(self, items):
        assert items == self.policy.map
        assert sorted(self.policy.minset.heap) == sorted(
            (freq, serial, key) for key, (freq, serial) in items.items()
        )

    def test_evict(self):
        assert self.policy.touch('a') is None
        self.check_items(dict(a=(0, 1)))

        assert self.policy.touch('b') is None
        assert self.policy.touch('c') is None
        self.check_items(dict(a=(0, 1), b=(0, 2), c=(0, 3)))

        assert self.policy.touch('c') is None
        self.check_items(dict(a=(0, 1), b=(0, 2), c=(1, 4)))
        assert self.policy.touch('a') is None
        self.check_items(dict(a=(1, 5), b=(0, 2), c=(1, 4)))

        assert self.policy.touch('d') == 'b'
        self.check_items(dict(a=(1, 5), c=(1, 4), d=(0, 6)))

        self.policy.touch('d')
        assert self.policy.touch('e') == 'c'
        self.check_items(dict(a=(1, 5), d=(1, 7), e=(0, 8)))

    def test_remove(self):
        for x in 'abc':
            self.policy.touch(x)
        self.policy.remove('b')
        self.check_items(dict(a=(0, 1), c=(0, 3)))

    def test_clear(self):
        for x in 'abc':
            self.policy.touch(x)
        self.policy.clear()
        self.check_items(dict())


class TestLRUPolicy(unittest.TestCase):
    def setUp(self):
        self.policy = LRUPolicy(maxsize=3)

    def check_items(self, items):
        assert list(self.policy.od.keys()) == items

    def test_evict(self):
        assert self.policy.touch(1) is None
        assert self.policy.touch(2) is None
        assert self.policy.touch(1) is None
        assert self.policy.touch(3) is None
        assert self.policy.touch(4) == 2
        self.check_items([1, 3, 4])

    def test_remove(self):
        for x in range(1, 4):
            self.policy.touch(x)
        self.policy.remove(2)
        self.check_items([1, 3])

    def test_clear(self):
        for x in range(1, 4):
            self.policy.touch(x)
        self.policy.clear()
        self.check_items([])


# noinspection PyAttributeOutsideInit
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


# noinspection PyAttributeOutsideInit
class TestTTLCacheWithLRUPolicy(unittest.TestCase):
    def setUp(self):
        self.policy = LRUPolicy(maxsize=3)
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


class TestTTLCacheWithLFUPolicy(unittest.TestCase):
    def setUp(self):
        self.policy = LFUPolicy(maxsize=3)
        self.clock = task.Clock()
        self.cache = TTLCache(clean_inteval=30, policy=self.policy, reactor=self.clock)

    def test_run(self):
        for _ in range(100):
            self.cache.put('k1', 'v1', 10)
            self.cache.put('k2', 'v2', 20)
            self.cache.put('k3', 'v3', 100)

        for _ in range(200):
            self.cache.put('k2', 'v2', 20)

        for _ in range(300):
            assert self.cache.get('k3') == ('v3', 100)

        self.cache.put('k4', 'v4', 10)
        with pytest.raises(KeyError):
            self.cache.get('k1')

        self.clock.advance(11)
        with pytest.raises(KeyError):
            self.cache.get('k4')
        assert self.cache.get('k2') == ('v2', 9)

        self.clock.advance(20)
        with pytest.raises(KeyError):
            self.cache.get('k2')


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
