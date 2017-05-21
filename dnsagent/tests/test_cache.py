import pytest
from twisted.internet import task
from twisted.trial import unittest

from dnsagent.cache import LinkedList, LFUPolicy, LRUPolicy, TTLCache


class TestLinkedList(unittest.TestCase):
    def setUp(self):
        self.ll = LinkedList()

    def check(self, items):
        if not self.ll.empty():
            prev = self.ll.end()
            next = self.ll.front()
            while True:
                assert next.prev is prev
                if next is self.ll:
                    break
                prev, next = next, next.next

        assert list(self.ll) == list(items)

    def test_insert_head(self):
        self.check([])
        for i in range(5):
            self.ll.push_front(i)
            self.check(reversed(range(i + 1)))

    def test_remove_node(self):
        for to_remove in range(5):
            self.ll.clear()
            nodes = []
            for i in range(5):
                nodes.append(self.ll.push_front(i))
            nodes.reverse()

            nodes[to_remove].remove()
            self.check([node.data for index, node in enumerate(nodes) if index != to_remove])

    def test_insert_after(self):
        for pos in range(5):
            self.ll.clear()
            nodes = []
            for i in range(5):
                nodes.append(self.ll.push_front(i))
            nodes.reverse()

            nodes[pos].insert_after(10)
            lst = list(reversed(range(5)))
            lst.insert(pos + 1, 10)
            self.check(lst)

    def test_pop_tail(self):
        for i in range(5):
            self.ll.push_front(i)
        for i in range(5):
            assert self.ll.pop_back().data == i


class TestLFUPolicy(unittest.TestCase):
    def setUp(self):
        self.policy = LFUPolicy(maxsize=3)

    def check_items(self, *items):
        assert items == tuple(
            (freq, list(order_list))
            for freq, order_list in self.policy.freq_list
        )

    def test_evict(self):
        assert self.policy.touch('a') is None
        self.check_items((1, list('a')))

        assert self.policy.touch('b') is None
        assert self.policy.touch('c') is None
        self.check_items((1, list('cba')))

        assert self.policy.touch('c') is None
        self.check_items((1, list('ba')), (2, list('c')))
        assert self.policy.touch('a') is None
        self.check_items((1, list('b')), (2, list('ac')))

        assert self.policy.touch('d') == 'b'
        self.check_items((1, list('d')), (2, list('ac')))

        self.policy.touch('d')
        assert self.policy.touch('e') == 'c'
        self.check_items((1, list('e')), (2, list('da')))

    def test_remove(self):
        for x in 'abc':
            self.policy.touch(x)
        for x in 'ac':
            self.policy.touch(x)
        self.policy.remove('a')
        self.check_items((1, ['b']), (2, ['c']))

    def test_clear(self):
        for x in 'abc':
            self.policy.touch(x)
        self.policy.clear()
        self.check_items()


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
