import abc
import math
from collections import OrderedDict

from dnsagent.utils import get_reactor


class BaseCachePolicy(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def touch(self, key):
        pass

    @abc.abstractmethod
    def remove(self, key):
        pass

    @abc.abstractmethod
    def clear(self):
        pass


class UnlimitedPolicy(BaseCachePolicy):
    def touch(self, key):
        pass

    def remove(self, key):
        pass

    def clear(self):
        pass


class LRUPolicy(BaseCachePolicy):
    def __init__(self, maxsize):
        assert maxsize > 0
        self.maxsize = maxsize
        self.od = OrderedDict()

    def touch(self, key):
        assert key is not None
        self.od.setdefault(key)
        self.od.move_to_end(key)
        if len(self.od) > self.maxsize:
            return self.od.popitem(last=False)[0]

    def remove(self, key):
        del self.od[key]

    def clear(self):
        self.od.clear()


class LLNode:
    __slots__ = ('data', 'prev', 'next')

    def __init__(self, data):
        self.data = data
        self.prev = None
        self.next = None


def llnode_insert(node: LLNode, new_node: LLNode):
    new_node.prev = node

    new_node.next = node.next
    if new_node.next is not None:
        new_node.next.prev = new_node

    node.next = new_node


def llnode_remove(node: LLNode):
    node.prev.next = node.next
    if node.next is not None:
        node.next.prev = node.prev


class LinkedList(LLNode):
    def __init__(self):
        super().__init__(None)
        self.tail = None

    def get_head(self) -> LLNode:
        if self.next is None:
            raise ValueError('Empty LinkedList')
        return self.next

    def insert_head(self, data) -> LLNode:
        node = LLNode(data)
        if self.tail is None:
            self.tail = node
        llnode_insert(self, node)
        return node

    def insert_after(self, node: LLNode, data):
        after = LLNode(data)
        if node is self.tail:
            self.tail = after
        llnode_insert(node, after)

    def remove_node(self, node: LLNode):
        if node is self.tail:
            self.tail = self.tail.prev
            if self.tail is self:
                self.tail = None
        llnode_remove(node)

    def pop_tail(self):
        node = self.tail
        self.tail = self.tail.prev
        if self.tail is self:
            self.tail = None
        llnode_remove(node)
        return node.data

    def is_empty(self):
        return self.next is None

    def clear(self):
        self.next = None
        self.tail = None

    def __iter__(self):
        node = self.next
        while node is not None:
            yield node.data
            node = node.next


class LFUPolicy(BaseCachePolicy):
    def __init__(self, maxsize: int):
        self.maxsize = maxsize
        self.freq_list = LinkedList()   # freq: int, order_list: LinkedList[Type[key]]
        self.key_to_node = dict()       # key -> (freq_list_node, order_list_node)

    def touch(self, key):
        try:
            freq_list_node, order_list_node = self.key_to_node[key]
        except KeyError:
            # eviction before insertion
            evicted = None
            if len(self.key_to_node) >= self.maxsize:
                evicted = self._evict()

            # get lowest order list
            if self.freq_list.is_empty():
                self.freq_list.insert_head((1, (LinkedList())))
            freq_list_node = self.freq_list.get_head()

            # insert key to order list
            freq, order_list = freq_list_node.data
            assert freq == 1
            order_list_node = order_list.insert_head(key)
            self.key_to_node[key] = freq_list_node, order_list_node

            return evicted
        else:
            freq, order_list = freq_list_node.data
            assert order_list_node.data == key
            # remove key from old frequency
            order_list.remove_node(order_list_node)

            # next frequency
            if freq_list_node.next is None or freq_list_node.next.data[0] != freq + 1:
                self.freq_list.insert_after(freq_list_node, (freq + 1, LinkedList()))

            next_freq, next_order_list = freq_list_node.next.data
            assert next_freq == freq + 1

            # add key to new frequency
            next_order_list_node = next_order_list.insert_head(key)
            self.key_to_node[key] = freq_list_node.next, next_order_list_node

            # remove empty order list
            if order_list.is_empty() and freq != 1:
                self.freq_list.remove_node(freq_list_node)

    def _evict(self):
        freq_list_node = self.freq_list.get_head()
        freq, order_list = freq_list_node.data
        if order_list.is_empty():   # lowest order list is empty, try next.
            assert freq == 1
            freq_list_node = freq_list_node.next
            freq, order_list = freq_list_node.data

        key = order_list.pop_tail()
        del self.key_to_node[key]
        # remove empty order list
        if freq != 1 and order_list.is_empty():
            self.freq_list.remove_node(freq_list_node)
        return key

    def remove(self, key):
        freq_list_node, order_list_node = self.key_to_node.pop(key)
        freq, order_list = freq_list_node.data
        order_list.remove_node(order_list_node)
        # remove empty order list
        if freq != 1 and order_list.is_empty():
            self.freq_list.remove_node(freq_list_node)

    def clear(self):
        self.freq_list.clear()
        self.key_to_node.clear()


class TTLCache:
    def __init__(self, clean_inteval=30, policy: BaseCachePolicy = None, reactor=None):
        self.clean_inteval = clean_inteval
        self.policy = policy or UnlimitedPolicy()
        self.reactor = get_reactor(reactor)

        self.map = dict()   # key -> (value, expire_time)
        self.started_time = None    # type: float
        self.pending_clean = dict()
        self.delayed_calls = dict()

    def put(self, key, value, ttl: float):
        assert key is not None
        assert ttl > 0

        evicted = self.policy.touch(key)
        if evicted is not None:
            del self.map[evicted]

        now = self.reactor.seconds()
        if self.started_time is None:
            self.started_time = now

        expire_time = now + ttl
        self.map[key] = value, expire_time

        tick = self._get_tick(expire_time)
        if tick not in self.pending_clean:
            assert tick not in self.delayed_calls
            clean_time = self.started_time + tick * self.clean_inteval
            dc = self.reactor.callLater(
                # add a small delay to clean time to avoid firing self.run_clean() too early
                clean_time - now + 0.01,
                self._run_clean_up, tick,
            )
            self.delayed_calls[tick] = dc
        pending = self.pending_clean.setdefault(tick, [])
        pending.append(key)

    def get(self, key):
        value, expire_time = self.map[key]  # raise KeyError
        self.policy.touch(key)
        now = self.reactor.seconds()
        if expire_time < now:
            self.remove(key)
            raise KeyError

        return value, expire_time - now

    def peek(self, key):
        value, expire_time = self.map[key]  # raise KeyError
        return value, expire_time - self.reactor.seconds()

    def remove(self, key):
        del self.map[key]
        self.policy.remove(key)

    def __len__(self):
        return len(self.map)

    def _get_tick(self, time):
        return math.ceil((time - self.started_time) / self.clean_inteval)

    def _run_clean_up(self, tick):
        del self.delayed_calls[tick]
        now = self.reactor.seconds()
        for key in self.pending_clean.pop(tick):
            try:
                value, expire_time = self.map[key]
            except KeyError:
                pass
            else:
                if expire_time <= now:
                    self.remove(key)
                else:
                    assert key in self.pending_clean[self._get_tick(expire_time)]

    def clear(self):
        self.map.clear()
        self.policy.clear()
        self.pending_clean.clear()
        # we need cancel all DelayedCall in unittest
        for dc in self.delayed_calls.values():
            dc.cancel()
        self.delayed_calls.clear()
