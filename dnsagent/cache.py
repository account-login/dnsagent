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


class LinkedNode:
    def __init__(self, data):
        self.data = data
        self.prev = self.next = self

    def remove(self):
        self.prev.next = self.next
        self.next.prev = self.prev
        self.prev = self.next = None
        return self

    def insert_after(self, key):
        after = LinkedNode(key)
        after.prev = self
        after.next = self.next
        self.next.prev = self.next = after
        return after


class LinkedList(LinkedNode):
    def __init__(self):
        super().__init__(None)

    def end(self):
        return self

    def front(self):
        assert not self.empty()
        return self.next

    def back(self):
        assert not self.empty()
        return self.prev

    def empty(self):
        return self.prev is self

    def clear(self):
        self.prev = self.next = self

    def push_front(self, key):
        return self.insert_after(key)

    def pop_back(self):
        return self.back().remove()

    def __iter__(self):
        cur = self.next
        while cur is not self:
            yield cur.data
            cur = cur.next


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
            if self.freq_list.empty():
                self.freq_list.push_front((1, (LinkedList())))
            freq_list_node = self.freq_list.front()

            # insert key to order list
            freq, order_list = freq_list_node.data
            assert freq == 1
            order_list_node = order_list.push_front(key)
            self.key_to_node[key] = freq_list_node, order_list_node

            return evicted
        else:
            freq, order_list = freq_list_node.data
            assert order_list_node.data == key
            # remove key from old frequency
            order_list_node.remove()

            # next frequency
            if (
                freq_list_node.next is self.freq_list.end()
                or freq_list_node.next.data[0] != freq + 1
            ):
                freq_list_node.insert_after((freq + 1, LinkedList()))

            next_freq, next_order_list = freq_list_node.next.data
            assert next_freq == freq + 1

            # add key to new frequency
            next_order_list_node = next_order_list.push_front(key)
            self.key_to_node[key] = freq_list_node.next, next_order_list_node

            self._remove_empty_freq_list_node(freq_list_node)

    def _evict(self):
        freq_list_node = self.freq_list.front()
        freq, order_list = freq_list_node.data
        if order_list.empty():      # lowest order list is empty, try next.
            assert freq == 1
            freq_list_node = freq_list_node.next
            freq, order_list = freq_list_node.data

        key = order_list.pop_back().data
        del self.key_to_node[key]
        self._remove_empty_freq_list_node(freq_list_node)
        return key

    def remove(self, key):
        freq_list_node, order_list_node = self.key_to_node.pop(key)
        order_list_node.remove()
        self._remove_empty_freq_list_node(freq_list_node)

    def _remove_empty_freq_list_node(self, freq_list_node):
        freq, order_list = freq_list_node.data
        if freq != 1 and order_list.empty():
            freq_list_node.remove()

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
