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


def heap_left(index):
    return index * 2 + 1


def heap_right(index):
    return index * 2 + 2


def heap_parent(index):
    return (index - 1) // 2


class MinSet:
    def __init__(self, key):
        self.key = key
        self.heap = []
        self.map = dict()   # key -> index

    def __len__(self):
        return len(self.heap)

    def __contains__(self, item):
        return self.key(item) in self.map

    def copy(self):
        ret = type(self)(self.key)
        ret.heap = self.heap.copy()
        ret.map = self.map.copy()
        return ret

    def clear(self):
        self.heap.clear()
        self.map.clear()

    def push(self, value):
        key = self.key(value)
        try:
            index = self.map[key]
        except KeyError:
            index = len(self.heap)
            self.heap.append(value)
            self.map[self.key(value)] = index
            self.decrease(index, value)
        else:
            origin_key = self.key(self.heap[index])
            if key < origin_key:
                self.decrease(index, value)
            else:
                self.increase(index, value)

    def poppush(self, value):
        ret = self.heap[0]
        self.increase(0, value)     # no decrease needed since we are modifying root
        return ret

    def remove(self, value):
        key = self.key(value)
        index = self.map[key]
        last = self.heap.pop()
        if index == len(self.heap):     # remove last key
            del self.map[key]
        else:
            if self.key(last) < key:
                self.decrease(index, last)
            else:
                self.increase(index, last)

    def decrease(self, index, replacement):
        assert 0 <= index < len(self.heap)
        del self.map[self.key(self.heap[index])]

        key = self.key(replacement)
        parent = heap_parent(index)
        while parent >= 0:
            parent_key = self.key(self.heap[parent])
            if parent_key > key:    # push parent down
                self.heap[index] = self.heap[parent]
                self.map[parent_key] = index
                parent, index = heap_parent(parent), parent
            else:
                break

        self.heap[index] = replacement
        self.map[key] = index

    def decrease_value(self, old, new):
        old_key = self.key(old)
        assert old_key >= self.key(new)
        index = self.map[old_key]
        self.decrease(index, new)

    def increase(self, index, replacement):
        assert 0 <= index < len(self.heap)
        del self.map[self.key(self.heap[index])]

        replace_key = self.key(replacement)
        min_index, min_key = index, replace_key
        while True:
            index = min_index
            for child in (heap_left(index), heap_right(index)):
                if child < len(self.heap):
                    child_key = self.key(self.heap[child])
                    if child_key < min_key:
                        min_index, min_key = child, child_key

            if min_index != index:  # pull up child
                self.heap[index] = self.heap[min_index]
                self.map[min_key] = index
                min_key = replace_key
            else:
                break

        self.heap[index] = replacement
        self.map[replace_key] = index

    def increase_value(self, old, new):
        old_key = self.key(old)
        assert self.key(new) >= old_key
        index = self.map[old_key]
        self.increase(index, new)


class LFUPolicy(BaseCachePolicy):
    def __init__(self, maxsize):
        assert maxsize > 0
        self.maxsize = maxsize
        self.minset = MinSet(lambda x: x[:2])
        self.map = dict()   # key -> (freq, serial)
        self.serial = 0

    def _get_serial(self):
        self.serial += 1
        return self.serial

    def touch(self, key):
        assert key is not None
        try:
            freq, serial = self.map[key]
        except KeyError:
            key_id = (0, self._get_serial())
            mskey = key_id + (key,)
            if len(self.minset) >= self.maxsize:
                _, _, evicted = self.minset.poppush(mskey)
                del self.map[evicted]
                self.map[key] = key_id
                return evicted
            else:
                self.minset.push(mskey)
        else:
            old_mskey = (freq, serial, key)
            assert old_mskey in self.minset
            key_id = (freq + 1, self._get_serial())
            mskey = key_id + (key,)
            self.minset.increase_value(old_mskey, mskey)

        self.map[key] = key_id

    def remove(self, key):
        self.minset.remove(self.map.pop(key) + (key,))

    def clear(self):
        self.minset.clear()
        self.map.clear()


class TTLCache:
    def __init__(self, clean_inteval=30, policy: BaseCachePolicy = None, reactor=None):
        self.clean_inteval = clean_inteval
        self.policy = policy or UnlimitedPolicy()
        self.reactor = get_reactor(reactor)

        self.map = dict()
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
