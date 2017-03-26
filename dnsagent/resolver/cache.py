import abc
from collections import OrderedDict
from itertools import chain
import math

from twisted.internet import defer
from twisted.names import dns

from dnsagent import logger
from dnsagent.resolver.base import BaseResolver
from dnsagent.utils import get_reactor


__all__ = ('CachingResolver',)


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
        self.od.setdefault(key)
        self.od.move_to_end(key)
        if len(self.od) > self.maxsize:
            return self.od.popitem(last=False)[0]

    def remove(self, key):
        del self.od[key]

    def clear(self):
        self.od.clear()


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


def rrheader_update_ttl(rr: dns.RRHeader, new_ttl):
    return dns.RRHeader(
        name=rr.name.name, type=rr.type, cls=rr.cls, ttl=int(new_ttl),
        payload=rr.payload,
    )


class CachingResolver(BaseResolver):
    """
    A resolver that caches the output of another resolver.

    ref: twisted.names.cache.CacheResolver
    """
    def __init__(self, resolver, cache=None, reactor=None):
        super().__init__()

        self.resolver = resolver
        self.reactor = get_reactor(reactor)
        self.cache = cache or TTLCache(reactor=self.reactor)

    @defer.inlineCallbacks
    def _lookup(self, name, cls, type_, timeout, **kwargs):
        # TODO: queue identical query
        request_id = kwargs.get('request_id', -1)

        query = dns.Query(name, type_, cls)
        try:
            result, ttl = self.cache.get(query)
        except KeyError:
            logger.debug('[%d]cache miss: %s', request_id, name.decode('latin1'))
            result = yield self.resolver.query(query, timeout=timeout, **kwargs)

            logger.debug('[%d]adding to cache: %r', kwargs.get('request_id', -1), query)
            minttl = min((rr.ttl for rr in chain.from_iterable(result)), default=0)
            if minttl > 0:
                self.cache.put(query, result, minttl)
            return result
        else:
            assert ttl >= 0
            logger.debug('[%d]cache hit: %s', request_id, name.decode('latin1'))
            return tuple([rrheader_update_ttl(r, ttl) for r in rrlist] for rrlist in result)

    def clear(self):
        self.cache.clear()

    def __repr__(self):
        return '<Cache for={}>'.format(self.resolver.__class__.__name__)
