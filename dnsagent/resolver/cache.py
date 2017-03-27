from itertools import chain

from twisted.internet import defer
from twisted.names import dns

from dnsagent import logger
from dnsagent.cache import TTLCache
from dnsagent.resolver.base import BaseResolver
from dnsagent.utils import get_reactor


__all__ = ('CachingResolver',)


def rrheader_adjust_ttl(rr: dns.RRHeader, diff):
    return dns.RRHeader(
        name=rr.name.name, type=rr.type, cls=rr.cls, ttl=int(rr.ttl + diff),
        payload=rr.payload,     # FIXME: update ttl in payload
    )


def query_result_adjust_ttl(result, diff):
    return tuple(
        [rrheader_adjust_ttl(r, diff) for r in rrlist]
        for rrlist in result
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
                self.cache.put(query, query_result_adjust_ttl(result, -minttl), minttl)
            return result
        else:
            assert ttl >= 0
            logger.debug('[%d]cache hit: %s', request_id, name.decode('latin1'))
            return query_result_adjust_ttl(result, ttl)

    def clear(self):
        self.cache.clear()

    def __repr__(self):
        return '<Cache for={}>'.format(self.resolver.__class__.__name__)
