import itertools

from twisted.internet import defer
from twisted.names import dns

from dnsagent import logger
from dnsagent.resolver.base import MyResolverBase


__all__ = ('CachingResolver',)


class CachingResolver(MyResolverBase):
    """
    A resolver that caches the output of another resolver.

    ref: twisted.names.cache.CacheResolver
    """
    def __init__(self, resolver, reactor=None):
        super().__init__()

        self.resolver = resolver
        if reactor is None:
            from twisted.internet import reactor
        self.reactor = reactor
        self.cache = dict()
        self.cancel = dict()

    def _lookup(self, name, cls, type_, timeout, **kwargs):
        # TODO: queue identical query
        request_id = kwargs.get('request_id', -1)

        def cache_miss(query):
            logger.debug('[%d]cache miss: %s', request_id, name.decode('latin1'))

            def add_to_cache(res):
                self.cache_result(query, res, **kwargs)
                return res

            d = self.resolver.query(query, timeout=timeout, **kwargs)
            return d.addCallback(add_to_cache)

        def adjust_ttl(rr: dns.RRHeader, diff):
            return dns.RRHeader(
                name=rr.name.name, type=rr.type, cls=rr.cls, ttl=int(rr.ttl - diff),
                payload=rr.payload,
            )

        q = dns.Query(name, type_, cls)
        try:
            when, (ans, auth, add) = self.cache[q]
        except KeyError:
            return cache_miss(q)
        else:
            now = self.reactor.seconds()
            diff = now - when
            try:
                result = (
                    [adjust_ttl(r, diff) for r in ans],
                    [adjust_ttl(r, diff) for r in auth],
                    [adjust_ttl(r, diff) for r in add],
                )
            except ValueError:
                # negative ttl
                return cache_miss(q)
            else:
                logger.debug('[%d]cache hit: %s', request_id, name.decode('latin1'))
                return defer.succeed(result)

    def cache_result(self, query, payload, cache_time=None, **kwargs):
        """
        Cache a DNS entry.

        @param query: a L{dns.Query} instance.
        @param payload: a 3-tuple of lists of L{dns.RRHeader} records, the
            matching result of the query (answers, authority and additional).
        @param cache_time: The time (seconds since epoch) at which the entry is
            considered to have been added to the cache. If L{None} is given,
            the current time is used.
        """
        minttl = min(
            map(lambda rr: rr.ttl, itertools.chain.from_iterable(payload)),
            default=0,
        )

        logger.debug('[%d]adding to cache: %r', kwargs.get('request_id', -1), query)
        self.cache[query] = (cache_time or self.reactor.seconds(), payload)

        if query in self.cancel:
            # reset count down
            self.cancel[query].cancel()
        self.cancel[query] = self.reactor.callLater(minttl, self.clear_entry, query)

    def clear_entry(self, query):
        del self.cache[query]
        del self.cancel[query]

    def clear(self):
        for d in self.cancel.values():
            d.cancel()
        for query in list(self.cancel.keys()):
            self.clear_entry(query)

    def __repr__(self):
        return '<Cache for={}>'.format(self.resolver.__class__.__name__)
