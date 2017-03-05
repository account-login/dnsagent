from twisted.internet import defer
from twisted.names import dns
from twisted.names.error import DomainError
from twisted.names.resolve import ResolverChain as OriginResolverChain

from dnsagent.resolver.base import patch_resolver
from dnsagent.utils import repr_short


__all__ = ('ChainedResolver',)


@patch_resolver
class ChainedResolver(OriginResolverChain):
    def _lookup(self, name, cls, type, timeout, **kwargs):
        """
        Build a L{dns.Query} for the given parameters and dispatch it
        to each L{IResolver} in C{self.resolvers} until an answer or
        L{error.AuthoritativeDomainError} is returned.

        @type name: C{str}
        @param name: DNS name to resolve.

        @type type: C{int}
        @param type: DNS record type.

        @type cls: C{int}
        @param cls: DNS record class.

        @type timeout: Sequence of C{int}
        @param timeout: Number of seconds after which to reissue the query.
            When the last timeout expires, the query is considered failed.

        @rtype: L{Deferred}
        @return: A L{Deferred} which fires with a three-tuple of lists of
            L{twisted.names.dns.RRHeader} instances.  The first element of the
            tuple gives answers.  The second element of the tuple gives
            authorities.  The third element of the tuple gives additional
            information.  The L{Deferred} may instead fail with one of the
            exceptions defined in L{twisted.names.error} or with
            C{NotImplementedError}.
        """
        if not self.resolvers:
            return defer.fail(DomainError())
        q = dns.Query(name, type, cls)
        d = self.resolvers[0].query(q, timeout, **kwargs)
        for r in self.resolvers[1:]:
            d = d.addErrback(ChainedFailureHandler(r.query, q, timeout, **kwargs))
        return d

    def __repr__(self):
        sub = '|'.join(map(repr_short, self.resolvers))
        return '<Chain {}>'.format(sub)


class ChainedFailureHandler:
    def __init__(self, resolver, query, timeout, **kwargs):
        self.resolver = resolver
        self.query = query
        self.timeout = timeout
        self.kwargs = kwargs

    def __call__(self, failure):
        # AuthoritativeDomainErrors should halt resolution attempts
        failure.trap(dns.DomainError, defer.TimeoutError, NotImplementedError)
        return self.resolver(self.query, self.timeout, **self.kwargs)
