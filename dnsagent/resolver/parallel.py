from twisted.internet import defer
from twisted.names import dns
from twisted.names.error import DomainError
from twisted.python.failure import Failure

from dnsagent import logger
from dnsagent.resolver.base import MyResolverBase
from dnsagent.utils import PrefixedLogger


__all__ = ('ParallelResolver',)


class ParallelResolver(MyResolverBase):
    """
    Lookup an address using multiple L{IResolver}s in parallel.
    """
    def __init__(self, resolvers):
        """
        @type resolvers: L{list}
        @param resolvers: A L{list} of L{IResolver} providers.
        """
        super().__init__()
        self.resolvers = resolvers

    def _lookup(self, name, cls, type_, timeout, **kwargs):
        """
        Build a L{dns.Query} for the given parameters and dispatch it
        to each L{IResolver} in C{self.resolvers} until an answer or
        L{error.AuthoritativeDomainError} is returned.

        @type name: C{str}
        @param name: DNS name to resolve.

        @type type_: C{int}
        @param type_: DNS record type.

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

        q = dns.Query(name, type_, cls)
        d = defer.Deferred()
        ResolverHub(q, timeout, self.resolvers, d, **kwargs)
        return d

    def __repr__(self):
        sub = '|'.join(map(repr, self.resolvers))
        return '<Parallel {}>'.format(sub)


class ResolverHub:
    def __init__(self, query, timeout, resolvers, output: defer.Deferred, **kwargs):
        self.resolvers = resolvers
        self.inputs = []
        self.output = output
        self.succeeded = False
        self.errcount = 0

        log_prefix = '[%d]' % kwargs.get('request_id', -1)
        self.logger = PrefixedLogger(logger, log_prefix)

        for res in resolvers:
            d = res.query(query, timeout=timeout, **kwargs)
            d.addCallbacks(
                callback=self.success, callbackArgs=[res],
                errback=self.fail, errbackArgs=[res],
            )
            self.inputs.append(d)

    def success(self, result, resolver):
        self.logger.info(
            'success! %r, succeeded: %s, result: %s',
            resolver, self.succeeded, result)
        if not self.succeeded:
            self.succeeded = True
            self.output.callback(result)
            # cancel other attempts
            for d, res in zip(self.inputs, self.resolvers):
                if res is not resolver:
                    d.cancel()

    def fail(self, failure: Failure, resolver):
        if isinstance(failure.value, defer.CancelledError):
            self.logger.info('canceled! %r', resolver)
        else:
            self.logger.info(
                'fail! %r, succeeded: %s, failure: %s',
                resolver, self.succeeded, failure)
        if not self.succeeded:
            self.errcount += 1
            # all failed
            self.logger.info('all fail! %r', self.resolvers)
            if self.errcount == len(self.inputs):
                self.output.errback(failure)
