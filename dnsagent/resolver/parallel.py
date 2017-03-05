from typing import Sequence

from twisted.internet import defer
from twisted.names import dns
from twisted.names.error import ResolverError
from twisted.python.failure import Failure

from dnsagent import logger
from dnsagent.resolver.base import MyResolverBase
from dnsagent.utils import PrefixedLogger, get_reactor


__all__ = ('ParallelResolver', 'BaseParalledResolverPolicy')


class BaseParalledResolverPolicy:
    def for_results(self, results: Sequence):
        """
        :param results: list of query result or L{Failure} or None
        :return: 
            Return None to wait for other results, 
            or return index number to pick up a result,
            or raise an exception to indicate a failure.
        """
        raise NotImplementedError


class FirstOnePolicy(BaseParalledResolverPolicy):
    def for_results(self, results: Sequence):
        for i, res in enumerate(results):
            if res and not isinstance(res, Failure):
                return i
        return None


class ParalledQueryHandler:
    def __init__(
            self, para_resolver: 'PoliciedParallelResolver', result_d: defer.Deferred,
            query: dns.Query, timeout, reactor=None, **kwargs
    ):
        self.para_resolver = para_resolver
        self.finished = False
        self.result_d = result_d
        self.results = [None] * len(para_resolver.resolvers)
        self.query_ds = [
            res.query(query, timeout=timeout, **kwargs).addBoth(self.update_results, i)
            for i, res in enumerate(para_resolver.resolvers)
        ]

        request_id = kwargs.get('request_id', -1)
        self.logger = PrefixedLogger(logger, '[%d]%s: ' % (request_id, self.__class__.__name__))

        self.reactor = get_reactor(reactor)

    def cancel_all(self):
        for d in self.query_ds:
            d.cancel()

    def resolve_success(self, index: int):
        self.logger.info('pick %r', self.para_resolver.resolvers[index])
        self.finished = True
        try:
            self.result_d.callback(self.results[index])
        finally:
            self.reactor.callLater(0, self.cancel_all)

    def resolve_fail(self, err=None):
        self.logger.error('failed: %r', err)
        self.finished = True
        try:
            self.result_d.errback(err or Failure())
        finally:
            self.reactor.callLater(0, self.cancel_all)

    def update_results(self, result, index: int):
        verb = {True: 'failed', False: 'got'}[isinstance(result, Failure)]
        self.logger.debug('%r %s: %r', self.para_resolver.resolvers[index], verb, result)
        self.results[index] = result
        if self.finished:
            return

        try:
            picked = self.para_resolver.policy.for_results(self.results)
        except Exception:
            self.resolve_fail()
            return

        if picked is not None:
            assert isinstance(picked, int)
            self.resolve_success(picked)
            return

        # all resolver finished
        if all(res is not None for res in self.results):
            self.resolve_fail(Failure(ResolverError('no result selected')))


class PoliciedParallelResolver(MyResolverBase):
    def __init__(self, resolvers: Sequence, policy: BaseParalledResolverPolicy):
        super().__init__()
        assert len(resolvers) > 0
        self.resolvers = resolvers
        self.policy = policy

    def _lookup(self, name, cls, type_, timeout, **kwargs):
        query = dns.Query(name, type_, cls)
        d = defer.Deferred()
        ParalledQueryHandler(self, d, query, timeout=timeout, **kwargs)
        return d


class ParallelResolver(PoliciedParallelResolver):
    def __init__(self, resolvers: Sequence, policy=FirstOnePolicy()):
        super().__init__(resolvers, policy)

    def __repr__(self):
        sub = '|'.join(map(repr, self.resolvers))
        return '<Parallel {}>'.format(sub)
