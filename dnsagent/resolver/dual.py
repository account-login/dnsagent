from typing import Mapping, Union, Sequence

from twisted.names.error import ResolverError
from twisted.python.failure import Failure

from dnsagent.resolver.cn import CnResolver
from dnsagent.resolver.parallel import PoliciedParallelResolver, BaseParalledResolverPolicy


__all__ = ('DualResolver',)


class PolicyError(ResolverError):
    pass


class NoSuchRule(PolicyError):
    pass


class SuccessFailStatePolicy(BaseParalledResolverPolicy):
    SUCC = 'S'
    FAIL = 'F'
    WAIT = 'W'

    def __init__(self, rules: Mapping[Sequence[str], Union[str, int]]):
        super().__init__()
        self.rules = rules

    def _convert(self, result):
        if result is None:
            return self.WAIT
        elif isinstance(result, Failure):
            return self.FAIL
        else:
            return self.SUCC

    def for_results(self, results: Sequence):
        states = tuple(self._convert(x) for x in results)
        try:
            action = self.rules[states]
        except KeyError:
            raise NoSuchRule(states)

        if action == self.FAIL:
            raise PolicyError
        elif action == self.WAIT:
            return None
        else:
            assert isinstance(action, int)
            return action


_cn_ab_policy = SuccessFailStatePolicy({
    # Cn   Ab
    ('W', 'W'): 'W',
    ('W', 'S'): 'W',
    ('W', 'F'): 'W',
    ('S', 'W'): 0,
    ('S', 'S'): 0,
    ('S', 'F'): 0,
    ('F', 'W'): 'W',
    ('F', 'S'): 1,
    ('F', 'F'): 'F',
})


class DualResolver(PoliciedParallelResolver):
    def __init__(self, cn_resolver, ab_resolver, policy=_cn_ab_policy):
        resolvers = [ CnResolver(cn_resolver), ab_resolver ]
        super().__init__(resolvers, policy)
