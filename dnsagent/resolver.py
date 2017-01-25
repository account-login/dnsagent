from ipaddress import IPv4Address, IPv6Address
from twisted.internet import interfaces, defer
from twisted.names import client, common, error, dns
from zope.interface import implementer
from iprir.ipset import IpSet

from dnsagent import logger


@implementer(interfaces.IResolver)
class ForceTCPResovlver(client.Resolver):
    def queryUDP(self, queries, timeout=None):
        if timeout is None:
            timeout = [10]
        return self.queryTCP(queries, timeout[0])


@implementer(interfaces.IResolver)
class ParallelResolver(common.ResolverBase):
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

    def _lookup(self, name, cls, type, timeout):
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
            return defer.fail(error.DomainError())

        q = dns.Query(name, type, cls)
        dl = [ res.query(q, timeout=timeout) for res in self.resolvers ]
        return make_paralleled_defered(dl)


def make_paralleled_defered(inputs):
    d = defer.Deferred()
    DeferedHub(inputs, d)
    return d


class DeferedHub:
    def __init__(self, inputs, output: defer.Deferred):
        """
        :type inputs: list[defer.Deferred]
        """
        self.inputs = inputs
        self.output = output
        self.successed = False
        self.errcount = 0

        for d in self.inputs:
            d.addCallback(self.success)
            d.addErrback(self.fail)

    def success(self, result):
        logger.info('success! sucessed: %s, result: %s', self.successed, result)
        if not self.successed:
            self.successed = True
            self.output.callback(result)

    def fail(self, failure):
        logger.info('fail! sucessed: %s, failure: %s', self.successed, failure)
        if not self.successed:
            self.errcount += 1
            # all failed
            if self.errcount == len(self.inputs):
                self.output.errback(failure)


@implementer(interfaces.IResolver)
class DualResovlver(common.ResolverBase):
    def __init__(self, cn_resolver, ab_resolver):
        super().__init__()
        self.cn_resolver = cn_resolver
        self.ab_resolver = ab_resolver

    def _lookup(self, name, cls, type, timeout):
        q = dns.Query(name, type, cls)
        output = defer.Deferred()
        DualHandler(
            self.cn_resolver.query(q, timeout=timeout),
            self.ab_resolver.query(q, timeout=timeout),
            output,
        )
        return output


class DualHandler:
    cn4_set = None
    cn6_set = None

    STATUS_FAIL = 'fail'
    STATUS_SUCC = 'succ'
    STATUS_UNK = 'unk'

    def __init__(
            self, cn_defered: defer.Deferred, ab_defered: defer.Deferred,
            output: defer.Deferred,
    ):
        self.output = output
        self.sent = False

        self.cn_status = self.STATUS_UNK
        self.ab_status = self.STATUS_UNK
        self.cn_result = None
        self.ab_result = None

        cn_defered.addCallback(self.cn_success)
        cn_defered.addErrback(self.cn_fail)
        ab_defered.addCallback(self.ab_success)
        ab_defered.addErrback(self.ab_fail)

    @classmethod
    def is_cn_ip(cls, ip) -> bool:
        if isinstance(ip, IPv4Address):
            if cls.cn4_set is None:
                cls.cn4_set = IpSet.by_country('ipv4', 'CN')
            return ip in cls.cn4_set
        elif isinstance(ip, IPv6Address):
            if cls.cn6_set is None:
                cls.cn6_set = IpSet.by_country('ipv6', 'CN')
            return ip in cls.cn6_set
        else:
            assert not 'possible'

    @classmethod
    def may_be_polluted(cls, result):
        answers, authority, additional = result
        if len(answers) == 1:
            rr = answers[0]  # type: dns.RRHeader
            ip = None
            if isinstance(rr.payload, dns.Record_A):
                ip = IPv4Address(rr.payload.dottedQuad())
            elif isinstance(rr.payload, dns.Record_AAAA):
                ip = IPv6Address(rr.payload._address)

            if ip is not None and not cls.is_cn_ip(ip):
                logger.debug('maybe polluted: %s', ip)
                return True

        return False

    def status_updated(self, failure=None):
        #    Cn   Ab
        # [('U', 'U'),	W
        #  ('U', 'S'),	W
        #  ('U', 'F'),	W
        #  ('S', 'U'),	C
        #  ('S', 'S'),	C
        #  ('S', 'F'),	C
        #  ('F', 'U'),	W
        #  ('F', 'S'),	A
        #  ('F', 'F')]	F

        assert not self.sent

        if self.cn_status == self.STATUS_SUCC:
            logger.debug('use cn_result')
            self.output.callback(self.cn_result)
        elif (self.cn_status, self.ab_status) == (self.STATUS_FAIL, self.STATUS_SUCC):
            logger.debug('use ab_result')
            self.output.callback(self.ab_result)
        elif (self.cn_status, self.ab_status) == (self.STATUS_FAIL, self.STATUS_FAIL):
            logger.debug('both cn & ab failed')
            assert failure is not None
            self.output.errback(failure)
        else:
            # wait for the other resolver
            return

        self.sent = True

    def cn_success(self, result):
        if not self.sent:
            self.cn_result = result
            if self.may_be_polluted(result):
                self.cn_status = self.STATUS_FAIL
            else:
                self.cn_status = self.STATUS_SUCC

            self.status_updated()
        else:
            logger.debug('response already sent, drop cn result')

    def ab_success(self, result):
        if not self.sent:
            self.ab_result = result
            self.ab_status = self.STATUS_SUCC

            self.status_updated()
        else:
            logger.debug('response already sent, drop ab result')

    def cn_fail(self, failure):
        logger.debug('cn_failed: %s', failure)
        if not self.sent:
            self.cn_status = self.STATUS_FAIL
            self.status_updated(failure)

    def ab_fail(self, failure):
        logger.debug('ab_failed: %s', failure)
        if not self.sent:
            self.ab_status = self.STATUS_FAIL
            self.status_updated(failure)
