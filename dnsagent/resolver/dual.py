from ipaddress import IPv4Address, IPv6Address

from iprir.ipset import IpSet
from twisted.internet import defer
from twisted.names import dns

from dnsagent import logger
from dnsagent.resolver.base import MyResolverBase
from dnsagent.utils import PrefixedLogger, rrheader_to_ip


__all__ = ('DualResovlver',)


class DualResovlver(MyResolverBase):
    def __init__(self, cn_resolver, ab_resolver):
        super().__init__()
        self.cn_resolver = cn_resolver
        self.ab_resolver = ab_resolver

    def _lookup(self, name, cls, type_, timeout, **kwargs):
        q = dns.Query(name, type_, cls)
        output = defer.Deferred()
        DualHandler(
            self.cn_resolver.query(q, timeout=timeout, **kwargs),
            self.ab_resolver.query(q, timeout=timeout, **kwargs),
            output, **kwargs
        )
        return output

    def __repr__(self):
        return '<Dual cn={} ab={}>'.format(self.cn_resolver, self.ab_resolver)


class DualHandler:
    cn4_set = None
    cn6_set = None

    STATUS_FAIL = 'fail'
    STATUS_SUCC = 'succ'
    STATUS_UNK = 'unk'

    def __init__(
            self, cn_defered: defer.Deferred, ab_defered: defer.Deferred,
            output: defer.Deferred, **kwargs
    ):
        self.output = output
        log_prefix = '[%d]' % kwargs.get('request_id', -1)
        self.logger = PrefixedLogger(logger, log_prefix)
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

    def may_be_polluted(self, result):
        answers, authority, additional = result
        if len(answers) == 1:
            rr = answers[0]  # type: dns.RRHeader
            ip = rrheader_to_ip(rr)
            if ip is not None and not self.is_cn_ip(ip):
                self.logger.debug('maybe polluted: %s', ip)
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
            self.logger.debug('use cn_result')
            self.output.callback(self.cn_result)
        elif (self.cn_status, self.ab_status) == (self.STATUS_FAIL, self.STATUS_SUCC):
            self.logger.debug('use ab_result')
            self.output.callback(self.ab_result)
        elif (self.cn_status, self.ab_status) == (self.STATUS_FAIL, self.STATUS_FAIL):
            self.logger.debug('both cn & ab failed')
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
            self.logger.debug('response already sent, drop cn result')

    def ab_success(self, result):
        if not self.sent:
            self.ab_result = result
            self.ab_status = self.STATUS_SUCC

            self.status_updated()
        else:
            self.logger.debug('response already sent, drop ab result')

    def cn_fail(self, failure):
        self.logger.debug('cn_failed: %s', failure)
        if not self.sent:
            self.cn_status = self.STATUS_FAIL
            self.status_updated(failure)

    def ab_fail(self, failure):
        self.logger.debug('ab_failed: %s', failure)
        if not self.sent:
            self.ab_status = self.STATUS_FAIL
            self.status_updated(failure)
