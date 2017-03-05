from ipaddress import IPv4Address, IPv6Address
from typing import Union

from iprir.ipset import IpSet
from twisted.names import dns

from dnsagent.resolver import MyResolverBase
from dnsagent.utils import rrheader_to_ip, repr_short


__all__ = ('CnResolver',)


class MayBePolluted(Exception):
    pass


class CnResolver(MyResolverBase):
    cn4_set = None
    cn6_set = None

    def __init__(self, upstream):
        super().__init__()
        self.upstream = upstream

    def _lookup(self, name, cls, type, timeout, **kwargs):
        d = self.upstream._lookup(name, cls, type, timeout=timeout, **kwargs)
        d.addCallback(self.drop_potential_polluted)
        return d

    @classmethod
    def is_cn_ip(cls, ip: Union[IPv4Address, IPv6Address]) -> bool:
        if isinstance(ip, IPv4Address):
            if cls.cn4_set is None:
                cls.cn4_set = IpSet.by_country('ipv4', 'CN')
            return ip in cls.cn4_set
        else:
            if cls.cn6_set is None:
                cls.cn6_set = IpSet.by_country('ipv6', 'CN')
            return ip in cls.cn6_set

    def drop_potential_polluted(self, result):
        """Result that contains exactly 1 foreign ip is considered potentially polluted."""
        answers, authority, additional = result
        if len(answers) == 1:
            rr = answers[0]  # type: dns.RRHeader
            ip = rrheader_to_ip(rr)
            if ip and not self.is_cn_ip(ip):
                raise MayBePolluted(ip)
        return result

    def __repr__(self):
        cls_name = type(self).__name__
        sub = repr_short(self.upstream)
        return '<{cls_name} {sub}>'.format_map(locals())
