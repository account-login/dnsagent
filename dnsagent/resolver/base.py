from twisted.internet import defer
from twisted.names import dns
from twisted.names.client import Resolver as OriginResolver
from twisted.names.common import ResolverBase as OriginBaseResolver
from twisted.python.failure import Failure

from dnsagent import logger
from dnsagent.utils import repr_short


__all__ = ('BaseResolver', 'patch_resolver', 'PatchedOriginResolver')


class BaseResolver(OriginBaseResolver):
    """
    Add kwargs to query() method, so additional information
    can by passed to resolver and sub-resovler.
    """
    def query(self, query, timeout=None, **kwargs):
        request_id = kwargs.get('request_id', -1)
        logger.info('[%d](%s).query(%r)', request_id, repr_short(self), query)
        try:
            method = self.typeToMethod[query.type]
        except KeyError:
            return defer.fail(
                Failure(NotImplementedError(self.__class__ + " " + str(query.type))))
        else:
            return defer.maybeDeferred(method, query.name.name, timeout, **kwargs)

    def _lookup(self, name, cls, type_, timeout, **kwargs):
        return defer.fail(NotImplementedError("%s._lookup" % (type(self).__name__),))

    def lookupAddress(self, name, timeout=None, **kwargs):
        return self._lookup(name, dns.IN, dns.A, timeout=timeout, **kwargs)

    def lookupIPV6Address(self, name, timeout=None, **kwargs):
        return self._lookup(name, dns.IN, dns.AAAA, timeout=timeout, **kwargs)

    def lookupAddress6(self, name, timeout=None, **kwargs):
        return self._lookup(name, dns.IN, dns.A6, timeout=timeout, **kwargs)

    def lookupMailExchange(self, name, timeout=None, **kwargs):
        return self._lookup(name, dns.IN, dns.MX, timeout=timeout, **kwargs)

    def lookupNameservers(self, name, timeout=None, **kwargs):
        return self._lookup(name, dns.IN, dns.NS, timeout=timeout, **kwargs)

    def lookupCanonicalName(self, name, timeout=None, **kwargs):
        return self._lookup(name, dns.IN, dns.CNAME, timeout=timeout, **kwargs)

    def lookupMailBox(self, name, timeout=None, **kwargs):
        return self._lookup(name, dns.IN, dns.MB, timeout=timeout, **kwargs)

    def lookupMailGroup(self, name, timeout=None, **kwargs):
        return self._lookup(name, dns.IN, dns.MG, timeout=timeout, **kwargs)

    def lookupMailRename(self, name, timeout=None, **kwargs):
        return self._lookup(name, dns.IN, dns.MR, timeout=timeout, **kwargs)

    def lookupPointer(self, name, timeout=None, **kwargs):
        return self._lookup(name, dns.IN, dns.PTR, timeout=timeout, **kwargs)

    def lookupAuthority(self, name, timeout=None, **kwargs):
        return self._lookup(name, dns.IN, dns.SOA, timeout=timeout, **kwargs)

    def lookupNull(self, name, timeout=None, **kwargs):
        return self._lookup(name, dns.IN, dns.NULL, timeout=timeout, **kwargs)

    def lookupWellKnownServices(self, name, timeout=None, **kwargs):
        return self._lookup(name, dns.IN, dns.WKS, timeout=timeout, **kwargs)

    def lookupService(self, name, timeout=None, **kwargs):
        return self._lookup(name, dns.IN, dns.SRV, timeout=timeout, **kwargs)

    def lookupHostInfo(self, name, timeout=None, **kwargs):
        return self._lookup(name, dns.IN, dns.HINFO, timeout=timeout, **kwargs)

    def lookupMailboxInfo(self, name, timeout=None, **kwargs):
        return self._lookup(name, dns.IN, dns.MINFO, timeout=timeout, **kwargs)

    def lookupText(self, name, timeout=None, **kwargs):
        return self._lookup(name, dns.IN, dns.TXT, timeout=timeout, **kwargs)

    def lookupSenderPolicy(self, name, timeout=None, **kwargs):
        return self._lookup(name, dns.IN, dns.SPF, timeout=timeout, **kwargs)

    def lookupResponsibility(self, name, timeout=None, **kwargs):
        return self._lookup(name, dns.IN, dns.RP, timeout=timeout, **kwargs)

    def lookupAFSDatabase(self, name, timeout=None, **kwargs):
        return self._lookup(name, dns.IN, dns.AFSDB, timeout=timeout, **kwargs)

    def lookupZone(self, name, timeout=None, **kwargs):
        return self._lookup(name, dns.IN, dns.AXFR, timeout=timeout, **kwargs)

    def lookupNamingAuthorityPointer(self, name, timeout=None, **kwargs):
        return self._lookup(name, dns.IN, dns.NAPTR, timeout=timeout, **kwargs)

    def lookupAllRecords(self, name, timeout=None, **kwargs):
        return self._lookup(name, dns.IN, dns.ALL_RECORDS, timeout=timeout, **kwargs)


def patch_resolver(cls):
    for k, v in BaseResolver.__dict__.items():
        if k.startswith('lookup') or k in ('query', '_lookup'):
            if k not in cls.__dict__:
                setattr(cls, k, v)

    return cls


@patch_resolver
class PatchedOriginResolver(OriginResolver):
    """Original twisted resolver with an additional **kwargs in query() and lookupXXX() method"""
    def _lookup(self, name, cls, type_, timeout, **kwargs):
        return super()._lookup(name, cls, type_, timeout=timeout)

    def __repr__(self):
        cls = self.__class__.__name__
        addr = self._repr_short_()
        return '<{cls} {addr}>'.format_map(locals())

    def _repr_short_(self):
        ip, port = self.servers[0]
        if port != 53:
            return '{ip}:{port}'.format_map(locals())
        else:
            return ip
