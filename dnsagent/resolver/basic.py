from twisted.names.client import Resolver as OriginResolver

from dnsagent.resolver.base import patch_resolver


__all__ = ('Resolver', 'TCPResovlver')


@patch_resolver
class Resolver(OriginResolver):
    def _lookup(self, name, cls, type, timeout, **kwargs):
        return super()._lookup(name, cls, type, timeout=timeout)

    def __repr__(self):
        ip, port = self.servers[0]
        cls = self.__class__.__name__
        return '<{cls} {ip}:{port}>'.format_map(locals())


class TCPResovlver(Resolver):
    def queryUDP(self, queries, timeout=None):
        if timeout is None:
            timeout = [10]
        return self.queryTCP(queries, timeout[0])
