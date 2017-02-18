from twisted.internet import defer
from twisted.names.client import Resolver as OriginResolver
from twisted.names.dns import DNSDatagramProtocol
from typing import Tuple

from dnsagent.resolver.base import patch_resolver
from dnsagent.socks import get_udp_relay, UDPRelay


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


class DNSDatagramProtocolOverSocks(DNSDatagramProtocol):
    def __init__(self, controller, reactor=None, relay: UDPRelay = None):
        super().__init__(controller, reactor=reactor)
        self.relay = relay

    def startListening(self):
        self.relay.listenUDP(0, self, maxPacketSize=512)    # ???


class ResolverOverSocks(Resolver):
    def __init__(
            self, resolv=None, servers=None, timeout=(1, 3, 11, 45), reactor=None,
            socks_proxy_addr: Tuple[str, int] = None
    ):
        super().__init__(resolv=resolv, servers=servers, timeout=timeout, reactor=reactor)
        self.socks_proxy_addr = socks_proxy_addr

    def _got_relay(self, relay: UDPRelay, query_d, *query_args):
        def stop_relay(ignore):
            relay.stop()
            return ignore

        proto = DNSDatagramProtocolOverSocks(self, reactor=self._reactor, relay=relay)
        relay.listenUDP(0, proto, maxPacketSize=512)

        proto.query(*query_args).chainDeferred(query_d)
        query_d.addBoth(stop_relay)

    def _query(self, *args):
        if self.socks_proxy_addr is not None:
            d = defer.Deferred()
            relay_d = get_udp_relay(self.socks_proxy_addr, reactor=self._reactor)
            relay_d.addCallback(self._got_relay, d, *args)
            relay_d.addErrback(d.errback)
            return d
        else:
            return super()._query(*args)
