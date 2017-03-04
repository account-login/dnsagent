from twisted.internet import defer
from twisted.names.client import Resolver as OriginResolver
from twisted.names.dns import DNSDatagramProtocol

from dnsagent.resolver.base import patch_resolver
from dnsagent.socks import SocksProxy, UDPRelay


__all__ = ('ExtendedResolver', 'TCPExtendedResolver')


@patch_resolver
class BaseResolver(OriginResolver):
    """Resolver with an additional **kwargs in query() and lookupXXX() method"""
    def _lookup(self, name, cls, type, timeout, **kwargs):
        return super()._lookup(name, cls, type, timeout=timeout)

    def __repr__(self):
        ip, port = self.servers[0]
        cls = self.__class__.__name__
        return '<{cls} {ip}:{port}>'.format_map(locals())


class DNSDatagramProtocolOverSocks(DNSDatagramProtocol):
    def __init__(self, controller, reactor=None, relay: UDPRelay = None):
        super().__init__(controller, reactor=reactor)
        self.relay = relay

    def startListening(self):
        self.relay.listenUDP(0, self, maxPacketSize=512)    # ???


class ExtendedResolver(BaseResolver):
    def __init__(
            self, resolv=None, servers=None, timeout=(1, 3, 11, 45), reactor=None,
            socks_proxy: SocksProxy = None
    ):
        super().__init__(resolv=resolv, servers=servers, timeout=timeout, reactor=reactor)
        self.socks_proxy = socks_proxy

    def _got_relay(self, relay: UDPRelay, query_d, *query_args):
        def stop_relay(ignore):
            relay.stop()
            return ignore

        proto = DNSDatagramProtocolOverSocks(self, reactor=self._reactor, relay=relay)
        relay.listenUDP(0, proto, maxPacketSize=512)

        proto.query(*query_args).chainDeferred(query_d)
        query_d.addBoth(stop_relay)

    def _query(self, *args):
        if self.socks_proxy is not None:
            d = defer.Deferred()
            relay_d = self.socks_proxy.get_udp_relay()
            relay_d.addCallback(self._got_relay, d, *args)
            relay_d.addErrback(d.errback)
            return d
        else:
            return super()._query(*args)

    def queryTCP(self, queries, timeout=10):
        """
        Make a number of DNS queries via TCP.

        @type queries: Any non-zero number of C{dns.Query} instances
        @param queries: The queries to make.

        @type timeout: C{int}
        @param timeout: The number of seconds after which to fail.

        @rtype: C{Deferred}
        """
        if not len(self.connections):
            address = self.pickServer()
            if address is None:
                return defer.fail(IOError("No domain name servers available"))
            host, port = address

            d = defer.Deferred()
            if self.socks_proxy:
                def disconnect(ignore):
                    connector.disconnect()
                    return ignore

                connector = self.socks_proxy.connectTCP(host, port, self.factory)
                d.addBoth(disconnect)
            else:
                self._reactor.connectTCP(host, port, self.factory)  # XXX: how is that disconnected?
            self.pending.append((d, queries, timeout))
            return d
        else:
            return self.connections[0].query(queries, timeout)


class TCPExtendedResolver(ExtendedResolver):
    def queryUDP(self, queries, timeout=None):
        return self.queryTCP(queries)
