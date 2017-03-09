import logging
import reprlib
from typing import Union, Set, List, Dict

from twisted.internet import defer
from twisted.internet.protocol import ClientFactory
from twisted.internet import tcp
from twisted.names.client import Resolver as OriginResolver
from twisted.names.dns import DNSDatagramProtocol, DNSProtocol

from dnsagent.resolver.base import patch_resolver
from dnsagent.socks import SocksProxy, UDPRelay, TCPRelayConnector


__all__ = ('ExtendedResolver', 'TCPExtendedResolver')


logger = logging.getLogger(__name__)


@patch_resolver
class BaseResolver(OriginResolver):
    """Resolver with an additional **kwargs in query() and lookupXXX() method"""
    def _lookup(self, name, cls, type, timeout, **kwargs):
        return super()._lookup(name, cls, type, timeout=timeout)

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


class DNSDatagramProtocolOverSocks(DNSDatagramProtocol):
    def __init__(self, controller, reactor=None, relay: UDPRelay = None):
        super().__init__(controller, reactor=reactor)
        self.relay = relay

    def startListening(self):
        self.relay.listenUDP(0, self, maxPacketSize=512)    # ???


def copy_and_clear(container: Union[List, Set, Dict]):
    try:
        return container.copy()
    finally:
        container.clear()


class MyDNSProtocol(DNSProtocol):
    """
    DNS protocol over TCP.
    
    Fixes a bug that self.liveMessages not handled when connection lost.
    """
    def connectionLost(self, reason):
        """
        Notify the controller that this protocol is no longer connected.
        And fail all running TCP queries.
        """
        self.controller.connectionLost(self)

        live_msg = copy_and_clear(self.liveMessages)
        if live_msg:
            logger.error(
                'connection lost, %d unhandled queries: %s',
                len(live_msg), reprlib.repr(live_msg),
            )
        for d, canceller in live_msg.values():
            d.errback(reason)
            canceller.cancel()


class MyDNSClientFactory(ClientFactory):
    protocol = MyDNSProtocol

    def __init__(self, controller: 'ExtendedResolver'):
        self.controller = controller

    def clientConnectionLost(self, connector, reason):
        logger.debug('MyDNSClientFactory.clientConnectionLost: %r', reason)
        # running queries will be cleaned later in MyDNSProtocol.connectionLost

    def clientConnectionFailed(self, connector, reason):
        """
        Fail all pending TCP DNS queries if the TCP connection attempt
        fails.

        @see: L{twisted.internet.protocol.ClientFactory}

        @param connector: Not used.
        @type connector: L{twisted.internet.interfaces.IConnector}

        @param reason: A C{Failure} containing information about the
            cause of the connection failure. This will be passed as the
            argument to C{errback} on every pending TCP query
            C{deferred}.
        @type reason: L{twisted.python.failure.Failure}
        """
        logger.debug('MyDNSClientFactory.clientConnectionFailed: %r', reason)
        # Copy the current pending deferreds then reset the master
        # pending list. This prevents triggering new deferreds which
        # may be added by callback or errback functions on the current
        # deferreds.
        pending = copy_and_clear(self.controller.pending)
        for d, query, timeout in pending:
            d.errback(reason)

    def buildProtocol(self, addr):
        p = self.protocol(self.controller)
        p.factory = self
        return p


class ExtendedResolver(BaseResolver):
    """
    A resolver that supports SOCKS5 proxy.
    
    Some TCP related bugs in OriginResolver is fixed:
        1. TCP connection not closed.
        2. Bad TCP connection reuse logic.
        3. Connection lost not handled.
    """
    def __init__(
            self, resolv=None, servers=None, timeout=(1, 3, 11, 45), reactor=None,
            socks_proxy: SocksProxy = None
    ):
        super().__init__(resolv=resolv, servers=servers, timeout=timeout, reactor=reactor)
        # override attributes in super().__init__()
        self.factory = MyDNSClientFactory(self)
        del self.connections

        self.socks_proxy = socks_proxy
        self.tcp_connector = None   # type: Union[tcp.Connector, TCPRelayConnector]
        self.tcp_protocol = None    # type: MyDNSProtocol
        self.tcp_waiting = set()    # type: Set[defer.Deferred]

    def _got_udp_relay(self, relay: UDPRelay, query_d, *query_args):
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
            relay_d.addCallback(self._got_udp_relay, d, *args)
            relay_d.addErrback(d.errback)
            return d
        else:
            return super()._query(*args)

    def connectionMade(self, protocol: MyDNSProtocol):
        """
        Run pending TCP queries and add resulting deferreds to self.tcp_waiting.
        Called from MyDNSProtocol.
        """
        assert self.tcp_protocol is None
        self.tcp_protocol = protocol

        pending = copy_and_clear(self.pending)
        logger.debug('resolve %d pending queries: %s', len(pending), reprlib.repr(pending))
        for d, queries, timeout in pending:
            self.queryTCP(queries, timeout=timeout).chainDeferred(d)
            self.tcp_waiting.add(d)

    def connectionLost(self, protocol: MyDNSProtocol):
        """
        TCP connection lost, remove disconnected protocol. 
        Called from MyDNSProtocol.
        """
        assert protocol is self.tcp_protocol
        self.tcp_protocol = None

    def queryTCP(self, queries, timeout=10):
        """
        Make a number of DNS queries via TCP.

        @type queries: Any non-zero number of C{dns.Query} instances
        @param queries: The queries to make.

        @type timeout: C{int}
        @param timeout: The number of seconds after which to fail.

        @rtype: C{Deferred}
        """
        if not self.tcp_protocol:
            address = self.pickServer()
            if address is None:
                return defer.fail(IOError("No domain name servers available"))
            host, port = address

            # set up TCP connection
            if self.tcp_connector is None:
                if self.socks_proxy:
                    self.tcp_connector = self.socks_proxy.connectTCP(host, port, self.factory)
                else:
                    self.tcp_connector = self._reactor.connectTCP(host, port, self.factory)
            # reconnecting
            if self.tcp_connector.state == 'disconnected':  # XXX: private attribute
                self.tcp_connector.connect()

            d = defer.Deferred()
            self.pending.append((d, queries, timeout))
            return d.addBoth(self._tcp_query_finished, d)
        else:
            # reuse existing TCP connection
            assert self.tcp_connector.state == 'connected'
            d = self.tcp_protocol.query(queries, timeout=timeout)
            self.tcp_waiting.add(d)
            return d

    def _tcp_query_finished(self, ignore, d: defer.Deferred):
        """
        Remove finished TCP query from self.tcp_waiting, 
        and close TCP connection if no waiting TCP queries.
        """
        assert not self.pending
        self.tcp_waiting.discard(d)
        if not self.tcp_waiting:
            logger.debug('no waiting queries, disconnect TCP connection.')
            self.tcp_connector.disconnect()     # may be already disconnected
        return ignore


class TCPExtendedResolver(ExtendedResolver):
    # TODO: merge this into ExtendedResolver
    def queryUDP(self, queries, timeout=None):
        return self.queryTCP(queries)

    def _repr_short_(self):
        return 'tcp://' + super()._repr_short_()
