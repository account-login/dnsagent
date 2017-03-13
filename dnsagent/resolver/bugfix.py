import reprlib
import struct
from typing import Union, List, Set, Dict, Optional

from twisted.internet import defer, tcp
from twisted.internet.protocol import ClientFactory
from twisted.names import dns
from twisted.names.dns import DNSProtocol, Message, DNSDatagramProtocol, randomSource
from twisted.python.failure import Failure

from dnsagent.resolver.base import BaseResolver
from dnsagent.socks import TCPRelayConnector
from dnsagent import logger


def copy_and_clear(container: Union[List, Set, Dict]):
    try:
        return container.copy()
    finally:
        container.clear()


def clean_dns_protocol(protocol: dns.DNSMixin, reason: Failure):
    live_msg = copy_and_clear(protocol.liveMessages)
    if live_msg:
        logger.error(
            '%r stopped, %d unhandled queries: %s',
            protocol, len(live_msg), reprlib.repr(live_msg),
        )
    for d, canceller in live_msg.values():
        d.errback(reason)
        canceller.cancel()


class BugFixDNSProtocol(DNSProtocol):
    """
    DNS protocol over TCP.
    
    Fixed bugs:
        1. self.liveMessages not handled when connection lost.
        2. dataReceived() fails on len(self.buffer) < 2
    """

    message_cls = Message

    def connectionLost(self, reason):
        """
        Notify the controller that this protocol is no longer connected.
        And fail all running TCP queries.
        """
        self.controller.connectionLost(self)
        clean_dns_protocol(self, reason)

    def dataReceived(self, data):
        """Bug fixed"""
        self.buffer += data

        while self.buffer:
            if self.length is None and len(self.buffer) >= 2:
                self.length = struct.unpack('!H', self.buffer[:2])[0]
                self.buffer = self.buffer[2:]

            # FIXED: self.length may be None
            if self.length is not None and len(self.buffer) >= self.length:
                msg = self.message_cls()
                msg.fromStr(self.buffer[:self.length])

                if msg.id in self.liveMessages:
                    d, canceller = self.liveMessages.pop(msg.id)
                    canceller.cancel()
                    d.callback(msg)
                else:
                    self.controller.messageReceived(msg, self)  # for DNSServerFactory

                self.buffer = self.buffer[self.length:]
                self.length = None
            else:
                break


class ProtocolStopped(Exception):
    pass


class BugFixDNSDatagramProtocol(DNSDatagramProtocol):
    """
    Fixed bugs:
        1. self.liveMessages not handled when stopping protocol
        2. self.resends not expired
    """

    message_cls = Message

    def stopProtocol(self):
        clean_dns_protocol(self, Failure(ProtocolStopped()))
        for d in copy_and_clear(self.resends).values():
            d.cancel()
        self.transport = None

    def pickID(self) -> int:
        while True:
            msg_id = randomSource()
            if msg_id not in self.liveMessages and msg_id not in self.resends:
                return msg_id

    def check_msg_id(self, msg_id: Optional[int], timeout: float):
        """
        Checks that weither this is a re-issued query, 
        return a new id if not, or remember msg_id in self.resends
        """
        if msg_id is None:
            msg_id = self.pickID()
        else:
            # query is a re-issue
            # FIXED: self.resends not expired
            if msg_id in self.resends:
                self.resends.pop(msg_id).cancel()
            resend_ttl = max(timeout * 2, 10)   # XXX: magic numbers
            self.resends[msg_id] = self._reactor.callLater(
                resend_ttl, self.removeResend, msg_id,
            )

        return msg_id

    def query(self, address, queries, timeout=10, id=None):
        assert self.transport

        def write_message(m):
            self.writeMessage(m, address)

        msg_id = self.check_msg_id(id, timeout)
        return self._query(queries, timeout, msg_id, write_message)


class BugFixDNSClientFactory(ClientFactory):
    protocol = BugFixDNSProtocol

    def __init__(self, controller: 'BugFixResolver'):
        self.controller = controller

    def clientConnectionLost(self, connector, reason):
        logger.debug('BugFixDNSClientFactory.clientConnectionLost: %r', reason)
        # running queries will be cleaned later in BugFixDNSProtocol.connectionLost

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
        logger.debug('BugFixDNSClientFactory.clientConnectionFailed: %r', reason)
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


class BugFixResolver(BaseResolver):
    """
    Some TCP related bugs in OriginResolver are fixed:
        1. TCP connection not closed.
        2. Bad TCP connection reuse logic.
        3. Connection lost not handled.
    """

    client_factory_cls = BugFixDNSClientFactory

    def __init__(self, resolv=None, servers=None, timeout=(1, 3, 11, 45), reactor=None):
        super().__init__(resolv=resolv, servers=servers, timeout=timeout, reactor=reactor)
        # override attributes in super().__init__()
        self.factory = self.client_factory_cls(self)
        del self.connections

        self.tcp_connector = None   # type: Union[tcp.Connector, TCPRelayConnector]
        self.tcp_protocol = None    # type: BugFixDNSProtocol
        self.tcp_waiting = set()    # type: Set[defer.Deferred]

    def connectionMade(self, protocol: BugFixDNSProtocol):
        """
        Run pending TCP queries and add resulting deferreds to self.tcp_waiting.
        Called from BugFixDNSProtocol.
        """
        assert self.tcp_protocol is None
        self.tcp_protocol = protocol

        pending = copy_and_clear(self.pending)
        logger.debug('resolve %d pending queries: %s', len(pending), reprlib.repr(pending))
        for d, queries, timeout in pending:
            requery_d = self.queryTCP(queries, timeout=timeout)
            requery_d.chainDeferred(d)
            # requery_d is duplicated
            # since deferreds from self.pending is moving to self.tcp_waiting.
            self.tcp_waiting.discard(requery_d)
            self.tcp_waiting.add(d)

    def connectionLost(self, protocol: BugFixDNSProtocol):
        """
        TCP connection lost, remove disconnected protocol. 
        Called from BugFixDNSProtocol.
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
                self.tcp_connector = self.connect_tcp(host, port, self.factory)
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

    def connect_tcp(self, host: str, port: int, factory: ClientFactory):
        return self._reactor.connectTCP(host, port, factory)

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
