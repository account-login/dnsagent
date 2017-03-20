from twisted.internet import defer, task
from twisted.internet.error import ConnectionDone
from twisted.internet.protocol import DatagramProtocol
from twisted.names import dns
from twisted.python.failure import Failure
from twisted.trial import unittest

from dnsagent.app import App
from dnsagent.resolver.bugfix import BugFixResolver, BugFixDNSDatagramProtocol
from dnsagent.resolver.extended import (
    ExtendedResolver, TCPExtendedResolver, ExtendedDNSDatagramProtocol,
)
from dnsagent.server import BugFixDNSServerFactory
from dnsagent.tests import BaseTestResolver, FakeResolver, iplist, FakeTransport
from dnsagent.utils import get_reactor, chain_deferred_call


class LoseConnectionDNSServerFactory(BugFixDNSServerFactory):
    countdown = 100

    def sendReply(self, protocol, message, address):
        self.countdown -= 1
        if self.countdown <= 0:
            protocol.transport.loseConnection()
        else:
            super().sendReply(protocol, message, address)


class TCPOnlyBugFixResolver(BugFixResolver):
    def queryUDP(self, queries, timeout=None):
        return self.queryTCP(queries)


class TestTCPBugFixResolver(BaseTestResolver):
    resolver_cls = TCPOnlyBugFixResolver

    server_addr = ('127.0.0.53', 5353)

    fake_resolver = FakeResolver()
    fake_resolver.set_answer('asdf', '1.2.3.4')
    fake_resolver.set_answer('fdsa', '4.3.2.1')
    fake_resolver.delay = 0.01

    def setUp(self):
        super().setUp()

        self.server = LoseConnectionDNSServerFactory(resolver=self.fake_resolver)
        self.app = App()
        self.app.start((self.server, [self.server_addr]))

        self.resolver = self.resolver_cls(servers=[self.server_addr])
        self.reactor = get_reactor()

    def tearDown(self):
        def super_super_down():
            return self.app.stop()

        return chain_deferred_call([
            super().tearDown,
            super_super_down,
        ])

    def test_success(self):
        def check_waiting_state():
            assert not self.resolver.pending
            assert len(self.resolver.tcp_waiting) == 2

        def check_finished_state(ignore):
            assert not self.resolver.pending
            assert not self.resolver.tcp_waiting
            self.reactor.callLater(0.002,
                lambda: defer.maybeDeferred(check_disconnected)
                    .chainDeferred(final_d))

        def check_disconnected():
            assert not self.resolver.tcp_protocol

        final_d = defer.Deferred()
        query_d = defer.DeferredList([
            self.check_a('asdf', iplist('1.2.3.4')),
            self.check_a('fdsa', iplist('4.3.2.1')),
        ], fireOnOneErrback=True)
        query_d.addCallback(check_finished_state)
        query_d.addErrback(final_d.errback)

        self.reactor.callLater(0.005,
            lambda: defer.maybeDeferred(check_waiting_state)
                .addErrback(final_d.errback))

        return final_d

    def test_connection_lost(self):
        self.server.countdown = 2

        self.check_a('asdf', iplist('1.2.3.4'))
        self.check_a('fdsa', fail=ConnectionDone)

    def test_connection_failed_reconnect(self):
        class MyException(Exception):
            pass

        self.check_a('asdf', fail=MyException)
        self.resolver.factory.clientConnectionFailed(None, Failure(MyException('asdf')))

        # reconnect
        self.check_a('fdsa', iplist('4.3.2.1'))


class TestTCPBugFixResolverWithExtended(TestTCPBugFixResolver):
    resolver_cls = TCPExtendedResolver


def swallow(ignore):
    pass


class TestDNSDatagramProtocolResendsExpiration(unittest.TestCase):
    protocol_cls = BugFixDNSDatagramProtocol

    discard_host = '127.0.3.3'
    discard_port = 3456
    discard_addr = (discard_host, discard_port)

    query = dns.Query(b'asdf', dns.A, dns.IN)

    def setUp(self):
        self.clock = task.Clock()
        self.protocol = self.protocol_cls(FakeResolver(), reactor=self.clock)
        self.protocol.makeConnection(FakeTransport())

        self.discard = get_reactor().listenUDP(
            self.discard_port, DatagramProtocol(), interface=self.discard_host,
        )

    def tearDown(self):
        assert not self.clock.calls
        return defer.maybeDeferred(self.discard.stopListening)

    def make_query(self):
        d = self.protocol.query(self.discard_addr, [self.query], timeout=5, id=123)
        return d.addErrback(swallow)

    def test_expire(self):
        self.make_query()
        assert 123 in self.protocol.liveMessages
        assert 123 in self.protocol.resends

        self.clock.advance(6)
        assert 123 not in self.protocol.liveMessages
        assert 123 in self.protocol.resends

        self.clock.advance(60)
        assert 123 not in self.protocol.resends

        self.protocol.doStop()

    def test_protocol_stop(self):
        self.make_query()

        self.clock.advance(6)
        self.protocol.doStop()
        assert not self.protocol.resends

    def test_reissue(self):
        self.make_query()
        self.clock.advance(6)
        self.make_query()
        self.protocol.doStop()
        assert not self.clock.calls


class TestDNSDatagramProtocolResendsExpirationWithExtended(
    TestDNSDatagramProtocolResendsExpiration
):
    protocol_cls = ExtendedDNSDatagramProtocol


class DropRequestDNSServerFactory(BugFixDNSServerFactory):
    drops = 1

    def sendReply(self, protocol, message, address):
        if self.drops <= 0:
            super().sendReply(protocol, message, address)
        else:
            self.drops -= 1


class TestReissue(unittest.TestCase):
    resolver_cls = BugFixResolver

    server_addr = ('127.0.0.54', 5454)
    fake_resolver = FakeResolver()
    fake_resolver.set_answer('asdf', '1.2.3.4')
    query = dns.Query(b'asdf', dns.A, dns.IN)

    def setUp(self):
        server = DropRequestDNSServerFactory(resolver=self.fake_resolver)
        self.app = App()
        self.app.start((server, [self.server_addr]))

        self.resolver = self.resolver_cls(servers=[self.server_addr])

    def tearDown(self):
        return self.app.stop()

    def test_timeout(self):
        def check_failure(result: Failure):
            assert isinstance(result, Failure)
            result.trap(defer.TimeoutError)

        d = self.resolver.query(self.query, timeout=[0.1])
        return d.addBoth(check_failure)

    def test_reissue(self):
        return self.resolver.query(self.query, timeout=[0.01, 0.02])


class TestReissueWithExtended(TestReissue):
    resolver_cls = ExtendedResolver


# TODO: TestUDPBugFixResolver
# TODO: test dnsagent.resolver.bugfix.BugFixDNSProtocol#dataReceived


del BaseTestResolver
