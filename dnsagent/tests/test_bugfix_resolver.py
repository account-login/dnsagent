from twisted.internet import defer, task
from twisted.internet.error import ConnectionDone
from twisted.internet.protocol import DatagramProtocol
from twisted.names import dns
from twisted.python.failure import Failure
from twisted.trial import unittest

from dnsagent.app import App
from dnsagent.resolver.bugfix import BugFixResolver, BugFixDNSDatagramProtocol
from dnsagent.server import MyDNSServerFactory
from dnsagent.tests import BaseTestResolver, FakeResolver, iplist, FakeTransport
from dnsagent.utils import get_reactor


class LoseConnectionDNSServerFactory(MyDNSServerFactory):
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
    server_addr = ('127.0.0.53', 5353)

    def setUp(self):
        super().setUp()
        self.fake_resolver = FakeResolver()
        self.fake_resolver.set_answer('asdf', '1.2.3.4')
        self.fake_resolver.set_answer('fdsa', '4.3.2.1')
        self.fake_resolver.delay = 0.01

        self.server = LoseConnectionDNSServerFactory(resolver=self.fake_resolver)
        self.app = App()
        self.app.start((self.server, [self.server_addr]))

        self.resolver = TCPOnlyBugFixResolver(servers=[self.server_addr])
        self.reactor = get_reactor()

    def tearDown(self):
        def super_down(ignore):
            self.app.stop().chainDeferred(d)

        d = defer.Deferred()
        super().tearDown().addCallbacks(super_down, d.errback)
        return d

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


def swallow(ignore):
    pass


class TestDNSDatagramProtocolResendsExpiration(unittest.TestCase):
    discard_host = '127.0.3.3'
    discard_port = 3456
    discard_addr = (discard_host, discard_port)

    query = dns.Query(b'asdf', dns.A, dns.IN)

    def setUp(self):
        self.clock = task.Clock()
        self.protocol = BugFixDNSDatagramProtocol(FakeResolver(), reactor=self.clock)
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


class DropRequestDNSServerFactory(MyDNSServerFactory):
    drops = 1

    def sendReply(self, protocol, message, address):
        if self.drops <= 0:
            super().sendReply(protocol, message, address)
        else:
            self.drops -= 1


class TestReissue(unittest.TestCase):
    server_addr = ('127.0.0.54', 5454)
    fake_resolver = FakeResolver()
    fake_resolver.set_answer('asdf', '1.2.3.4')
    query = dns.Query(b'asdf', dns.A, dns.IN)

    def setUp(self):
        self.server = DropRequestDNSServerFactory(resolver=self.fake_resolver)
        self.app = App()
        self.app.start((self.server, [self.server_addr]))

        self.resolver = BugFixResolver(servers=[self.server_addr])
        self.reactor = get_reactor()

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


# TODO: TestUDPBugFixResolver
# TODO: test dnsagent.resolver.bugfix.BugFixDNSProtocol#dataReceived


del BaseTestResolver
