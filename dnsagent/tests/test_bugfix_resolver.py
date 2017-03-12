from twisted.internet import defer
from twisted.internet.error import ConnectionDone
from twisted.python.failure import Failure

from dnsagent.app import App
from dnsagent.resolver.basic import BugFixResolver
from dnsagent.server import MyDNSServerFactory
from dnsagent.tests import BaseTestResolver, FakeResolver, iplist
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
            self.reactor.callLater(0.001,
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


del BaseTestResolver
