from twisted.internet import defer

from dnsagent.app import App
from dnsagent.resolver import ExtendedResolver
from dnsagent.server import ExtendedDNSServerFactory
from dnsagent.tests import iplist, FakeResolver, BaseTestResolver


class TestApp(BaseTestResolver):
    server_addr = ('127.0.2.2', 5300)

    def setUp(self):
        super().setUp()
        self.apps = []

    def tearDown(self):
        d = defer.Deferred()
        super().tearDown().addCallbacks(lambda ignore: self.clean_apps(d), d.errback)
        return d

    def clean_apps(self, final: defer.Deferred):
        return defer.DeferredList(
            [ app.stop() for app in self.apps ], fireOnOneErrback=True,
        ).chainDeferred(final)

    def set_resolver(self, resolver):
        server = ExtendedDNSServerFactory(resolver=resolver)
        app = App()
        self.apps.append(app)
        app.start((server, [self.server_addr]))
        self.resolver = ExtendedResolver(servers=[self.server_addr])

    def test_basic(self):
        fake_resolver = FakeResolver()
        fake_resolver.set_answer('asdf', '1.1.1.1')
        self.set_resolver(fake_resolver)

        self.check_a('asdf', iplist('1.1.1.1'))
        self.check_a('asdfasdf', fail=True)


del BaseTestResolver
