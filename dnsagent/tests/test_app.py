import random

import pytest
from twisted.internet import defer
from twisted.internet.error import CannotListenError
from twisted.trial import unittest

from dnsagent.app import App
from dnsagent.utils import parse_url, ParsedURL, BadURL
from dnsagent.config import parse_dns_server_string, DnsServerInfo
from dnsagent.resolver import ExtendedResolver
from dnsagent.server import MyDNSServerFactory
from dnsagent.tests import iplist, FakeResolver, BaseTestResolver


class BaseTestParseURL(unittest.TestCase):
    parse_method = None
    parsed_type = None

    def good(self, string: str, scheme=None, host=None, port=None):
        assert self.parse_method(string) == self.parsed_type(scheme, host, port)

    def bad(self, string: str):
        with pytest.raises(BadURL):
            self.parse_method(string)

    def test_run(self):
        self.good('127.0.0.1', host='127.0.0.1')
        self.good('2000::', host='2000::')
        self.good('[2000::]', host='2000::')

        self.good('127.0.0.1:88', host='127.0.0.1', port=88)
        self.bad('2000:::88')
        self.good('[2000::]:88', host='2000::', port=88)

        self.good('tcp://127.0.0.1', scheme='tcp', host='127.0.0.1')
        self.good('udp://127.0.0.1', scheme='udp', host='127.0.0.1')
        self.bad('tcp://2000::')
        self.good('tcp://[2000::]', scheme='tcp', host='2000::')

        self.bad('[200::')
        self.bad('[20u::]')
        self.bad('127.0.0.1:ff')
        self.bad('[2000::]ff')
        self.bad(':123')


class TestParseURL(BaseTestParseURL):
    parse_method = staticmethod(parse_url)
    parsed_type = ParsedURL


class TestParseDnsServerString(BaseTestParseURL):
    parse_method = staticmethod(parse_dns_server_string)
    parsed_type = DnsServerInfo

    def good(self, string: str, scheme='udp', host=None, port=53):
        return super().good(string, scheme, host, port)


class TestApp(BaseTestResolver):
    def setUp(self):
        super().setUp()
        self.apps = []

    def tearDown(self):
        d = defer.Deferred()
        super().tearDown().addBoth(lambda ignore: self.clean_apps(d))
        return d

    def clean_apps(self, final: defer.Deferred):
        return defer.DeferredList(
            [ app.stop() for app in self.apps ]
        ).addBoth(lambda ignore: final.callback(None))

    def set_resolver(self, resolver):
        server = MyDNSServerFactory(resolver=resolver)
        app = App()
        self.apps.append(app)
        for i in range(10):
            port = random.randrange(1024, 60000)
            try:
                app.start((server, [('', port)]))
            except CannotListenError:
                pass
            else:
                self.resolver = ExtendedResolver(servers=[('127.0.0.1', port)])
                return app

        self.fail('set_resolver() failed.')

    def test_basic(self):
        fake_resolver = FakeResolver()
        fake_resolver.set_answer('asdf', '1.1.1.1')
        self.set_resolver(fake_resolver)

        self.check_a('asdf', iplist('1.1.1.1'))
        self.check_a('asdfasdf', fail=True)


del BaseTestParseURL
del BaseTestResolver
