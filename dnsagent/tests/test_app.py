import random

import pytest
from twisted.internet import defer
from twisted.internet.error import CannotListenError

from dnsagent.app import App
from dnsagent.config import parse_dns_server_string, DnsServerInfo, InvalidDnsServerString
from dnsagent.resolver import parse_hosts_file, Resolver
from dnsagent.server import MyDNSServerFactory
from dnsagent.tests import iplist, FakeResolver, TestResolverBase


def test_parse_dns_server_string():
    def R(string, *, proto='udp', host=None, port=53):
        assert parse_dns_server_string(string) == DnsServerInfo(proto, host, port)

    def E(string):
        with pytest.raises(InvalidDnsServerString):
            parse_dns_server_string(string)

    R('127.0.0.1', host='127.0.0.1')
    R('2000::', host='2000::')
    R('[2000::]', host='2000::')

    R('127.0.0.1:88', host='127.0.0.1', port=88)
    E('2000:::88')
    R('[2000::]:88', host='2000::', port=88)

    R('tcp://127.0.0.1', proto='tcp', host='127.0.0.1')
    R('udp://127.0.0.1', proto='udp', host='127.0.0.1')
    E('tcp://2000::')
    R('tcp://[2000::]', proto='tcp', host='2000::')

    E('[200::')
    E('[20u::]')
    E('127.0.0.1:ff')
    E('[2000::]ff')


def test_parse_hosts_file():
    name2ip = parse_hosts_file('''
        127.0.0.1   localhost loopback
        ::1         localhost   # asdf
        127.0.0.1   localhost loopback

        # asdf
        0.0.0.0     a b
        0.0.0.1     c a

        # bad lines
        0.0.0.256 asdf
        0.0.0.0
    '''.splitlines())
    assert name2ip == dict(
        localhost=iplist('127.0.0.1', '::1'),
        loopback=iplist('127.0.0.1'),
        a=iplist('0.0.0.0', '0.0.0.1'),
        b=iplist('0.0.0.0'),
        c=iplist('0.0.0.1'),
    )


class TestApp(TestResolverBase):
    def setUp(self):
        super().setUp()
        self.apps = []

    def tearDown(self):
        d = defer.Deferred()
        super().tearDown().addBoth(lambda ignore: self.clean_apps(d))
        return d

    def clean_apps(self, final: defer.Deferred):
        return defer.gatherResults(
            [ app.stop() for app in self.apps ]).addBoth(lambda ignore: final.callback(None))

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
                self.resolver = Resolver(servers=[('127.0.0.1', port)])
                return app

        self.fail('set_resolver() failed.')

    def test_basic(self):
        fake_resolver = FakeResolver()
        fake_resolver.set_answer('asdf', '1.1.1.1')
        self.set_resolver(fake_resolver)

        self.check_a('asdf', iplist('1.1.1.1'))
        self.check_a('asdfasdf', fail=True)


del TestResolverBase
