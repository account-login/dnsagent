from ipaddress import ip_network
import json
from urllib.parse import urlparse, parse_qsl

import pytest
from twisted.internet import defer
from twisted.names import dns
from twisted.names.error import DNSServerError
from twisted.web.resource import Resource
from twisted.web.server import Site

from dnsagent.resolver.https import HTTPSResolver, BadRData
from dnsagent.tests import make_rrheader, BaseTestResolver, iplist
from dnsagent.utils import get_reactor


def test_split_rdata():
    def R(string, excepted):
        assert HTTPSResolver.split_rdata(string) == excepted

    def E(string, exc_type=BadRData):
        with pytest.raises(exc_type):
            HTTPSResolver.split_rdata(string)

    R(' asf  sdf ', ['asf', 'sdf'])
    R('asf sdf', ['asf', 'sdf'])
    R(r'"asdf\"sdf\\123" 456', [r'asdf"sdf\123', '456'])
    R(r'"asdf\"" 456', [r'asdf"', '456'])
    R(r'45\6', [r'45\6'])
    R(r'"asdf 234 "', ['asdf 234 '])

    E('"')
    E('"\\')


def test_decode_response():
    def R(param, expected):
        assert HTTPSResolver().decode_response(param) == expected

    def E(param, exc_type=Exception):
        with pytest.raises(Exception):
            HTTPSResolver().decode_response(param)

    R({
        "Status": 0,
        "TC": False,
        "RD": True,
        "RA": True,
        "AD": False,
        "CD": False,
        "Question": [{
            "name": "apple.com.",
            "type": 1
        }],
        "Answer": [
            {
                "name": "apple.com.",
                "type": 1,
                "TTL": 3599,
                "data": "17.178.96.59"
            },
            {
                "name": "apple.com.",
                "type": 1,
                "TTL": 3599,
                "data": "17.172.224.47"
            },
            {
                "name": "apple.com.",
                "type": 1,
                "TTL": 3599,
                "data": "17.142.160.59"
            }
        ],
        "Additional": [],
        "edns_client_subnet": "12.34.56.78/0"
    }, (
        [
            make_rrheader('apple.com', '17.178.96.59', ttl=3599),
            make_rrheader('apple.com', '17.172.224.47', ttl=3599),
            make_rrheader('apple.com', '17.142.160.59', ttl=3599),
        ], [], [],
    ))

    R({
        "Status": 0,
        "TC": False,
        "RD": True,
        "RA": True,
        "AD": False,
        "CD": True,
        "Question": [{
            "name": "img.alicdn.com.",
            "type": 6
        }],
        "Answer": [{
            "name": "img.alicdn.com.",
            "type": 5,
            "TTL": 20556,
            "data": "img.alicdn.com.danuoyi.alicdn.com."
        }],
        "Authority": [{
            "name": "danuoyi.alicdn.com.",
            "type": 6,
            "TTL": 0,
            "data": "danuoyinewns1.gds.alicdn.com. root.taobao.com. 20141014 3600 3600 604800 10800"
        }],
        "Additional": [],
        "edns_client_subnet": "114.114.114.114/24",
        "Comment": "Response from danuoyinewns1.gds.alicdn.com.(121.43.18.33)"
    }, (
        [dns.RRHeader(
            'img.alicdn.com', type=dns.CNAME, ttl=20556,
            payload=dns.Record_CNAME('img.alicdn.com.danuoyi.alicdn.com', ttl=20556)
        )],
        [dns.RRHeader(
            'danuoyi.alicdn.com', type=dns.SOA, ttl=0,
            payload=dns.Record_SOA(
                'danuoyinewns1.gds.alicdn.com', 'root.taobao.com',
                '20141014', '3600', '3600', '604800', '10800',
                ttl=0,
            ),
        )],
        [])
    )

    R({
        "Status": 0,
        "TC": False,
        "RD": True,
        "RA": True,
        "AD": False,
        "CD": False,
        "Question": [{
            "name": "*.dns-example.info",
            "type": 99
        }],
        "Answer": [{
            "name": "*.dns-example.info",
            "type": 99,
            "TTL": 21599,
            "data": "\"v=spf1 -all\""
        }],
        "Comment": "Response from 216.239.38.110"

    }, (
        [dns.RRHeader(
            '*.dns-example.info', type=dns.SPF, ttl=21599,
            payload=dns.Record_SPF('v=spf1 -all', ttl=21599)
        )], [], [])
    )

    E({
        "Status": 2,
        "TC": False,
        "RD": True,
        "RA": True,
        "AD": False,
        "CD": False,
        "Question":
            [
                {
                    "name": "dnssec-failed.org.",
                    "type": 1
                }
            ],
        "Comment": "DNSSEC validation failure. "
                   "Please check http://dnsviz.net/d/dnssec-failed.org/dnssec/."
    }, DNSServerError)


def test_make_request_url():
    def dict_value_to_string(dct):
        return dict((k, str(v)) for k, v in dct.items())

    def R(name: bytes, type_=dns.A, param=None, **kwargs):
        url = HTTPSResolver().make_request_url(name, dns.IN, type_, **kwargs)
        assert url.startswith('https://dns.google.com/resolve?')
        assert dict(parse_qsl(urlparse(url).query)) == dict_value_to_string(param)

    R(b'asdf', param=dict(name='asdf', type=dns.A))
    R(
        b'asdf', dns.SOA, client_subnet=ip_network('1.2.3.0/24'),
        param=dict(name='asdf', type=dns.SOA, edns_client_subnet='1.2.3.0/24'),
    )


class LocalHTTPSResolver(HTTPSResolver):
    server_host = '127.0.4.44'
    server_port = 4444
    API_BASE_URL = 'http://%s:%s/' % (server_host, server_port)


class FakeApiResource(Resource):
    isLeaf = True

    def render_GET(self, request):
        answer = {
            "Status": 0,
            "TC": False,
            "RD": True,
            "RA": True,
            "AD": False,
            "CD": False,
            "Question": [{
                "name": "apple.com.",
                "type": 1
            }],
            "Answer": [{
                "name": "apple.com.",
                "type": 1,
                "TTL": 3599,
                "data": "17.178.96.59"
            }],
            "Additional": [],
            "edns_client_subnet": "12.34.56.78/0"
        }
        return json.dumps(answer).encode('utf8')


class TestIntegration(BaseTestResolver):
    def setUp(self):
        super().setUp()
        self.resolver = LocalHTTPSResolver()

        site = Site(FakeApiResource())
        reactor = get_reactor()
        host, port = LocalHTTPSResolver.server_host, LocalHTTPSResolver.server_port
        self.server_transport = reactor.listenTCP(port, site, interface=host)

    def tearDown(self):
        def cleanup(ignore):
            import treq._utils
            return defer.DeferredList([
                defer.maybeDeferred(self.server_transport.stopListening),
                # XXX: hacks to clean delayed call
                treq._utils.get_global_pool().closeCachedConnections(),
            ], fireOnOneErrback=True).chainDeferred(final_d)

        final_d = defer.Deferred()
        d = super().tearDown()
        d.addCallback(cleanup).addErrback(final_d.errback)
        return final_d

    def test_run(self):
        self.check_a('apple.com', iplist('17.178.96.59'))


del BaseTestResolver
