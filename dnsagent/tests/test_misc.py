import pytest
from twisted.internet import defer
from twisted.trial import unittest

from dnsagent.config import parse_dns_server_string, DnsServerInfo
from dnsagent.tests import need_clean_treq, require_internet
from dnsagent.utils import BadURL, parse_url, ParsedURL, patch_twisted_ssl_root_bug, get_treq


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


@require_internet
class TestTwistedSSLBug(unittest.TestCase):
    """Windows only bug"""

    def setUp(self):
        patch_twisted_ssl_root_bug()

    @need_clean_treq
    @defer.inlineCallbacks
    def test_run(self):
        treq = get_treq()
        response = yield treq.get('https://example.com/')
        text = yield treq.text_content(response)
        assert len(text) > 10


del BaseTestParseURL
