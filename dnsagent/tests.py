import os
import tempfile
from ipaddress import ip_address
from twisted.internet import defer
from twisted.names import dns
from twisted.trial import unittest
import pytest

from dnsagent.config import (
    parse_dns_server_string, DnsServerInfo, InvalidDnsServerString,
)
from dnsagent.resolver import parse_hosts_file, HostsResolver, dns_record_to_ip


from dnsagent.__main__ import enable_log
enable_log()


def iplist(*lst):
    return [ip_address(ip) for ip in lst]


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


class TestHostsResolver(unittest.TestCase):
    def setUp(self):
        self.defereds = []
        self.hosts_file = None

        hosts_string = '''
            127.0.0.1   localhost loopback
            ::1         localhost   # asdf
        '''
        self.setup_resolver(hosts_string)

    def tearDown(self):
        def cleanup(result):
            os.unlink(self.hosts_file)

        return defer.gatherResults(self.defereds).addBoth(cleanup)

    def setup_resolver(self, hosts_string):
        fd, self.hosts_file = tempfile.mkstemp(prefix='hosts_', suffix='.txt', text=True)
        os.write(fd, hosts_string.encode('utf8'))
        self.resolver = HostsResolver(self.hosts_file, reload=True)
        os.close(fd)

    def _check_query(self, query: dns.Query, expect):
        d = defer.Deferred()
        self.defereds.append(d)

        def check_result(result):
            try:
                ans, auth, add = result
                assert [dns_record_to_ip(rr.payload) for rr in ans] == expect
            finally:
                d.callback(None)

        def failed(failure):
            print('query failed: ', query)
            print(failure)
            d.callback(None)
            assert False

        self.resolver.query(query, timeout=[0.5]).addCallbacks(check_result, failed)

    def check_a(self, name: str, expect: list):
        self._check_query(dns.Query(name.encode('utf8'), dns.A, dns.IN), expect)

    def check_aaaa(self, name: str, expect: list):
        self._check_query(dns.Query(name.encode('utf8'), dns.AAAA, dns.IN), expect)

    def check_all(self, name: str, expect: list):
        self._check_query(dns.Query(name.encode('utf8'), dns.ALL_RECORDS, dns.IN), expect)

    def test_resolve(self):
        self.check_a('localhost', iplist('127.0.0.1'))
        self.check_aaaa('localhost', iplist('::1'))
        self.check_all('localhost', iplist('127.0.0.1', '::1'))
        self.check_a('loopback', iplist('127.0.0.1'))
