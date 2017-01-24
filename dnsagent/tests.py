import pytest

from dnsagent.config import (
    parse_dns_server_string, DnsServerInfo, InvalidDnsServerString,
)


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
