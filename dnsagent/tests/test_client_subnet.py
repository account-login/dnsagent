from ipaddress import ip_network

import pytest
from twisted.internet.protocol import connectionDone
from twisted.names import dns

from dnsagent.resolver.extended import (
    OPTClientSubnetOption, BadOPTClientSubnetData,
    ExtendedDNSProtocol, ExtendedDNSDatagramProtocol, EDNSMessage,
)
from dnsagent.tests import FakeTransport, FakeResolver


def test_opt_client_subnet_option_construct():
    def R(subnet_string: str, expected_data: bytes, scope_prefix=0):
        option = OPTClientSubnetOption.from_subnet(
            ip_network(subnet_string, strict=False), scope_prefix=scope_prefix,
        )
        assert option.data == expected_data

    R('1.2.3.4/24', b'\0\1\x18\0\1\2\3')
    R('1.2.3.4/24', b'\0\1\x18\5\1\2\3', scope_prefix=5)
    R('1.2.3.4/23', b'\0\1\x17\0\1\2\2')
    R('1:2:3::4/32', b'\0\2\x20\0\0\1\0\2')


def test_opt_client_subnet_option_parse_data():
    def R(data: bytes, subnet_string: str, scope_prefix=0):
        assert OPTClientSubnetOption.parse_data(data) == (
            ip_network(subnet_string, strict=False),
            scope_prefix,
        )

    def E(data: bytes, exc_type=BadOPTClientSubnetData):
        with pytest.raises(exc_type):
            OPTClientSubnetOption.parse_data(data)

    R(b'\0\1\x18\0\1\2\3', '1.2.3.4/24')
    R(b'\0\1\x18\5\1\2\3', '1.2.3.4/24', scope_prefix=5)
    R(b'\0\2\x20\0\0\1\0\2', '1:2:3::4/32')

    E(b'\0\1\x19\0\1\2\3')      # addr too short
    E(b'\0\1\x1f\0\1\2\3')      # addr too long
    E(b'\0\1\x18\0\1\2\3\0')    # addr too long
    E(b'\0\1\x18\0\1\2\3\4')    # addr too long
    E(b'\0\1\x17\0\1\2\3')      # addr not zero padded
    E(b'\0\3\x18\0\1\2\3')      # addr family unknown
    E(b'\0\1\x18')              # data too short


def swallow(ignore):
    pass


def test_extended_dns_protocol():
    fake_transport = FakeTransport()
    proto = ExtendedDNSProtocol(FakeResolver())
    proto.makeConnection(fake_transport)

    q = dns.Query(b'asdf', dns.A, dns.IN)
    proto.query([q], client_subnet=ip_network('1.2.3.0/24')).addErrback(swallow)
    proto.connectionLost(connectionDone)    # clear delayed call
    writed, addr = fake_transport.write_logs.pop()

    emsg = EDNSMessage()
    emsg.fromStr(writed[2:])
    assert emsg.options == [OPTClientSubnetOption.from_subnet(ip_network('1.2.3.0/24'))]


def test_extended_dns_datagram_protocol():
    fake_transport = FakeTransport()
    proto = ExtendedDNSDatagramProtocol(FakeResolver())
    proto.makeConnection(fake_transport)

    q = dns.Query(b'asdf', dns.A, dns.IN)
    proto.query(
        ('2.3.4.5', 0x2345), [q], client_subnet=ip_network('1.2.3.0/24')
    ).addErrback(swallow)
    proto.doStop()  # clear delayed call
    writed, addr = fake_transport.write_logs.pop()

    emsg = EDNSMessage()
    emsg.fromStr(writed)
    assert emsg.options == [OPTClientSubnetOption.from_subnet(ip_network('1.2.3.0/24'))]
