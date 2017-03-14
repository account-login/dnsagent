from ipaddress import ip_network
import struct
from typing import Union, Type

import pytest
from twisted.internet.protocol import connectionDone
from twisted.names import dns
from twisted.trial import unittest

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


# noinspection PyAttributeOutsideInit
class BaseTestExtendedDNSXXXProtcol(unittest.TestCase):
    protocol_cls = None # type: Union[Type[ExtendedDNSProtocol], Type[ExtendedDNSDatagramProtocol]]

    query = dns.Query(b'asdf', dns.A, dns.IN)
    subnet = ip_network('1.2.3.0/24')
    ecs_option = OPTClientSubnetOption.from_subnet(subnet)

    def setUp(self):
        self.fake_transport = FakeTransport()
        self.fake_resolver = FakeResolver()
        self.proto = self.protocol_cls(self.fake_resolver)
        self.proto.makeConnection(self.fake_transport)

    def test_query(self):
        data = self.do_query(self.query)
        emsg = EDNSMessage()
        emsg.fromStr(data)
        assert emsg.options == [self.ecs_option]

    def do_query(self, query: dns.Query) -> bytes:
        raise NotImplementedError

    def test_receive(self):
        msg = EDNSMessage(options=[self.ecs_option])
        self.protocol_receive(msg)
        received_msg = self.fake_resolver.msg_logs.pop()
        assert received_msg == msg
        assert received_msg.options == [self.ecs_option]

    def protocol_receive(self, msg: EDNSMessage):
        raise NotImplementedError


class TestExtendedDNSProtocol(BaseTestExtendedDNSXXXProtcol):
    protocol_cls = ExtendedDNSProtocol

    def do_query(self, query: dns.Query):
        self.proto.query([query], client_subnet=self.subnet).addErrback(swallow)
        self.proto.connectionLost(connectionDone)

        writed, addr = self.fake_transport.write_logs.pop()
        return writed[2:]

    def protocol_receive(self, msg: EDNSMessage):
        data = msg.toStr()
        self.proto.dataReceived(struct.pack('!H', len(data)) + data)


class TestExtendedDNSDatagramProtocol(BaseTestExtendedDNSXXXProtcol):
    protocol_cls = ExtendedDNSDatagramProtocol

    def do_query(self, query: dns.Query):
        d = self.proto.query(('2.3.4.5', 0x2345), [query], client_subnet=self.subnet)
        d.addErrback(swallow)
        self.proto.doStop()

        writed, addr = self.fake_transport.write_logs.pop()
        return writed

    def protocol_receive(self, msg: EDNSMessage):
        self.proto.datagramReceived(msg.toStr(), ('2.3.4.5', 0x2345))


del BaseTestExtendedDNSXXXProtcol
