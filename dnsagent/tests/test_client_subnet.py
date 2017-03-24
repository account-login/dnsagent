from ipaddress import ip_network
import logging
import struct
from typing import Union, Type

import pytest
from twisted.internet import task, defer
from twisted.internet.protocol import connectionDone
from twisted.names import dns
from twisted.python.failure import Failure
from twisted.trial import unittest

from dnsagent.app import App
from dnsagent.pubip import get_public_ip
from dnsagent.resolver import ExtendedResolver, TCPExtendedResolver
from dnsagent.resolver.extended import (
    OPTClientSubnetOption, BadOPTClientSubnetData, QueryList,
    ExtendedDNSProtocol, ExtendedDNSDatagramProtocol, EDNSMessage,
)
from dnsagent.server import ExtendedDNSServerFactory, AutoDiscoveryPolicy
from dnsagent.tests import (
    FakeTransport, FakeResolver, clean_treq_connection_pool, require_internet, swap_function,
)


logger = logging.getLogger(__name__)


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

    subnet = ip_network('1.2.3.0/24')
    queries = QueryList([(dns.Query(b'asdf', dns.A, dns.IN))], client_subnet=subnet)
    ecs_option = OPTClientSubnetOption.from_subnet(subnet)

    def setUp(self):
        self.fake_transport = FakeTransport()
        self.fake_resolver = FakeResolver()
        self.proto = self.protocol_cls(self.fake_resolver)
        self.proto.makeConnection(self.fake_transport)

    def test_query(self):
        data = self.do_query(self.queries)
        emsg = EDNSMessage()
        emsg.fromStr(data)
        assert emsg.options == [self.ecs_option]

    def do_query(self, queries: QueryList) -> bytes:
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

    def do_query(self, queries: QueryList) -> bytes:
        self.proto.query(queries).addErrback(swallow)
        self.proto.connectionLost(connectionDone)

        writed, addr = self.fake_transport.write_logs.pop()
        return writed[2:]

    def protocol_receive(self, msg: EDNSMessage):
        data = msg.toStr()
        self.proto.dataReceived(struct.pack('!H', len(data)) + data)


class TestExtendedDNSDatagramProtocol(BaseTestExtendedDNSXXXProtcol):
    protocol_cls = ExtendedDNSDatagramProtocol

    def do_query(self, queries: QueryList) -> bytes:
        d = self.proto.query(('2.3.4.5', 0x2345), queries)
        d.addErrback(swallow)
        self.proto.doStop()

        writed, addr = self.fake_transport.write_logs.pop()
        return writed

    def protocol_receive(self, msg: EDNSMessage):
        self.proto.datagramReceived(msg.toStr(), ('2.3.4.5', 0x2345))


class BaseTestECSClientServer(unittest.TestCase):
    resolver_cls = None     # type: Union[Type[ExtendedResolver], Type[TCPExtendedResolver]]
    server_addr = ('127.0.0.56', 5656)

    query = dns.Query(b'asdf', dns.A, dns.IN)
    subnet = ip_network('1.2.3.0/24')
    ecs_option = OPTClientSubnetOption.from_subnet(subnet)

    def setUp(self):
        self.fake_resolver = FakeResolver()
        server = ExtendedDNSServerFactory(resolver=self.fake_resolver)
        self.app = App()
        self.app.start((server, [self.server_addr]))

        self.resolver = self.resolver_cls(servers=[self.server_addr])

    def tearDown(self):
        return self.app.stop()

    def test_run(self):
        def check_server(err):
            assert isinstance(err, Failure)
            assert self.fake_resolver.query_logs.pop()['client_subnet'] == self.subnet

        d = self.resolver.query(self.query, client_subnet=self.subnet)
        return d.addBoth(check_server)


class TestClientSubnetWithExtendedResolver(BaseTestECSClientServer):
    resolver_cls = ExtendedResolver


class TestClientSubnetWithTCPExtendedResolver(BaseTestECSClientServer):
    resolver_cls = TCPExtendedResolver


class TestAutoDiscoveryPolicy(unittest.TestCase):
    def setUp(self):
        self.clock = task.Clock()
        self.policy = AutoDiscoveryPolicy(retry_intevals=(1, 2), reactor=self.clock)
        self.pub_addr = ('1.2.3.4', 1234)

        self.addCleanup(clean_treq_connection_pool)

    def test_from_msg(self):
        subnet = ip_network('2.3.0.0/16')
        ecs_option = OPTClientSubnetOption.from_subnet(subnet)
        assert self.policy(EDNSMessage(options=[ecs_option]), self.pub_addr) == subnet

    def test_from_addr(self):
        subnet = self.policy(EDNSMessage(), self.pub_addr)
        net_string = '%s/%d' % (self.pub_addr[0], self.policy.max_prefix_lens[4])
        assert subnet == ip_network(net_string, strict=False)

    @require_internet
    def test_from_get_public_ip(self):
        subnet = self.policy(EDNSMessage(), ('192.168.1.1', 1111))
        if subnet:
            logger.info('got subnet from server ip immediately')
        else:
            def check(result):
                if result is None:
                    logger.error('get_public_ip() failed')
                try:
                    if self.policy.retry_d:
                        assert result is None
                        assert not self.policy.retry_d.called
                        assert self.policy.retry_d.getTime() == 1
                    assert result == self.policy.server_public_ip
                finally:
                    if self.policy.retry_d:
                        self.policy.retry_d.cancel()

            return self.policy.request_d.addBoth(check)

    def test_fallback(self):
        def fake_get_public_ip():
            return defer.succeed(None)

        swap_function(fake_get_public_ip, get_public_ip)
        self.addCleanup(swap_function, fake_get_public_ip, get_public_ip)

        subnet = ip_network('9.8.0.0/16')
        self.policy = AutoDiscoveryPolicy(fallback=subnet, reactor=self.clock)
        assert self.policy(EDNSMessage(), ('10.10.1.1', 1010)) == subnet


del BaseTestExtendedDNSXXXProtcol
del BaseTestECSClientServer
