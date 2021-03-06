import logging
import os
import struct
from io import BytesIO
from ipaddress import ip_address

import pytest
from twisted.internet import address as taddress, defer, ssl
from twisted.internet.endpoints import (
    TCP4ClientEndpoint, TCP4ServerEndpoint, SSL4ServerEndpoint, connectProtocol,
)
from twisted.internet.error import CannotListenError
from twisted.internet.protocol import (
    DatagramProtocol, Protocol, ServerFactory, connectionDone, ClientFactory,
)
from twisted.python.failure import Failure
from twisted.python.modules import getModule
from twisted.trial import unittest
from twisted.web.client import Agent, BrowserLikePolicyForHTTPS
from twisted.web.resource import Resource
from twisted.web.server import Site

from dnsagent.app import App
from dnsagent.resolver import HostsResolver
from dnsagent.resolver.extended import ExtendedResolver, TCPExtendedResolver
from dnsagent.socks import (
    read_socks_host, encode_socks_host, SocksHost, BadSocksHost, InsufficientData,
    Socks5Reply, BadSocks5Reply,
    UDPRelayPacket, BadUDPRelayPacket, UDPRelayProtocol, UDPRelayTransport, UDPRelay,
    Socks5ControlProtocol, Socks5Cmd, TCPRelayConnector, SocksProxy, SocksWrappedReactor,
)
from dnsagent.tests import (
    FakeTransport, FakeDatagramProtocol, FakeProtocol,
    OneshotClientFactory, OneshotServerFactory,
    Greeter, TCPGreeter, Reverser, TCPReverser,
    SSRunner,
)
from dnsagent.utils import (
    get_reactor, get_client_endpoint, get_treq, rrheader_to_ip, to_twisted_addr,
)


logger = logging.getLogger(__name__)


def test_to_twisted_addr():
    assert to_twisted_addr('asdf', 1234) == taddress.HostnameAddress(b'asdf', 1234)
    assert to_twisted_addr('asdf', 1234, type_='UDP') == taddress.HostnameAddress(b'asdf', 1234)
    assert to_twisted_addr('1.2.3.4', 1234) == taddress.IPv4Address('TCP', '1.2.3.4', 1234)
    assert to_twisted_addr('::1', 3456, type_='UDP') == taddress.IPv6Address('UDP', '::1', 3456)


def test_read_socks_host():
    def E(data, exc_type=BadSocksHost):
        with pytest.raises(exc_type):
            read_socks_host(BytesIO(data))

    def R(data, expected):
        for i in range(len(data) - 1):
            with pytest.raises(InsufficientData):
                read_socks_host(BytesIO(data[:i]))
        assert read_socks_host(BytesIO(data)) == expected

    R(b'\x01\x7f\0\0\1', ip_address('127.0.0.1'))
    R(b'\x03\x04asdf', 'asdf')
    R(b'\x04' + b'\0' * 15 + b'\1', ip_address('::1'))

    E(b'\x02\0\0\0\0')
    E(b'\x03\x00\0')


def test_encode_socks_host():
    assert encode_socks_host(ip_address('127.0.0.1')) == b'\x01\x7f\0\0\1'
    assert encode_socks_host(ip_address('::1')) == b'\x04' + b'\0' * 15 + b'\1'
    assert encode_socks_host('asdf') == b'\x03\x04asdf'


def test_udp_packet_decode():
    def E(data):
        with pytest.raises(BadUDPRelayPacket):
            UDPRelayPacket.loads(data)

    assert UDPRelayPacket.loads(b'\0\0\0\x01\x7f\0\0\1\xab\xcd\xff\xff') \
        == UDPRelayPacket(ip_address('127.0.0.1'), 0xabcd, b'\xff\xff')

    E(b'\0\0\1\x01\x7f\0\0\1\xab\xcd\xff\xff')
    E(b'\0\0\0\x01\x7f\0\0\1\xab')


def test_udp_packet_encode():
    assert UDPRelayPacket(ip_address('127.0.0.1'), 0xabcd, b'\xff\xff').dumps() == (
        b'\0\0\0' + encode_socks_host(ip_address('127.0.0.1')) + b'\xab\xcd' + b'\xff\xff'
    )


def test_socks5_reply_load():
    def E(data, exc_type):
        with pytest.raises(exc_type):
            Socks5Reply.load(BytesIO(data))

    def R(data: bytes, reply: int, host: SocksHost, port: int):
        assert Socks5Reply.load(BytesIO(data)) == Socks5Reply(reply, host, port)

    reply_data = b'\5\1\0\1\x7f\0\0\1\x12\x34'
    for i in range(len(reply_data) - 1):
        E(reply_data[:i], InsufficientData)
    R(reply_data, 1, ip_address('127.0.0.1'), 0x1234)

    E(b'\4\0\0\1\x7f\0\0\1\x12\x34', BadSocks5Reply)
    E(b'\5\0\1\1\x7f\0\0\1\x12\x34', BadSocks5Reply)
    E(b'\5\0\1\5\x7f\0\0\1\x12\x34', BadSocks5Reply)


def test_socks5_reply_dumps():
    def R(reply: int, host: SocksHost, port: int, answer: bytes):
        assert Socks5Reply(reply, host, port).dumps() == answer

    R(0, 'asdf', 0x1234, b'\5\0\0\3\4asdf\x12\x34')
    R(1, ip_address('1.2.3.4'), 0x1234, b'\5\1\0\1\1\2\3\4\x12\x34')


def test_udp_relay_protocol():
    relay_proto = UDPRelayProtocol()
    tr = FakeTransport()
    relay_proto.makeConnection(tr)
    dp = FakeDatagramProtocol()

    # accept all packet if not connected
    relay_proto.set_user_protocol(dp)
    packet = UDPRelayPacket(ip_address('127.0.0.1'), 1234, b'1234')
    relay_proto.datagramReceived(packet.dumps(), ('1.2.3.4', 4567))
    assert dp.data_logs == [(b'1234', ('127.0.0.1', 1234))]
    dp.data_logs.clear()

    # drop unexpected packet if connected
    relay_proto.connect(('127.0.0.88', 8899))
    packet = UDPRelayPacket(ip_address('127.0.0.1'), 1234, b'1234')
    relay_proto.datagramReceived(packet.dumps(), ('1.2.3.4', 4567))
    assert dp.data_logs == []

    # accept relevant packet
    packet = UDPRelayPacket(ip_address('127.0.0.88'), 8899, b'8899')
    relay_proto.datagramReceived(packet.dumps(), ('1.2.3.4', 4567))
    assert dp.data_logs == [(b'8899', ('127.0.0.88', 8899))]
    dp.data_logs.clear()


def test_udp_relay_port():
    user_proto = FakeDatagramProtocol()
    tr = FakeTransport()
    relay_proto = UDPRelayProtocol()
    relay_proto.makeConnection(tr)

    relay_transport = UDPRelayTransport(1212, user_proto, relay_protocol=relay_proto)
    assert relay_proto.user_protocol is user_proto

    relay_transport.startListening()
    assert user_proto.transport is relay_transport
    assert user_proto.start_count == 1

    relay_transport.connect('1.2.3.4', 1234)
    assert relay_transport.connected_addr == relay_proto.connected_addr == ('1.2.3.4', 1234)

    # write a connected transport
    user_proto.transport.write(b'asdf')
    packet = UDPRelayPacket(ip_address('1.2.3.4'), 1234, b'asdf')
    assert tr.poplogs() == [(packet.dumps(), None)]

    # getHost()
    from twisted.internet import address
    assert relay_transport.getHost() == address.IPv4Address('UDP', '1.2.3.4', 1234)

    # stopListening()
    relay_transport.stopListening()
    assert relay_transport.connected_addr is None
    assert user_proto.stop_count == 1

    # write a un-connected transport
    relay_transport.write(b'zxcv', ('2.3.4.5', 2345))
    packet = UDPRelayPacket(ip_address('2.3.4.5'), 2345, b'zxcv')
    assert tr.poplogs() == [(packet.dumps(), None)]


# noinspection PyAttributeOutsideInit
class TestSocks5ControlProtocol(unittest.TestCase):
    # TODO: test connectionLost
    def setUp(self):
        self.transport = FakeTransport()
        self.ctrl_proto = Socks5ControlProtocol()
        self.ctrl_proto.makeConnection(self.transport)

        def authed(arg):
            self.auth_result = arg
        self.ctrl_proto.auth_defer.addBoth(authed)
        self.auth_result = None

    def feed(self, data: bytes, expected_state: str):
        assert self.ctrl_proto.state == expected_state
        for i in range(len(data)):
            self.ctrl_proto.dataReceived(b'')
            assert self.ctrl_proto.state == expected_state
            self.ctrl_proto.dataReceived(data[i:(i + 1)])
            if i < len(data) - 1:
                assert self.ctrl_proto.state == expected_state

    def test_greeting_success(self):
        assert self.ctrl_proto.state == 'greeted'
        assert self.transport.write_logs.pop() == (b'\x05\x01\x00', None)

        self.feed(b'\x05\x00', 'greeted')
        assert self.ctrl_proto.state == 'authed'
        assert self.auth_result is self.ctrl_proto
        assert self.ctrl_proto.data == b''

    def test_greeting_server_fail(self):
        self._run_greeting_failure_test(b'\x05\xff')

    def test_greeting_protocol_fail(self):
        self._run_greeting_failure_test(b'\x04\x00')

    def _run_greeting_failure_test(self, data: bytes):
        self.feed(data, 'greeted')
        assert self.ctrl_proto.state == 'failed'
        assert isinstance(self.auth_result, Failure)
        assert self.ctrl_proto.data == b''

    def test_udp_associate_success(self):
        d = self._run_request(
            method=Socks5ControlProtocol.request_udp_associate,
            args=(ip_address('1.2.3.4'), 0x1234),
            state_after_req='udp_req', req=b'\x05\x03\0\x01\1\2\3\4\x12\x34',
            resp=b'\5\0\0\x01\2\3\4\5\x23\x45', state_after_resp='udp_relay',
        )

        def udp_reqed(arg):
            assert arg == (ip_address('2.3.4.5'), 0x2345)
            assert self.ctrl_proto.data == b''
        return d.addBoth(udp_reqed)

    def test_tcp_connect_success(self):
        class FakeConnector:
            def __init__(self, user_proto: Protocol):
                self.user_protocol = user_proto

            def data_received(self, data):
                self.user_protocol.dataReceived(data)

        d = self._run_request(
            method=Socks5ControlProtocol.request_tcp_connect,
            args=(ip_address('1.2.3.4'), 0x1234),
            state_after_req='tcp_req', req=b'\x05\x01\0\x01\1\2\3\4\x12\x34',
            resp=b'\5\0\0\x01\2\3\4\5\x23\x45', state_after_resp='tcp_relay',
        )

        def tcp_reqed(arg):
            assert arg == (ip_address('2.3.4.5'), 0x2345)
            assert self.ctrl_proto.data == b''

            user_proto = FakeProtocol()
            self.ctrl_proto.connector = FakeConnector(user_proto)
            self.ctrl_proto.dataReceived(b'1234')
            assert user_proto.recv_logs == [b'1234']

        return d.addBoth(tcp_reqed)

    def _run_request(self, method, args, state_after_req, req, resp, state_after_resp):
        self.ctrl_proto.dataReceived(b'\x05\x00')

        d = method(self.ctrl_proto, *args)
        assert self.ctrl_proto.state == state_after_req
        assert self.transport.write_logs.pop() == (req, None)
        assert d is self.ctrl_proto.request_defer

        self.feed(resp, state_after_req)
        assert self.ctrl_proto.state == state_after_resp

        return d

    def test_udp_associate_server_fail(self):
        return self._run_request_server_fail(Socks5ControlProtocol.request_udp_associate)

    def test_udp_associate_protocol_fail(self):
        return self._run_request_protocol_fail(Socks5ControlProtocol.request_udp_associate)

    def test_tcp_connect_server_fail(self):
        return self._run_request_server_fail(Socks5ControlProtocol.request_tcp_connect)

    def test_tcp_connect_protocol_fail(self):
        return self._run_request_protocol_fail(Socks5ControlProtocol.request_tcp_connect)

    def _run_request_server_fail(self, method):
        d = self._run_request_failure(
            method=method, args=(ip_address('1.2.3.4'), 0x1234),
            data=b'\5\x01\0\x01\2\3\4\5\x23\x45', failed_state='req_failed',
        )
        assert self.transport.connected
        return d

    def _run_request_protocol_fail(self, method):
        return self._run_request_failure(
            method=method, args=(ip_address('1.2.3.4'), 0x1234),
            data=b'\5\0\0\x08\2\3\4\5\x23\x45', failed_state='failed',
        )

    def _run_request_failure(self, method, args, data, failed_state):
        def requested(arg):
            assert isinstance(arg, Failure)
            assert self.ctrl_proto.data == b''

        self.ctrl_proto.dataReceived(b'\x05\x00')
        d = method(self.ctrl_proto, *args)
        d.addBoth(requested)

        self.ctrl_proto.dataReceived(data)
        assert d.called
        assert self.ctrl_proto.state == failed_state
        return d


# noinspection PyAttributeOutsideInit
class TestUDPRelay(unittest.TestCase):
    def setUp(self):
        self.transport = FakeTransport()
        self.ctrl_proto = Socks5ControlProtocol()
        self.ctrl_proto.makeConnection(self.transport)
        self.relay = UDPRelay(ctrl_protocol=self.ctrl_proto)
        self.relay_defer = self.relay.setup_relay()

        def set_result(arg):
            self.relay_setup_result = arg
        self.relay_defer.addBoth(set_result)
        self.relay_setup_result = None

    def tearDown(self):
        return self.relay.stop()

    def test_auth_failed(self):
        self.ctrl_proto.dataReceived(b'\5\xff')
        assert isinstance(self.relay_setup_result, Failure)

    def test_udp_associate_failed(self):
        self.ctrl_proto.dataReceived(b'\5\0')
        self.ctrl_proto.dataReceived(b'\5\x01\0\x01\2\3\4\5\x23\x45')
        assert not self.relay.relay_done
        assert isinstance(self.relay_setup_result, Failure)

    def test_udp_associate_success(self):
        self.ctrl_proto.dataReceived(b'\5\0')
        self.ctrl_proto.dataReceived(b'\5\0\0\x01\x7f\0\0\x08\x23\x45')
        assert self.relay.relay_done
        assert self.relay_setup_result == (ip_address('127.0.0.8'), 0x2345)

    def test_listenUDP(self):
        self.ctrl_proto.dataReceived(b'\5\0')
        self.ctrl_proto.dataReceived(b'\5\0\0\x01\x7f\0\0\x08\x23\x45')

        greet_to = ('4.3.2.1', 0x4321)
        user_proto = Greeter(greet_to)
        port = self.relay.listenUDP(0x1234, user_proto)
        assert user_proto.transport is port
        assert self.relay.relay_proto.user_protocol is user_proto
        assert self.relay.listening_port is port

    def test_listenUDP_can_not_listen(self):
        for data in (b'', b'\5\0', b'\5\1\0\x01\2\3\4\5\x23\x45'):
            self.ctrl_proto.dataReceived(data)
            with pytest.raises(CannotListenError):
                self.relay.listenUDP(0x1234, Greeter(('4.3.2.1', 0x4321)))

    def test_listenUDP_can_not_listen_more_than_once(self):
        self.ctrl_proto.dataReceived(b'\5\0')
        self.ctrl_proto.dataReceived(b'\5\0\0\x01\x7f\0\0\x08\x23\x45')
        self.relay.listenUDP(0x1234, FakeDatagramProtocol())
        with pytest.raises(RuntimeError):
            self.relay.listenUDP(0x2345, FakeDatagramProtocol())


class RelayProtocol(Protocol):
    def __init__(self, other_transport):
        self.other_transport = other_transport

    def dataReceived(self, data):
        self.other_transport.write(data)


class Buffer:
    def __init__(self):
        self.data = b''

    def read(self, n: int):
        assert n > 0
        if len(self.data) < n:
            raise InsufficientData
        else:
            ret = self.data[:n]
            self.data = self.data[n:]
            return ret

    def readall(self):
        ret = self.data
        self.data = b''
        return ret

    def append(self, data: bytes):
        self.data += data

    def __bool__(self):
        return len(self.data) != 0


class FakeSocks5ControlServerProtocol(Protocol):
    def __init__(self, udp_relay_address, reactor=None):
        self.udp_relay_host, self.udp_relay_port = udp_relay_address
        self.udp_relay_proto = FakeUDPRelayServerProtocol()
        self.udp_relay_server_port = None
        self.tcp_relay_proto = None
        self.buffer = Buffer()
        self.state = None

        self.reactor = get_reactor(reactor)

    def connectionMade(self):
        self.state = 'init'

    def dataReceived(self, data):
        self.buffer.append(data)
        self.data_processing_loop()

    def data_processing_loop(self):
        while self.buffer:
            try:
                self.handle_data()
            except InsufficientData:
                break

    def handle_data(self):
        if self.state == 'init':
            self.buffer.read(3)
            self.transport.write(b'\5\0')
            self.state = 'authed'
        elif self.state == 'authed':
            ver, cmd, rsv = struct.unpack('!BBB', self.buffer.read(3))
            host = read_socks_host(self.buffer)  # raise InsufficientData
            port, = struct.unpack('!H', self.buffer.read(2))
            if cmd == Socks5Cmd.UDP_ASSOCIATE:
                self.handle_udp_associate(host, port)
            elif cmd == Socks5Cmd.CONNECT:
                self.handle_tcp_connect(host, port)
            else:
                raise NotImplementedError
        elif self.state == 'tcp_relay':
            self.tcp_relay_proto.transport.write(self.buffer.readall())
        else:
            logger.error('fake server unexpected data: %r', self.buffer.data)
            raise InsufficientData  # hacks

    def handle_udp_associate(self, client_host: SocksHost, client_port: int):
        logger.info('fake server udp associate. client: %s:%d', client_host, client_port)

        self.udp_relay_server_port = self.reactor.listenUDP(
            self.udp_relay_port, self.udp_relay_proto, interface=self.udp_relay_host,
        )
        reply = Socks5Reply(0, self.udp_relay_host, self.udp_relay_port)
        self.transport.write(reply.dumps())
        self.state = 'udp_relay'

    def handle_tcp_connect(self, host: SocksHost, port: int):
        def connected(ignore):
            taddr = self.tcp_relay_proto.transport.getHost()
            reply = Socks5Reply(0, ip_address(taddr.host), taddr.port)
            self.transport.write(reply.dumps())
            self.state = 'tcp_relay'
            self.data_processing_loop()    # state changed

        def failed(failure):
            logger.error('fake server tcp connect failed: %r', failure)
            reply = Socks5Reply(1, ip_address('0.0.0.0'), 0)
            self.transport.write(reply.dumps())
            self.state = 'failed'
            self.transport.loseConnection()

        logger.info('fake server connect to: %s:%d', host, port)

        endpoint = get_client_endpoint(self.reactor, (str(host), port))
        self.tcp_relay_proto = RelayProtocol(self.transport)
        d = connectProtocol(endpoint, self.tcp_relay_proto)
        d.addCallbacks(connected, failed)

        self.state = 'tcp_relay_setup'

    def connectionLost(self, reason=connectionDone):
        if self.tcp_relay_proto and self.tcp_relay_proto.transport:
            self.tcp_relay_proto.transport.loseConnection()

    def stop(self):
        dl = []
        if self.udp_relay_server_port:
            dl.append(defer.maybeDeferred(self.udp_relay_server_port.stopListening))
        if self.tcp_relay_proto and self.tcp_relay_proto.transport:
            dl.append(defer.maybeDeferred(self.tcp_relay_proto.transport.loseConnection))
        return defer.DeferredList(dl, fireOnOneErrback=True)


# noinspection PyAttributeOutsideInit
class FakeSocks5ControlServer(ServerFactory):
    def __init__(self, udp_relay_address):
        self.udp_relay_address = udp_relay_address

    def buildProtocol(self, addr):
        self.protocol_inst = FakeSocks5ControlServerProtocol(self.udp_relay_address)
        self.protocol_inst.factory = self
        return self.protocol_inst


class FakeUDPRelayServerProtocol(DatagramProtocol):
    def datagramReceived(self, datagram, addr):
        logger.info('fake udp relay received data from %r', addr)
        packet = UDPRelayPacket.loads(datagram)
        data = bytes(reversed(packet.data))
        response = UDPRelayPacket(packet.host, packet.port, data)
        self.transport.write(response.dumps(), addr)


# noinspection PyAttributeOutsideInit
class BaseTestUDPRelayIntegrated(unittest.TestCase):
    def setUp(self):
        self.reactor = get_reactor()

        self.setup_socks5_server()
        self.setup_target_service()
        self.setup_socks5_client()

        return self.relay_done

    def setup_socks5_server(self):
        raise NotImplementedError

    def setup_target_service(self):
        raise NotImplementedError

    def setup_socks5_client(self):
        self.relay_done = defer.maybeDeferred(self._setup_socks5_client)

    @defer.inlineCallbacks
    def _setup_socks5_client(self):
        proxy_endpoint = TCP4ClientEndpoint(
            self.reactor, self.proxy_host, self.proxy_port,
        )
        self.ctrl_proto = Socks5ControlProtocol()
        yield connectProtocol(proxy_endpoint, self.ctrl_proto)
        self.relay = UDPRelay(self.ctrl_proto)
        yield self.relay.setup_relay()
        return self.relay

    def tearDown(self):
        return self.relay.stop()

    def test_run(self):
        def check_result(respond):
            assert respond == b'olleh'

        user_proto = Greeter((self.service_host, self.service_port))
        self.relay.listenUDP(0x4321, user_proto)
        return user_proto.d.addCallback(check_result)


# noinspection PyAttributeOutsideInit
class TestUDPRelayWithFakeServer(BaseTestUDPRelayIntegrated):
    proxy_host = '127.0.0.4'
    proxy_port = 4444
    relay_address = ('127.0.0.8', 8888)

    def setup_socks5_server(self):
        self.server_ctrl_factory = FakeSocks5ControlServer(self.relay_address)
        self.server_ctrl_port = self.reactor.listenTCP(
            self.proxy_port, self.server_ctrl_factory, interface=self.proxy_host,
        )

    def setup_target_service(self):
        self.service_host, self.service_port = '127.0.0.66', 6666

    def tearDown(self):
        server_ctrl_proto = self.server_ctrl_factory.protocol_inst
        dl = [
            super().tearDown(),
            defer.maybeDeferred(self.server_ctrl_port.stopListening),
            server_ctrl_proto.stop(),
        ]
        return defer.DeferredList(dl, fireOnOneErrback=True)


# noinspection PyAttributeOutsideInit
class TestUDPRelayWithSS(BaseTestUDPRelayIntegrated):
    service_host = '127.0.0.40'
    service_port = 4444

    proxy_host, proxy_port = SSRunner.ss_client_host, SSRunner.ss_client_port

    @defer.inlineCallbacks
    def setUp(self):
        yield SSRunner.start()
        return (yield super(TestUDPRelayWithSS, self).setUp())

    def setup_socks5_server(self):
        pass

    def setup_target_service(self):
        self.reverser_transport = self.reactor.listenUDP(
            self.service_port, Reverser(), interface=self.service_host,
        )

    def tearDown(self):
        return defer.DeferredList([
            super().tearDown(),
            defer.maybeDeferred(self.reverser_transport.stopListening)
        ], fireOnOneErrback=True)


# noinspection PyAttributeOutsideInit
class TestGetUDPRelayWithSS(TestUDPRelayWithSS):
    def setup_socks5_client(self):
        proxy = SocksProxy(self.proxy_host, self.proxy_port, reactor=self.reactor)
        self.relay_done = proxy.get_udp_relay()
        self.relay_done.addCallback(lambda relay: setattr(self, 'relay', relay))


# noinspection PyAttributeOutsideInit
class TestResolverOverSocks(TestUDPRelayWithSS):
    def setup_resolver(self, resolver_cls: type):
        self.resolver = resolver_cls(
            servers=[(self.service_host, self.service_port)],
            socks_proxy=SocksProxy(self.proxy_host, self.proxy_port),
        )

    def setup_target_service(self):
        from dnsagent.config import server, hosts
        self.app = App()
        self.mapping = dict(asdf='1.2.3.4', b='::1')
        server_info = server(
            hosts(self.mapping), port=self.service_port, interface=self.service_host,
        )
        self.app.start(server_info)

    def setup_socks5_client(self):
        self.relay_done = defer.succeed(None)

    def tearDown(self):
        return self.app.stop()

    def run_test(self, resolver_cls: type):
        def check_a(result):
            ans, add, ns = result
            assert [ rrheader_to_ip(rr) for rr in ans ] == [ ip_address('1.2.3.4') ]
            assert add == ns == []

        self.setup_resolver(resolver_cls)
        return self.resolver.lookupAddress('asdf', timeout=[1]).addBoth(check_a)

    def test_resolve_over_udp(self):
        return self.run_test(ExtendedResolver)

    def test_resolve_over_tcp(self):
        # FIXME: this fails randomly on windows
        return self.run_test(TCPExtendedResolver)

    def test_run(self):
        """this test is splited."""


class TCPRelayConnectorWithFakeTranport(TCPRelayConnector):
    def _connect_control_protocol(self):
        assert self.ctrl_proto.transport is None
        self.ctrl_proto.makeConnection(FakeTransport(addr=self.proxy_addr))
        return defer.succeed(self.ctrl_proto)


class FakeClientFactory(ClientFactory):
    protocol = FakeProtocol
    connector = None
    started = False
    lost = False
    failed = False

    def startFactory(self):
        self.started = True

    def startedConnecting(self, connector):
        self.connector = connector

    def clientConnectionLost(self, connector, reason):
        assert connector is self.connector
        self.lost = True
        logger.info('clientConnectionLost, reason=%r', reason)

    def clientConnectionFailed(self, connector, reason):
        assert connector is self.connector
        self.failed = True
        logger.error('clientConnectionFailed, reason=%r', reason)

    def stopFactory(self):
        self.started = False


class ReconnectingFakeClientFactory(FakeClientFactory):
    failed_count = 0
    lost_count = 0

    def clientConnectionFailed(self, connector, reason):
        self.failed_count += 1
        connector.connect()

    def clientConnectionLost(self, connector, reason):
        self.lost_count += 1
        connector.connect()


# noinspection PyAttributeOutsideInit
class TestTCPRelayConnector(unittest.TestCase):
    def setUp(self):
        self.factory = FakeClientFactory()
        self.connector = TCPRelayConnectorWithFakeTranport(
            '1.2.3.4', 1234, self.factory, ('4.3.2.1', 4321),
        )

    def test_run(self):
        assert not self.factory.started
        assert self.factory.connector is None
        assert self.connector.state == 'disconnected'

        self.connector.connect()
        assert self.connector.state == 'connecting'
        assert self.factory.started                     # startFactory() called
        assert self.factory.connector is self.connector # startedConnecting() called

        ctrl_proto = self.connector.ctrl_proto  # type: Socks5ControlProtocol
        assert ctrl_proto.transport.write_logs.pop() == (b'\5\1\0', None)

        # authentication
        ctrl_proto.dataReceived(b'\5\0')
        assert ctrl_proto.transport.write_logs.pop() == (b'\5\1\0\1\1\2\3\4\x04\xd2', None)

        # reply to CONNECT request
        assert self.connector.state == 'connecting'
        assert self.connector.user_proto.transport is None
        ctrl_proto.dataReceived(Socks5Reply(0, ip_address('9.8.7.6'), 0x9876).dumps())
        assert self.connector.user_proto.transport is ctrl_proto.transport
        assert self.connector.state == 'connected'

        # send data through relay
        ctrl_proto.dataReceived(b'asdf')
        assert self.connector.user_proto.recv_logs.pop() == b'asdf'

        # close connection
        ctrl_proto.connectionLost(Failure(Exception('haha')))
        assert self.connector.user_proto.lost
        assert self.factory.lost            # clientConnectionLost() called
        assert not self.factory.started     # stopFactory() called
        assert self.connector.state == 'disconnected'

    def test_server_rejected(self):
        self.connector.connect()
        self.connector.ctrl_proto.dataReceived(b'\5\0')
        self.connector.ctrl_proto.dataReceived(
            Socks5Reply(1, ip_address('9.8.7.6'), 0x9876).dumps()
        )
        assert self.connector.state == 'disconnected'
        assert self.factory.failed
        assert not self.factory.started

    def test_auth_failed(self):
        self.connector.connect()
        self.connector.ctrl_proto.dataReceived(b'\5\xff')
        assert self.connector.state == 'disconnected'
        assert self.factory.failed
        assert not self.factory.started

    # TODO: test_connect_failed
    # TODO: test factory.buildProtocol() returns None

    def test_stopConnecting(self):
        self.connector.connect()
        self.connector.ctrl_proto.dataReceived(b'\5\0')
        assert self.connector.state == 'connecting'

        tr = self.connector.ctrl_proto.transport
        self.connector.stopConnecting()
        assert self.connector.state == 'disconnected'
        assert self.connector.ctrl_proto.transport is self.connector.user_proto.transport is None
        assert not tr.connected

    def test_stopConecting_reconnect(self):
        self.connector.connect()
        self.connector.ctrl_proto.dataReceived(b'\5\0')
        self.connector.stopConnecting()

        # reconnect
        self.connector.connect()
        self.connector.ctrl_proto.dataReceived(b'\5\0')
        self.connector.ctrl_proto.dataReceived(
            Socks5Reply(0, ip_address('9.8.7.6'), 0x9876).dumps()
        )
        assert self.connector.state == 'connected'
        assert self.connector.user_proto.transport is self.connector.ctrl_proto.transport

    def test_reconnecting_from_client_factory(self):
        self.factory = ReconnectingFakeClientFactory()
        self.connector = TCPRelayConnectorWithFakeTranport(
            '1.2.3.4', 1234, self.factory, ('4.3.2.1', 4321),
        )
        self.connector.connect()

        # clientConnectionFailed()
        self.connector.ctrl_proto.dataReceived(b'\5\xff')
        assert self.factory.failed_count == 1
        assert self.connector.state == 'connecting'
        assert self.factory.started

        self.connector.ctrl_proto.dataReceived(b'\5\0')
        self.connector.ctrl_proto.dataReceived(
            Socks5Reply(0, ip_address('9.8.7.6'), 0x9876).dumps()
        )
        assert self.connector.state == 'connected'

        # clientConnectionLost()
        self.connector.ctrl_proto.connectionLost(Failure(Exception('hahaha')))
        assert self.factory.lost_count == 1
        assert self.connector.state == 'connecting'
        assert self.factory.started

    def test_disconnect(self):
        self.connector.connect()
        self.connector.ctrl_proto.dataReceived(b'\5\0')
        self.connector.ctrl_proto.dataReceived(
            Socks5Reply(0, ip_address('9.8.7.6'), 0x9876).dumps()
        )
        assert self.connector.state == 'connected'

        tr = self.connector.ctrl_proto.transport
        self.connector.disconnect()
        assert self.connector.state == 'disconnected'
        assert not tr.connected
        assert self.connector.ctrl_proto.transport is self.connector.user_proto.transport is None


class BaseTestSocksProxyTCP(unittest.TestCase):
    service_host = '127.0.0.1'
    service_port = 10111

    socks_host = '127.0.0.200'
    socks_port = 20000

    def setUp(self):
        self.reactor = get_reactor()

        return defer.DeferredList([
            self.setup_service(),
            self.setup_socks(),
        ], fireOnOneErrback=True)

    def tearDown(self):
        return defer.DeferredList([
            defer.maybeDeferred(self.teardown_service),
            defer.maybeDeferred(self.teardown_socks),
        ], fireOnOneErrback=True)

    def _listen_protocol(self, protocol: Protocol, host: str, port: int, name: str):
        def got_transport(transport):
            setattr(self, name + '_transport', transport)
            return transport

        setattr(self, name + '_proto', protocol)
        endpoint = self._get_server_endpoint(host, port)
        d = endpoint.listen(OneshotServerFactory(protocol))
        d.addCallback(got_transport)
        return d

    def _get_server_endpoint(self, host, port):
        return TCP4ServerEndpoint(self.reactor, port, interface=host)

    def setup_service(self, protocol: Protocol = None):
        protocol = protocol or TCPReverser()
        return self._listen_protocol(protocol, self.service_host, self.service_port, 'service')

    def teardown_service(self):
        dl = [defer.maybeDeferred(self.service_transport.stopListening)]
        if getattr(self.service_proto, 'transport', None):
            dl.append(defer.maybeDeferred(self.service_proto.transport.loseConnection))
        return defer.DeferredList(dl, fireOnOneErrback=True)

    def setup_socks(self):
        raise NotImplementedError

    def teardown_socks(self):
        raise NotImplementedError

    def test_run(self):
        def got_reply(reply: bytes):
            try:
                assert reply == b'olleh'
            finally:
                connector.disconnect()

        proto = TCPGreeter()
        proxy = SocksProxy(self.socks_host, self.socks_port, reactor=self.reactor)
        connector = self._connect_client_factory(
            proxy, self.service_host, self.service_port, OneshotClientFactory(proto),
        )

        proto.d.addCallback(got_reply)
        return proto.d

    def _connect_client_factory(self, proxy: SocksProxy, host, port, factory):
        return proxy.connectTCP(host, port, factory)


class TestSocksProxyTCPWithFakeServer(BaseTestSocksProxyTCP):
    def setup_socks(self):
        proto = FakeSocks5ControlServerProtocol(('0.0.0.0', 1234), reactor=self.reactor)
        return self._listen_protocol(proto, self.socks_host, self.socks_port, 'socks')

    def teardown_socks(self):
        return self.socks_transport.stopListening()


class TestSocksProxyTCPWithSS(BaseTestSocksProxyTCP):
    def setup_socks(self):
        self.socks_host, self.socks_port = SSRunner.ss_client_host, SSRunner.ss_client_port
        return SSRunner.start()

    def teardown_socks(self):
        pass


class TestSocksProxyConnectSSL(TestSocksProxyTCPWithSS):
    _module_dir = getModule(__name__).filePath.dirname()
    key_path = os.path.join(_module_dir, 'privkey.pem')
    ca_path = os.path.join(_module_dir, 'cacert.pem')
    ssl_ctx_factory = ssl.DefaultOpenSSLContextFactory(key_path, ca_path)

    def _get_server_endpoint(self, host, port):
        return SSL4ServerEndpoint(self.reactor, port, self.ssl_ctx_factory, interface=host)

    def _connect_client_factory(self, proxy: SocksProxy, host, port, factory):
        return proxy.connectSSL(host, port, factory, self.ssl_ctx_factory)


class WebResource(Resource):
    isLeaf = True

    def render_GET(self, request):
        return b'hello'


class ProtocolTracedSite(Site):
    _protocols = []

    def buildProtocol(self, addr):
        proto = super().buildProtocol(addr)
        self._protocols.append(proto)
        return proto


class TestSocksProxyWithTreq(TestSocksProxyConnectSSL):
    def setUp(self):
        from twisted.internet._sslverify import OpenSSLCertificateAuthorities

        with open(self.ca_path, 'rb') as fp:
            cacert = ssl.Certificate.loadPEM(fp.read()).original
        trust_root = OpenSSLCertificateAuthorities([cacert])
        self.https_policy = BrowserLikePolicyForHTTPS(trust_root)

        return super().setUp()

    def setup_service(self, protocol=None):
        def got_transport(transport):
            self.service_transport = transport
            return transport

        endpoint = self._get_server_endpoint(self.service_host, self.service_port)
        site = ProtocolTracedSite(WebResource())
        self.service_protocols = site._protocols
        d = endpoint.listen(site)
        d.addCallback(got_transport)
        return d

    def teardown_service(self):
        assert len(self.service_protocols) == 1
        self.service_proto = self.service_protocols.pop()
        return super().teardown_service()

    def test_run(self):
        def check(text: str):
            assert text == 'hello'

        def restore_resolver(ignore):
            self.reactor.installResolver(origin_resolver)
            return ignore

        hostname = 'dnsagent.test'
        resolver = HostsResolver(mapping={hostname: self.service_host})
        origin_resolver = self.reactor.installResolver(resolver)

        url = 'https://%s:%d/' % (hostname, self.service_port)
        proxy = SocksWrappedReactor(self.socks_host, self.socks_port, reactor=self.reactor)
        agent = Agent(reactor=proxy, contextFactory=self.https_policy)
        treq = get_treq()
        d = treq.get(url, agent=agent)
        d.addCallback(treq.text_content)
        d.addCallback(check)
        d.addBoth(restore_resolver)
        return d


def tearDownModule():
    SSRunner.shutdown()


del BaseTestUDPRelayIntegrated
del BaseTestSocksProxyTCP
