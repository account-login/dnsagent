import struct
import subprocess
from io import BytesIO
from ipaddress import ip_address
import logging
import random

import pytest
from twisted.trial import unittest
from twisted.python.failure import Failure
from twisted.internet import defer
from twisted.internet.error import CannotListenError
from twisted.internet.protocol import DatagramProtocol, Protocol, ServerFactory
from twisted.internet.endpoints import TCP4ClientEndpoint, connectProtocol

from dnsagent.socks import (
    read_socks_host, encode_socks_host, BadSocksHost, InsufficientData,
    UDPRelayPacket, BadUDPRelayPacket, UDPRelayProtocol, UDPRelayTransport,
    Socks5ControlProtocol, UDPRelay, get_udp_relay,
)


logger = logging.getLogger(__name__)


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


class FakeTransport:
    def __init__(self):
        self.write_logs = []
        self.connected = True

    def write(self, data, addr=None):
        self.write_logs.append((data, addr))

    def loseConnection(self):
        assert self.connected
        self.connected = False

    stopListening = loseConnection

    def poplogs(self):
        logs = self.write_logs
        self.write_logs = []
        return logs


class FakeDatagramProtocol(DatagramProtocol):
    def __init__(self):
        self.data_logs = []

    def datagramReceived(self, datagram: bytes, addr):
        self.data_logs.append((datagram, addr))


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

    def feed(self, data: bytes, expected_status: str):
        assert self.ctrl_proto.status == expected_status
        for i in range(len(data)):
            self.ctrl_proto.dataReceived(b'')
            assert self.ctrl_proto.status == expected_status
            self.ctrl_proto.dataReceived(data[i:(i + 1)])
            if i < len(data) - 1:
                assert self.ctrl_proto.status == expected_status

    def test_greeting_success(self):
        assert self.ctrl_proto.status == 'greeted'
        assert self.transport.write_logs.pop() == (b'\x05\x01\x00', None)

        self.feed(b'\x05\x00', 'greeted')
        assert self.ctrl_proto.status == 'authed'
        assert self.auth_result is self.ctrl_proto
        assert self.ctrl_proto.data == b''

    def test_greeting_server_fail(self):
        self._run_greeting_failure_test(b'\x05\xff')

    def test_greeting_protocol_fail(self):
        self._run_greeting_failure_test(b'\x04\x00')

    def _run_greeting_failure_test(self, data: bytes):
        self.feed(data, 'greeted')
        assert self.ctrl_proto.status == 'failed'
        assert isinstance(self.auth_result, Failure)
        assert self.ctrl_proto.data == b''

    def test_udp_associate_request(self):
        self.ctrl_proto.dataReceived(b'\x05\x00')
        d = self.ctrl_proto.request_udp_associate(ip_address('1.2.3.4'), 0x1234)
        assert self.ctrl_proto.status == 'udp_req'
        assert self.transport.write_logs.pop() == (b'\x05\x03\0\x01\1\2\3\4\x12\x34', None)
        assert d is self.ctrl_proto.request_defer

    def test_udp_associate_success(self):
        self.ctrl_proto.dataReceived(b'\x05\x00')
        d = self.ctrl_proto.request_udp_associate(ip_address('1.2.3.4'), 0x1234)
        self.feed(b'\5\0\0\x01\2\3\4\5\x23\x45', 'udp_req')
        assert self.ctrl_proto.status == 'success'

        def udp_reqed(arg):
            assert arg == (ip_address('2.3.4.5'), 0x2345)
            assert self.ctrl_proto.data == b''

        return d.addBoth(udp_reqed)

    def test_udp_associate_server_fail(self):
        d = self._run_udp_associate_failure_test(b'\5\x01\0\x01\2\3\4\5\x23\x45', 'req_failed')
        assert self.transport.connected
        return d

    def test_udp_associate_protocol_fail(self):
        d = self._run_udp_associate_failure_test(b'\5\0\0\x08\2\3\4\5\x23\x45', 'failed')
        return d

    def _run_udp_associate_failure_test(self, data, status):
        def udp_reqed(arg):
            assert isinstance(arg, Failure)
            assert self.ctrl_proto.data == b''

        self.ctrl_proto.dataReceived(b'\x05\x00')
        d = self.ctrl_proto.request_udp_associate(ip_address('1.2.3.4'), 0x1234)
        d.addBoth(udp_reqed)

        self.ctrl_proto.dataReceived(data)
        assert d.called
        assert self.ctrl_proto.status == status
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

    def test_auth_failed(self):
        self.ctrl_proto.dataReceived(b'\5\xff')
        assert isinstance(self.relay_setup_result, Failure)
        return self.relay.stop()

    def test_udp_associate_failed(self):
        self.ctrl_proto.dataReceived(b'\5\0')
        self.ctrl_proto.dataReceived(b'\5\x01\0\x01\2\3\4\5\x23\x45')
        assert not self.relay.relay_done
        assert isinstance(self.relay_setup_result, Failure)
        return self.relay.stop()

    def test_udp_associate_success(self):
        self.ctrl_proto.dataReceived(b'\5\0')
        self.ctrl_proto.dataReceived(b'\5\0\0\x01\x7f\0\0\x08\x23\x45')
        assert self.relay.relay_done
        assert self.relay_setup_result == (ip_address('127.0.0.8'), 0x2345)
        return self.relay.stop()

    def test_listenUDP(self):
        self.ctrl_proto.dataReceived(b'\5\0')
        self.ctrl_proto.dataReceived(b'\5\0\0\x01\x7f\0\0\x08\x23\x45')

        greet_to = ('4.3.2.1', 0x4321)
        user_proto = Greeter(greet_to)
        port = self.relay.listenUDP(0x1234, user_proto)
        assert user_proto.transport is port
        assert self.relay.relay_proto.user_protocol is user_proto
        assert self.relay.listening_port is port

        return self.relay.stop()

    def test_listenUDP_can_not_listen(self):
        for data in (b'', b'\5\0', b'\5\1\0\x01\2\3\4\5\x23\x45'):
            self.ctrl_proto.dataReceived(data)
            with pytest.raises(CannotListenError):
                self.relay.listenUDP(0x1234, Greeter(('4.3.2.1', 0x4321)))

        return self.relay.stop()

    def test_listenUDP_can_not_listen_more_than_once(self):
        self.ctrl_proto.dataReceived(b'\5\0')
        self.ctrl_proto.dataReceived(b'\5\0\0\x01\x7f\0\0\x08\x23\x45')
        self.relay.listenUDP(0x1234, FakeDatagramProtocol())
        with pytest.raises(RuntimeError):
            self.relay.listenUDP(0x2345, FakeDatagramProtocol())

        return self.relay.stop()


# noinspection PyAttributeOutsideInit
class FakeSocks5ControlServerProtocol(Protocol):
    def __init__(self, relay_address, reactor=None):
        self.relay_host, self.relay_port = relay_address
        self.relay_proto = FakeUDPRelayServerProtocol()
        self.relay_server_port = None
        if reactor is None:
            from twisted.internet import reactor
        self.reactor = reactor

    def connectionMade(self):
        self.state = 'init'

    def dataReceived(self, data):
        if self.state == 'init':
            assert len(data) == 3
            self.transport.write(b'\5\0')
            self.state = 'authed'
        elif self.state == 'authed':
            bio = BytesIO(data)
            assert len(bio.read(3)) == 3
            host = read_socks_host(bio)
            port = struct.unpack('!H', bio.read(2))[0]
            logger.info('client_host: %s, client_port: %d', host, port)

            self.relay_server_port = self.reactor.listenUDP(
                self.relay_port, self.relay_proto, interface=self.relay_host,
            )
            data = (
                b'\5\0\0'
                + encode_socks_host(ip_address(self.relay_host))
                + struct.pack('!H', self.relay_port))
            self.transport.write(data)
            self.state = 'success'


# noinspection PyAttributeOutsideInit
class FakeSocks5ControlServer(ServerFactory):
    def __init__(self, relay_address):
        self.relay_address = relay_address

    def buildProtocol(self, addr):
        self.protocol_inst = FakeSocks5ControlServerProtocol(self.relay_address)
        self.protocol_inst.factory = self
        return self.protocol_inst


class FakeUDPRelayServerProtocol(DatagramProtocol):
    def datagramReceived(self, datagram, addr):
        logger.info('relay received data from %r', addr)
        packet = UDPRelayPacket.loads(datagram)
        data = bytes(reversed(packet.data))
        response = UDPRelayPacket(packet.host, packet.port, data)
        self.transport.write(response.dumps(), addr)


# noinspection PyAttributeOutsideInit
class BaseTestUDPRelayIntegrated(unittest.TestCase):
    def setUp(self):
        from twisted.internet import reactor
        self.reactor = reactor

        self.setup_socks5_server()
        self.setup_target_service()
        self.setup_socks5_client()

        return self.relay_done

    def setup_socks5_server(self):
        raise NotImplementedError

    def setup_target_service(self):
        raise NotImplementedError

    def setup_socks5_client(self):
        def proxy_connected(ignore):
            assert not isinstance(ignore, Failure)
            d = self.ctrl_proto.get_udp_relay()
            d.addCallbacks(got_relay, self.relay_done.errback)

        def got_relay(relay):
            assert isinstance(relay, UDPRelay)
            self.relay = relay
            self.relay_done.callback(relay)

        self.relay_done = defer.Deferred()
        proxy_endpoint = TCP4ClientEndpoint(
            self.reactor, self.proxy_host, self.proxy_port,
        )
        self.ctrl_proto = Socks5ControlProtocol()
        ctrl_connected = connectProtocol(proxy_endpoint, self.ctrl_proto)
        ctrl_connected.addCallbacks(proxy_connected, self.relay_done.errback)

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
        relay_server_port = self.server_ctrl_factory.protocol_inst.relay_server_port
        dl = [
            super().tearDown(),
            defer.maybeDeferred(self.server_ctrl_port.stopListening),
            defer.maybeDeferred(relay_server_port.stopListening)
        ]
        return defer.DeferredList(dl)


# noinspection PyAttributeOutsideInit
class TestUDPRelayWithSS(BaseTestUDPRelayIntegrated):
    ss_server_host = '127.0.0.20'
    ss_server_port = 2200 + random.randrange(100)
    ss_client_host = '127.0.0.30'
    ss_client_port = 3300 + random.randrange(100)
    ss_passwd = '123'
    service_host = '127.0.0.10'
    service_port = 1100 + random.randrange(100)

    @classmethod
    def setUpClass(cls):
        cls.ss_server = subprocess.Popen([
            'ssserver', '-s', cls.ss_server_host, '-p', str(cls.ss_server_port),
            '-k', cls.ss_passwd, '--forbidden-ip', '',
        ])
        cls.ss_local = subprocess.Popen([
            'sslocal', '-s', cls.ss_server_host, '-p', str(cls.ss_server_port),
            '-b', cls.ss_client_host, '-l', str(cls.ss_client_port), '-k', cls.ss_passwd,
        ])

        cls.proxy_host, cls.proxy_port = cls.ss_client_host, cls.ss_client_port

    @classmethod
    def tearDownClass(cls):
        cls.ss_server.terminate()
        cls.ss_local.terminate()

    def setup_socks5_server(self):
        pass

    def setup_target_service(self):
        self.reverser_transport = self.reactor.listenUDP(
            self.service_port, Reverser(), interface=self.service_host,
        )

    def tearDown(self):
        dl = [ super().tearDown(), defer.maybeDeferred(self.reverser_transport.stopListening) ]
        return defer.DeferredList(dl)


# noinspection PyAttributeOutsideInit
class TestGetUDPRelayWithSS(TestUDPRelayWithSS):
    def setup_socks5_client(self):
        self.relay_done = get_udp_relay(
            (self.proxy_host, self.proxy_port), reactor=self.reactor,
        )
        self.relay_done.addCallback(lambda relay: setattr(self, 'relay', relay))


class Reverser(DatagramProtocol):
    def datagramReceived(self, datagram, addr):
        data = bytes(reversed(datagram))
        self.transport.write(data, addr)


# noinspection PyAttributeOutsideInit
class Greeter(DatagramProtocol):
    def __init__(self, dest_addr):
        self.dest_addr = dest_addr

    def startProtocol(self):
        self.transport.connect(*self.dest_addr)
        self.transport.write(b'hello')
        self.d = defer.Deferred()

    def datagramReceived(self, datagram, addr):
        self.d.callback(datagram)


del BaseTestUDPRelayIntegrated
