import struct
import subprocess
from io import BytesIO
from ipaddress import ip_address
import logging

import psutil
import pytest
from twisted.trial import unittest
from twisted.python.failure import Failure
from twisted.internet import defer
from twisted.internet import address as taddress
from twisted.internet.error import CannotListenError
from twisted.internet.protocol import (
    DatagramProtocol, Protocol, ServerFactory, connectionDone, ClientFactory,
)
from twisted.internet.endpoints import TCP4ClientEndpoint, TCP4ServerEndpoint, connectProtocol

from dnsagent.app import App
from dnsagent.resolver.basic import ResolverOverSocks
from dnsagent.socks import (
    read_socks_host, encode_socks_host, SocksHost, BadSocksHost, InsufficientData,
    Socks5Reply, BadSocks5Reply, to_twisted_addr,
    UDPRelayPacket, BadUDPRelayPacket, UDPRelayProtocol, UDPRelayTransport,
    Socks5ControlProtocol, Socks5Cmd, UDPRelay, get_udp_relay, get_client_endpoint,
    TCPRelayConnector,
)
from dnsagent.utils import rrheader_to_ip


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

    data = b'\5\1\0\1\x7f\0\0\1\x12\x34'
    for i in range(len(data) - 1):
        E(data[:i], InsufficientData)
    R(data, 1, ip_address('127.0.0.1'), 0x1234)

    E(b'\4\0\0\1\x7f\0\0\1\x12\x34', BadSocks5Reply)
    E(b'\5\0\1\1\x7f\0\0\1\x12\x34', BadSocks5Reply)
    E(b'\5\0\1\5\x7f\0\0\1\x12\x34', BadSocks5Reply)


def test_socks5_reply_dumps():
    def R(reply: int, host: SocksHost, port: int, answer: bytes):
        assert Socks5Reply(reply, host, port).dumps() == answer

    R(0, 'asdf', 0x1234, b'\5\0\0\3\4asdf\x12\x34')
    R(1, ip_address('1.2.3.4'), 0x1234, b'\5\1\0\1\1\2\3\4\x12\x34')


class FakeTransport:
    def __init__(self, addr=('8.7.6.5', 8765)):
        self.write_logs = []
        self.connected = True
        self.addr = addr

    def write(self, data, addr=None):
        self.write_logs.append((data, addr))

    def loseConnection(self):
        assert self.connected
        self.connected = False

    stopListening = loseConnection

    def getHost(self):
        return to_twisted_addr(*self.addr, type_='TCP')

    def poplogs(self):
        logs = self.write_logs
        self.write_logs = []
        return logs


class FakeDatagramProtocol(DatagramProtocol):
    def __init__(self):
        self.data_logs = []

    def datagramReceived(self, datagram: bytes, addr):
        self.data_logs.append((datagram, addr))


class FakeProtocol(Protocol):
    def __init__(self):
        self.recv_logs = []

    def dataReceived(self, data):
        self.recv_logs.append(data)


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

        if reactor is None:
            from twisted.internet import reactor
        self.reactor = reactor

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
        return defer.DeferredList(dl)


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
        server_ctrl_proto = self.server_ctrl_factory.protocol_inst
        dl = [
            super().tearDown(),
            defer.maybeDeferred(self.server_ctrl_port.stopListening),
            server_ctrl_proto.stop(),
        ]
        return defer.DeferredList(dl)


# noinspection PyAttributeOutsideInit
class TestUDPRelayWithSS(BaseTestUDPRelayIntegrated):
    ss_server_host = '127.0.0.20'
    ss_server_port = 2222
    ss_client_host = '127.0.0.30'
    ss_client_port = 3333
    ss_passwd = '123'
    service_host = '127.0.0.40'
    service_port = 4444

    ss_server = None
    ss_local = None

    def setUp(self):
        d = defer.Deferred()
        ss_d = self.setup_ss()
        ss_d.addCallback(
            lambda ignore: super(TestUDPRelayWithSS, self).setUp().chainDeferred(d)
        ).addErrback(d.errback)
        return d

    @classmethod
    def setup_ss(cls):
        if cls.ss_server is None:
            cls.ss_server = subprocess.Popen([
                'ssserver', '-s', cls.ss_server_host, '-p', str(cls.ss_server_port),
                '-k', cls.ss_passwd, '--forbidden-ip', '',
            ])
            cls.ss_local = subprocess.Popen([
                'sslocal', '-s', cls.ss_server_host, '-p', str(cls.ss_server_port),
                '-b', cls.ss_client_host, '-l', str(cls.ss_client_port), '-k', cls.ss_passwd,
            ])

            cls.proxy_host, cls.proxy_port = cls.ss_client_host, cls.ss_client_port
            return cls.wait_for_ss()
        else:
            return defer.succeed(None)

    @classmethod
    def wait_for_ss(cls, times=20, timeout=0.2, d=None):
        def connected(result):
            protocol.transport.loseConnection()
            d.callback(None)
            return result

        def failed(ignore):
            logger.debug('testing sslocal failed: times=%d', times)
            reactor.callLater(
                timeout,
                cls.wait_for_ss, times=(times - 1), timeout=timeout, d=d,
            )

        from twisted.internet import reactor
        d = d or defer.Deferred()

        if times <= 0:
            d.errback(Exception('sslocal not started'))
        else:
            protocol = Protocol()
            connect_d = connectProtocol(
                get_client_endpoint(
                    reactor, (cls.proxy_host, cls.proxy_port), timeout=timeout),
                protocol,
            )
            connect_d.addCallbacks(connected, failed)

        return d

    def setup_socks5_server(self):
        pass

    def setup_target_service(self):
        self.reverser_transport = self.reactor.listenUDP(
            self.service_port, Reverser(), interface=self.service_host,
        )

    @classmethod
    def shutdown_ss(cls):
        def kill_proc_tree(pid):
            parent = psutil.Process(pid)
            children = parent.children(recursive=True)
            for child in children:
                child.kill()
            psutil.wait_procs(children, timeout=2)

            try:
                parent.kill()
                parent.wait(2)
            except Exception:
                logger.exception('failed to kill process: %d', pid)

        for popen in (cls.ss_server, cls.ss_local):
            if popen.returncode is None:
                kill_proc_tree(popen.pid)

    def tearDown(self):
        return defer.DeferredList([
            super().tearDown(),
            defer.maybeDeferred(self.reverser_transport.stopListening)
        ])


# noinspection PyAttributeOutsideInit
class TestGetUDPRelayWithSS(TestUDPRelayWithSS):
    def setup_socks5_client(self):
        self.relay_done = get_udp_relay(
            (self.proxy_host, self.proxy_port), reactor=self.reactor,
        )
        self.relay_done.addCallback(lambda relay: setattr(self, 'relay', relay))


class TestResolverOverSocks(TestUDPRelayWithSS):
    def setUp(self):
        def set_resolver(ignore):
            self.resolver = ResolverOverSocks(
                servers=[(self.service_host, self.service_port)],
                socks_proxy_addr=(self.proxy_host, self.proxy_port),
            )
            return ignore
        return super().setUp().addCallback(set_resolver)

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

    def test_run(self):
        def check_a(result):
            ans, add, ns = result
            assert [ rrheader_to_ip(rr) for rr in ans ] == [ ip_address('1.2.3.4') ]
            assert add == ns == []

        return self.resolver.lookupAddress('asdf', timeout=[1]).addBoth(check_a)


class TestableTCPRelayConnector(TCPRelayConnector):
    def _connect_control_protocol(self, errback):
        assert self.ctrl_proto.transport is None
        self.ctrl_proto.makeConnection(FakeTransport(addr=self.proxy_addr))


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


class TestTCPRelayConnector(unittest.TestCase):
    def setUp(self):
        self.factory = FakeClientFactory()
        self.connector = TestableTCPRelayConnector(
            '1.2.3.4', 1234, self.factory, ('4.3.2.1', 4321),
        )

    def test_run(self):
        assert not self.factory.started
        assert self.factory.connector is None
        self.connector.connect()
        assert self.factory.started                     # startFactory() called
        assert self.factory.connector is self.connector # startedConnecting() called

        ctrl_proto = self.connector.ctrl_proto  # type: Socks5ControlProtocol
        assert ctrl_proto.transport.write_logs.pop() == (b'\5\1\0', None)

        # authentication
        ctrl_proto.dataReceived(b'\5\0')
        assert ctrl_proto.transport.write_logs.pop() == (b'\5\1\0\1\1\2\3\4\x04\xd2', None)

        # reply to CONNECT request
        assert self.connector.user_proto.transport is None
        ctrl_proto.dataReceived(Socks5Reply(0, ip_address('9.8.7.6'), 0x9876).dumps())
        assert self.connector.user_proto.transport is ctrl_proto.transport

        # send data through relay
        ctrl_proto.dataReceived(b'asdf')
        assert self.connector.user_proto.recv_logs.pop() == b'asdf'

        # close connection
        ctrl_proto.connectionLost(Failure(Exception('haha')))
        assert self.factory.lost            # clientConnectionLost() called
        assert not self.factory.started     # stopFactory() called

    def test_server_rejected(self):
        self.connector.connect()
        self.connector.ctrl_proto.dataReceived(b'\5\0')
        self.connector.ctrl_proto.dataReceived(
            Socks5Reply(1, ip_address('9.8.7.6'), 0x9876).dumps()
        )
        assert self.factory.failed
        assert not self.factory.started

    def test_auth_failed(self):
        self.connector.connect()
        self.connector.ctrl_proto.dataReceived(b'\5\xff')
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
        self.connector = TestableTCPRelayConnector(
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
        assert not tr.connected
        assert self.connector.ctrl_proto.transport is self.connector.user_proto.transport is None


class TestTCPRelayConnectorWithFakeServer(unittest.TestCase):
    service_host = '127.0.0.100'
    service_port = 10000
    service_transport = None

    server_host = '127.0.0.200'
    server_port = 20000
    server_transport = None

    def setUp(self):
        from twisted.internet import reactor
        self.reactor = reactor

        return defer.DeferredList([
            self.setup_service(),
            self.setup_server(),
        ])

    def tearDown(self):
        return defer.DeferredList([
            self.teardown_service(),
            self.teardown_server(),
        ])

    def setup_service(self):
        proto = TCPReverser()
        return self._listen_protocol(proto, self.service_host, self.service_port, 'service')

    def teardown_service(self):
        return defer.maybeDeferred(self.service_transport.stopListening)

    def setup_server(self):
        proto = FakeSocks5ControlServerProtocol(('0.0.0.0', 1234), reactor=self.reactor)
        return self._listen_protocol(proto, self.server_host, self.server_port, 'server')

    def teardown_server(self):
        return defer.maybeDeferred(self.server_transport.stopListening)

    def _listen_protocol(self, protocol: Protocol, host: str, port: int, name: str):
        def got_transport(transport):
            setattr(self, name + '_transport', transport)
            return transport

        setattr(self, name + '_proto', protocol)
        endpoint = TCP4ServerEndpoint(self.reactor, port, interface=host)
        d = endpoint.listen(OneshotServerFactory(protocol))
        d.addCallback(got_transport)
        return d

    def test_run(self):
        def got_reply(reply: bytes):
            try:
                assert reply == b'olleh'
            finally:
                connector.disconnect()
                # FIXME: workaround to strange error
                # twisted.trial.util.DirtyReactorAggregateError: Reactor was unclean.
                # Selectables:
                # <TCPReverser #0 on 10000>
                self.teardown_service().chainDeferred(d)

        proto = TCPGreeter()
        connector = TCPRelayConnector(
            self.service_host, self.service_port, OneshotClientFactory(proto),
            proxy_addr=(self.server_host, self.server_port), reactor=self.reactor,
        )
        connector.connect()

        d = defer.Deferred()
        proto.d.addCallback(got_reply).addErrback(d.errback)
        return d


class Reverser(DatagramProtocol):
    def datagramReceived(self, datagram, addr):
        data = bytes(reversed(datagram))
        self.transport.write(data, addr)


class TCPReverser(Protocol):
    def dataReceived(self, data):
        data = bytes(reversed(data))
        self.transport.write(data)


class OneshotServerFactory(ServerFactory):
    def __init__(self, protocol: Protocol):
        self.proto = protocol

    def buildProtocol(self, addr):
        return self.proto


class Greeter(DatagramProtocol):
    def __init__(self, dest_addr):
        self.dest_addr = dest_addr
        self.d = defer.Deferred()

    def startProtocol(self):
        self.transport.connect(*self.dest_addr)
        self.transport.write(b'hello')

    def datagramReceived(self, datagram, addr):
        self.d.callback(datagram)


class TCPGreeter(Protocol):
    def __init__(self):
        self.d = defer.Deferred()

    def connectionMade(self):
        self.transport.write(b'hello')

    def dataReceived(self, data):
        self.d.callback(data)


class OneshotClientFactory(ClientFactory):
    def __init__(self, protocol: Protocol):
        self.proto = protocol

    def buildProtocol(self, addr):
        self.proto.factory = self
        return self.proto


def tearDownModule():
    if TestUDPRelayWithSS.ss_local is not None:
        TestUDPRelayWithSS.shutdown_ss()


del BaseTestUDPRelayIntegrated
