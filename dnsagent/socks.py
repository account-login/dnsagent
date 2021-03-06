import logging
import socket
import struct
from enum import IntEnum
from io import BytesIO
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import NamedTuple, Union, Optional, Tuple

from twisted.internet import defer, ssl
from twisted.internet.endpoints import connectProtocol
from twisted.internet.error import MessageLengthError, CannotListenError
from twisted.internet.interfaces import (
    IListeningPort, IUDPTransport, IReactorUDP, IReactorTCP, IConnector, IReactorSSL,
)
from twisted.internet.protocol import DatagramProtocol, Protocol, connectionDone, ClientFactory
from twisted.python.failure import Failure
from zope.interface import implementer

from dnsagent.utils import (
    get_reactor, get_client_endpoint, to_twisted_addr,
    patch_twisted_ssl_root_bug, sequence_deferred_call,
)

# TODO: timeout?


logger = logging.getLogger(__name__)


SocksHost = Union[IPv4Address, IPv6Address, str]


class BadSocksHost(Exception):
    pass


class InsufficientData(EOFError):
    pass


class SocksError(Exception):
    pass


class BadSocks5Reply(SocksError):
    pass


class BadSocksVersion(SocksError):
    pass


class UnsupportedAuthMethod(SocksError):
    pass


def to_socks_host(host: str) -> SocksHost:
    try:
        return ip_address(host)
    except ValueError:
        return host

def read_socks_host(data: BytesIO) -> SocksHost:
    atyp = data.read(1)
    if not atyp:
        raise InsufficientData('socks addr ATYP')

    if atyp == b'\x01':
        octets = data.read(4)
        if len(octets) != 4:
            raise InsufficientData('socks addr ipv4')
        return IPv4Address(socket.inet_ntop(socket.AF_INET, octets))
    elif atyp == b'\x03':
        dlen_byte = data.read(1)
        if not dlen_byte:
            raise InsufficientData('socks addr domain length')
        dlen, = struct.unpack('B', dlen_byte)
        if dlen == 0:
            raise BadSocksHost('domain length is zero')
        domain = data.read(dlen)
        if len(domain) != dlen:
            raise InsufficientData('socks addr domain name')
        return domain.decode('latin1')
    elif atyp == b'\x04':
        octets = data.read(16)
        if len(octets) != 16:
            raise InsufficientData('socks addr ipv6')
        return IPv6Address(socket.inet_ntop(socket.AF_INET6, octets))
    else:
        raise BadSocksHost('unknown ATYP: %r' % atyp)


def encode_socks_host(host: SocksHost) -> bytes:
    if isinstance(host, IPv4Address):
        return b'\x01' + socket.inet_pton(socket.AF_INET, str(host))
    elif isinstance(host, IPv6Address):
        return b'\x04' + socket.inet_pton(socket.AF_INET6, str(host))
    else:
        return b'\x03' + struct.pack('B', len(host)) + host.encode('latin1')


class BadUDPRelayPacket(Exception):
    pass


_UDPRelayPacketBase = NamedTuple(
    'UDPRelayPacket',
    [('host', SocksHost), ('port', int), ('data', bytes)]
)


class UDPRelayPacket(_UDPRelayPacketBase):
    @classmethod
    def loads(cls, data: bytes) -> 'UDPRelayPacket':
        bio = BytesIO(data)
        rsv = bio.read(2)
        if rsv != b'\0\0':
            raise BadUDPRelayPacket('bad UDP request header. RSV: %r' % rsv)

        frag = bio.read(1)
        if frag != b'\0':
            raise BadUDPRelayPacket('FRAG not implemented. FRAG: %r' % frag)

        try:
            target_host = read_socks_host(bio)
        except (BadSocksHost, InsufficientData) as exc:
            raise BadUDPRelayPacket('fail to read DST.ADDR') from exc

        bport = bio.read(2)
        if len(bport) != 2:
            raise BadUDPRelayPacket('fail to read DST.PORT')
        port, = struct.unpack('!H', bport)

        return cls(target_host, port, bio.read())

    def dumps(self) -> bytes:
        return (
            b'\0\0'  # RSV
            + b'\0'  # FRAG
            + encode_socks_host(self.host)  # DST.ADDR
            + struct.pack('!H', self.port)  # DST.PORT
            + self.data
        )


class UDPRelayProtocol(DatagramProtocol):
    user_protocol = None
    connected_addr = None

    def startProtocol(self):
        """Called when a transport is connected to this protocol.

        Will only be called once, even if multiple ports are connected.
        """

    def stopProtocol(self):
        """Called when the transport is disconnected.

        Will only be called once, after all ports are disconnected.
        """
        if self.user_protocol is not None:
            self.user_protocol = None

    def datagramReceived(self, datagram: bytes, addr):
        """Called when a datagram is received.

        @param datagram: the string received from the transport.
        @param addr: tuple of source of datagram.
        """
        try:
            packet = UDPRelayPacket.loads(datagram)
        except BadUDPRelayPacket:
            logger.exception('bad udp relay packet: %r', datagram)
            return

        remote_host = str(packet.host)
        connection = (remote_host, packet.port)
        if self.user_protocol is not None:
            if self.connected_addr is None or self.connected_addr == connection:
                self.user_protocol.datagramReceived(packet.data, connection)
            else:
                logger.error('unexpected packet: %r', packet)
        else:
            logger.error('user_protocol not set')

    def send_datagram(self, data: bytes, host: SocksHost, port: int, max_size=None):
        packed = UDPRelayPacket(host, port, data).dumps()
        if max_size is not None and len(packed) > max_size:
            raise MessageLengthError("message too long: %d > %d" % (len(packed), max_size))
        self.transport.write(packed)

    def connect(self, addr):
        assert self.connected_addr is None
        self.connected_addr = addr

    def set_user_protocol(self, proto: DatagramProtocol):
        assert self.user_protocol is None
        self.user_protocol = proto


# noinspection PyPep8Naming
@implementer(IListeningPort, IUDPTransport)
class UDPRelayTransport:
    def __init__(
            self, port: int, protocol: DatagramProtocol, *,
            relay_protocol: UDPRelayProtocol, max_packet_size: int = 8192
    ):
        self.port = port
        self.protocol = protocol
        self.relay_proto = relay_protocol
        self.relay_proto.set_user_protocol(self.protocol)
        self.max_size = max_packet_size
        self.connected_addr = None

    def startListening(self):
        """
        Start listening on this port.

        @raise CannotListenError: If it cannot listen on this port (e.g., it is
                                  a TCP port and it cannot bind to the required
                                  port number).
        """
        self.protocol.makeConnection(self)  # startProtocol() called

    def stopListening(self):
        """
        Stop listening on this port.

        If it does not complete immediately, will return Deferred that fires
        upon completion.
        """
        self.connected_addr = None
        self.protocol.doStop()  # stopProtocol() called

    def getHost(self):
        """
        Get the host that this port is listening for.

        @return: An L{IAddress} provider.
        """
        host, port = self.connected_addr
        return to_twisted_addr(host, port, type_='UDP')

    def connect(self, host, port):
        """
        Connect the transport to an address.

        This changes it to connected mode. Datagrams can only be sent to
        this address, and will only be received from this address. In addition
        the protocol's connectionRefused method might get called if destination
        is not receiving datagrams.

        @param host: an IP address, not a domain name ('127.0.0.1', not 'localhost')
        @param port: port to connect to.
        """
        if self.connected_addr is not None:
            raise RuntimeError("already connected, reconnecting is not currently supported")

        host = str(to_socks_host(host))     # normalize ip address
        self.connected_addr = (host, port)
        self.relay_proto.connect(self.connected_addr)

    def write(self, datagram, addr=None):
        """
        Write a datagram.

        @type datagram: L{bytes}
        @param datagram: The datagram to be sent.

        @type addr: L{tuple} containing L{str} as first element and L{int} as
            second element, or L{None}
        @param addr: A tuple of (I{stringified IPv4 or IPv6 address},
            I{integer port number}); can be L{None} in connected mode.
        """
        if self.connected_addr:
            assert addr in (None, self.connected_addr)
            addr = self.connected_addr
        else:
            assert addr is not None

        host, port = addr
        host = to_socks_host(host)
        self.relay_proto.send_datagram(datagram, host, port, max_size=self.max_size)

    def setBroadcastAllowed(self, enabled):
        """
        Set whether this port may broadcast.

        @param enabled: Whether the port may broadcast.
        @type enabled: L{bool}
        """
        raise NotImplementedError

    def getBroadcastAllowed(self):
        """
        Checks if broadcast is currently allowed on this port.

        @return: Whether this port may broadcast.
        @rtype: L{bool}
        """
        return False


# noinspection PyPep8Naming
@implementer(IReactorUDP)
class UDPRelay:
    def __init__(self, ctrl_protocol: 'Socks5ControlProtocol', reactor=None):
        self.ctrl_proto = ctrl_protocol
        assert self.ctrl_proto.udp_relay is None
        self.ctrl_proto.udp_relay = self
        self.relay_proto = UDPRelayProtocol()
        self.listening_port = None

        def set_flag(result):
            self.relay_done = True
            return result
        self.relay_defer = defer.Deferred().addCallback(set_flag)
        self.relay_done = False
        self.relay_port = None

        self._stop_defer = None
        self.reactor = get_reactor(reactor)

    def setup_relay(self):
        def connect_relay(result: Tuple[SocksHost, int]):
            host, port = result
            host = str(host)
            self.relay_port.connect(host, port)
            return result

        def do_request(ignore):
            # TODO: interface
            self.relay_port = self.reactor.listenUDP(0, self.relay_proto)

            relay_port_bind = self.relay_port.getHost()
            client_host, client_port = relay_port_bind.host, relay_port_bind.port
            # XXX: hacks
            client_host = {
                '0.0.0.0': '127.0.0.1',
                '::': '::1',
            }.get(client_host, client_host)

            return self.ctrl_proto.request_udp_associate(
                ip_address(client_host), client_port,
            )

        sequence_deferred_call([
            lambda ignore: self.ctrl_proto.auth_defer,
            do_request,
            connect_relay,
        ], 'ignore').chainDeferred(self.relay_defer)
        return self.relay_defer

    def listenUDP(self, port: int, protocol: DatagramProtocol, interface='', maxPacketSize=8192):
        """
        Connects a given L{DatagramProtocol} to the given numeric UDP port.

        @param port: A port number on which to listen.
        @type port: C{int}

        @param protocol: A L{DatagramProtocol} instance which will be
            connected to the given C{port}.
        @type protocol: L{DatagramProtocol}

        @param interface: The local IPv4 or IPv6 address to which to bind;
            defaults to '', ie all IPv4 addresses.
        @type interface: C{str}

        @param maxPacketSize: The maximum packet size to accept.
        @type maxPacketSize: C{int}

        @return: object which provides L{IListeningPort}.
        """
        if not self.relay_done:
            raise CannotListenError(interface, port, socket.error('relay not set up'))
        if self.listening_port is not None:
            raise RuntimeError('can not listen more than once')

        self.listening_port = UDPRelayTransport(
            port, protocol, relay_protocol=self.relay_proto, max_packet_size=maxPacketSize,
        )
        self.listening_port.startListening()
        return self.listening_port

    def stop(self):
        if self._stop_defer is None:
            dl = [defer.maybeDeferred(self.ctrl_proto.transport.loseConnection)]
            if self.listening_port is not None:
                dl.append(defer.maybeDeferred(self.listening_port.stopListening))
            if self.relay_proto.transport is not None:
                dl.append(defer.maybeDeferred(self.relay_proto.transport.stopListening))
            self._stop_defer = defer.DeferredList(dl, fireOnOneErrback=True)
        return self._stop_defer


# noinspection PyPep8Naming
@implementer(IConnector)
class TCPRelayConnector:
    def __init__(
            self, host: str, port: int, factory: ClientFactory,
            proxy_addr: Tuple[str, int], reactor=None
    ):
        self.host, self.port = host, port
        self.factory = factory
        self.proxy_addr = proxy_addr
        self.ctrl_proto = None      # type: Socks5ControlProtocol
        self.ctrl_connect_d = None  # type: defer.Deferred
        self.user_proto = None      # type: Protocol
        self.state = 'disconnected'

        self.reactor = get_reactor(reactor)

    def connect(self):
        def authed(ignore):
            host = to_socks_host(self.host)
            d = self.ctrl_proto.request_tcp_connect(host, self.port)
            d.addCallbacks(relay_ready, failed)
            return ignore

        def relay_ready(result):
            self.state = 'connected'
            self.user_proto.makeConnection(self.ctrl_proto.transport)
            return result

        def failed(failure):
            self.state = 'disconnected'

            if self.ctrl_proto.transport is not None:
                self._disconnect_control_protocol()     # triggers self.connection_lost()

            self.factory.clientConnectionFailed(self, failure)
            if self.state == 'disconnected':
                self.factory.doStop()

        if self.state != 'disconnected':
            raise RuntimeError('TCPRelayConnector can not connect. state=%r', self.state)
        self.state = 'connecting'

        addr = to_twisted_addr(self.host, self.port, type_='TCP')
        self.user_proto = self.factory.buildProtocol(addr)
        if self.user_proto is not None:
            self.factory.doStart()
            self.factory.startedConnecting(self)

            self.ctrl_proto = Socks5ControlProtocol()
            self.ctrl_proto.connector = self
            self.ctrl_proto.auth_defer.addCallbacks(authed, failed)
            self._connect_control_protocol().addErrback(failed)
        else:
            logger.debug('%r.buildProtocol(%r) returns None', self.factory, addr)

    def _connect_control_protocol(self):
        """this method exists for test purpose."""
        proxy_endpoint = get_client_endpoint(self.reactor, self.proxy_addr)
        self.ctrl_connect_d = connectProtocol(proxy_endpoint, self.ctrl_proto)
        return self.ctrl_connect_d

    def connection_lost(self, failure):
        if self.state == 'connected':   # preventing called from connecting/disconnected state
            self.state = 'disconnected'
            self._disconnect_user_protocol(failure)
            self.factory.clientConnectionLost(self, failure)
            if self.state == 'disconnected':
                self.factory.doStop()

    def data_received(self, data):
        assert self.state == 'connected'
        self.user_proto.dataReceived(data)

    def stopConnecting(self):
        assert self.state == 'connecting'
        self.state = 'disconnected'
        if self.ctrl_connect_d:
            self.ctrl_connect_d.cancel()
        if self.ctrl_proto.transport:
            self._disconnect_control_protocol()

    def disconnect(self):
        # BUG: ssl not disconnected cleanly
        if self.state == 'connecting':
            self.stopConnecting()
        elif self.state == 'connected':
            self._disconnect_control_protocol()
        else:
            raise RuntimeError('TCPRelayConnector already disconnected')
        assert self.state == 'disconnected'

    def getDestination(self):
        raise NotImplementedError

    def _disconnect_control_protocol(self):
        self.ctrl_proto.transport.loseConnection()
        self.ctrl_proto.transport = None
        self.connection_lost(connectionDone)

    def _disconnect_user_protocol(self, reason=connectionDone):
        if self.user_proto and self.user_proto.transport:
            self.user_proto.connectionLost(reason)
            self.user_proto.transport = None


_Socks5Reply = NamedTuple(
    'Socks5Reply',
    [('reply', int), ('bind_host', SocksHost), ('bind_port', int)])


class Socks5Reply(_Socks5Reply):
    # FIXME: verify reply and port.
    def dumps(self):
        return (
            struct.pack('!BBB', 5, self.reply, 0)
            + encode_socks_host(self.bind_host)
            + struct.pack('!H', self.bind_port)
        )

    @classmethod
    def load(cls, stream: BytesIO) -> 'Socks5Reply':
        def read(n: int) -> bytes:
            data = stream.read(n)
            if len(data) != n:
                raise InsufficientData
            return data

        ver, rep, rsv = struct.unpack('!BBB', read(3))
        if ver != 5:
            raise BadSocks5Reply('bad socks version: %r' % ver)
        if rsv != 0:
            raise BadSocks5Reply('RSV is not zero: %r' % rsv)

        try:
            bind_addr = read_socks_host(stream)  # may raise InsufficientData
        except BadSocksHost as exc:
            raise BadSocks5Reply(exc) from exc

        bind_port, = struct.unpack('!H', read(2))

        return cls(rep, bind_addr, bind_port)


class Socks5Cmd(IntEnum):
    CONNECT = 1
    BIND = 2
    UDP_ASSOCIATE = 3


class Socks5ControlProtocol(Protocol):
    def __init__(self):
        self.data = b''
        self.state = 'init'
        self.auth_defer = defer.Deferred()
        self.request_defer = None   # type: Optional[defer.Deferred]
        self.udp_relay = None       # type: Optional[UDPRelay]
        self.connector = None       # type: Optional[TCPRelayConnector]

    def connectionMade(self):
        self.greet()

    def connectionLost(self, reason=connectionDone):
        if self.state == 'greeted':
            self.auth_defer.errback(reason)
        elif self.state == 'authed':
            # TODO: figure out when will happen for self._make_request()
            pass
        elif self.state in ('udp_req', 'tcp_req'):
            self.request_defer.errback(reason)
        elif self.state == 'tcp_relay':
            assert self.connector is not None
            self.connector.connection_lost(reason)

        self.state = 'failed'
        if self.udp_relay is not None:
            self.udp_relay.stop()

    def greet(self):
        assert self.state == 'init'
        data = (
            b'\x05'     # version
            + b'\x01'   # number of authentication methods supported
            + b'\x00'   # no authentication
        )
        self.transport.write(data)
        self.state = 'greeted'
        logger.debug('socks5 greeted')

    def check_greet_reply(self):
        assert self.state == 'greeted'

        try:
            self._read_greet_reply()
        except InsufficientData:
            pass
        except SocksError as exc:
            logger.error('bad reply: %r', exc)
            self.data = b''
            self.state = 'failed'
            self.auth_defer.errback(Failure(exc))
        else:
            self.state = 'authed'
            logger.debug('socks5 authed')
            self.auth_defer.callback(self)

    def _read_greet_reply(self):
        if len(self.data) < 2:
            raise InsufficientData('greet reply')

        version, method = self.data[:2]
        self.data = self.data[2:]

        if version != 5:
            raise BadSocksVersion(version)
        if method != 0:
            raise UnsupportedAuthMethod(method)
        return version, method

    def _make_request(self, cmd: Socks5Cmd, dst_host: SocksHost, dst_port: int, next_state: str) \
            -> defer.Deferred:
        assert self.state == 'authed'
        data = (
            struct.pack('!BBB', 5, cmd.value, 0)    # ver, cmd, reserved
            + encode_socks_host(dst_host) + struct.pack('!H', dst_port))
        self.transport.write(data)
        self.state = next_state

        assert self.request_defer is None
        self.request_defer = defer.Deferred()
        return self.request_defer

    def _check_reply(self, cmd: Socks5Cmd, cur_state: str, next_state: str):
        assert self.state == cur_state

        bio = BytesIO(self.data)
        try:
            reply, bind_host, bind_port = Socks5Reply.load(bio)
        except InsufficientData:
            pass
        except BadSocks5Reply as exc:
            logger.error('%r', exc)
            self.data = b''
            self.state = 'failed'
            self.request_defer.errback(Failure(exc))
        else:
            self.data = bio.read()
            if reply != 0:
                logger.error('%s: non-success reply: %r', cmd, reply)
                self.state = 'req_failed'
                self.request_defer.errback(Failure(Exception('%s: server rejected' % cmd)))
            else:
                self.state = next_state
                logger.debug('%s: %s:%d', cmd, bind_host, bind_port)
                self.request_defer.callback((bind_host, bind_port))

    def request_udp_associate(self, client_host: SocksHost, client_port: int):
        return self._make_request(Socks5Cmd.UDP_ASSOCIATE, client_host, client_port, 'udp_req')

    def check_udp_associate_reply(self):
        self._check_reply(Socks5Cmd.UDP_ASSOCIATE, 'udp_req', 'udp_relay')

    def request_tcp_connect(self, dst_host: SocksHost, dst_port: int):
        return self._make_request(Socks5Cmd.CONNECT, dst_host, dst_port, 'tcp_req')

    def check_tcp_connect_reply(self):
        self._check_reply(Socks5Cmd.CONNECT, 'tcp_req', 'tcp_relay')

    def dataReceived(self, data):
        self.data += data

        while True:
            data_len = len(self.data)
            if self.state == 'greeted':
                self.check_greet_reply()
            elif self.state == 'udp_req':
                self.check_udp_associate_reply()
            elif self.state == 'tcp_req':
                self.check_tcp_connect_reply()
            elif self.state == 'tcp_relay':
                assert self.connector is not None
                self.connector.data_received(data)
                self.data = b''
            else:
                logger.error('unexpected server data: %r', data)

            # insufficient data (self.data not touched) or protocol failed (self.data is b'')
            if len(self.data) == 0 or len(self.data) == data_len:
                break


# noinspection PyPep8Naming
@implementer(IReactorTCP, IReactorSSL)
class SocksProxy:
    def __init__(self, host: str, port: int, reactor=None):
        self.host, self.port = host, port
        self.reactor = get_reactor(reactor)

    @defer.inlineCallbacks
    def get_udp_relay(self):
        proxy_endpoint = get_client_endpoint(self.reactor, (self.host, self.port))
        ctrl_proto = Socks5ControlProtocol()
        relay = UDPRelay(ctrl_proto)

        yield connectProtocol(proxy_endpoint, ctrl_proto)
        yield relay.setup_relay()
        return relay

    def connectTCP(
            self, host: str, port: int, factory: ClientFactory,
            timeout=30, bindAddress=None
    ):
        # TODO: timeouts
        # TODO: bindAddress

        connector = TCPRelayConnector(
            host, port, factory,
            proxy_addr=(self.host, self.port), reactor=self.reactor,
        )
        connector.connect()
        return connector

    def listenTCP(self, port, factory, backlog=50, interface=''):
        raise NotImplementedError

    def connectSSL(
            self, host: str, port: int, factory: ClientFactory,
            contextFactory: ssl.ClientContextFactory, timeout=30, bindAddress=None
    ):
        try:
            from twisted.protocols import tls
        except ImportError:
            raise NotImplementedError
        else:
            patch_twisted_ssl_root_bug()
            tls_factory = tls.TLSMemoryBIOFactory(contextFactory, True, factory)
            return self.connectTCP(host, port, tls_factory, timeout, bindAddress)

    def listenSSL(self, port, factory, contextFactory, backlog=50, interface=''):
        raise NotImplementedError


# noinspection PyPep8Naming
@implementer(IReactorTCP, IReactorSSL)
class SocksWrappedReactor:
    def __init__(self, proxy_host: str, proxy_port: int, reactor=None):
        self.__reactor = get_reactor(reactor)
        self.__socks_proxy = SocksProxy(proxy_host, proxy_port, reactor=self.__reactor)

    def __getattr__(self, item):
        return getattr(self.__reactor, item)

    def connectTCP(
            self, host: str, port: int, factory: ClientFactory,
            timeout=30, bindAddress=None
    ):
        return self.__socks_proxy.connectTCP(
            host, port, factory,
            timeout=timeout, bindAddress=bindAddress,
        )

    def connectSSL(
            self, host: str, port: int, factory: ClientFactory,
            contextFactory: ssl.ClientContextFactory, timeout=30, bindAddress=None
    ):
        return self.__socks_proxy.connectSSL(
            host, port, factory, contextFactory,
            timeout=timeout, bindAddress=bindAddress,
        )

    def listenUDP(self, port, protocol, interface='', maxPacketSize=8192):
        raise NotImplementedError('please use SocksProxy.get_udp_relay()')
