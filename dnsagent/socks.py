from ipaddress import IPv4Address, IPv6Address, ip_address
import struct
import socket
from io import BytesIO
from typing import NamedTuple, Union, Optional, Tuple

from twisted.internet.endpoints import (
    TCP4ClientEndpoint, TCP6ClientEndpoint, HostnameEndpoint, connectProtocol,
)
from twisted.internet.protocol import DatagramProtocol, Protocol, connectionDone
from twisted.internet.interfaces import IListeningPort, IUDPTransport, IReactorUDP
from twisted.internet.error import MessageLengthError, CannotListenError
from twisted.python.failure import Failure
from twisted.internet import address
from twisted.internet import defer
from zope.interface import implementer

from dnsagent import logger


SocksHost = Union[IPv4Address, IPv6Address, str]


class BadSocksHost(Exception):
    pass


class InsufficientData(Exception):
    pass


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
    def startProtocol(self):
        """Called when a transport is connected to this protocol.

        Will only be called once, even if multiple ports are connected.
        """
        self.protocols = dict()

    def stopProtocol(self):
        """Called when the transport is disconnected.

        Will only be called once, after all ports are disconnected.
        """
        for proto in self.protocols.values():
            proto.stopProtocol()
        self.protocols.clear()

    def datagramReceived(self, datagram: bytes, addr):
        """Called when a datagram is received.

        @param datagram: the string received from the transport.
        @param addr: tuple of source of datagram.
        """
        try:
            packet = UDPRelayPacket.loads(datagram)
        except BadUDPRelayPacket:
            logger.exception('bad udp relay packet')
            return

        remote_host = str(packet.host)
        proto = self.protocols.get((remote_host, packet.port))
        if proto is not None:
            proto.datagramReceived(packet.data, (remote_host, packet.port))
        else:
            logger.error('unexpected packet: %r', packet)

    def send_datagram(self, data: bytes, host: SocksHost, port: int, max_size=None):
        packed = UDPRelayPacket(host, port, data).dumps()
        if max_size is not None and len(packed) > max_size:
            raise MessageLengthError("message too long: %d > %d" % (len(packed), max_size))
        self.transport.write(packed)

    def connect_protocol(self, addr, proto):
        self.protocols[addr] = proto

    def disconnect_protocol(self, addr):
        del self.protocols[addr]


@implementer(IListeningPort, IUDPTransport)
class UDPRelayTransport:
    def __init__(
            self, port: int, proto, *, relay_protocol: UDPRelayProtocol,
            max_packet_size: int = 8192, on_stop=None
    ):
        self.port = port
        self.protocol = proto
        self.relay_proto = relay_protocol
        self.max_size = max_packet_size
        self.on_stop = on_stop
        self.connected_addr = None

    def startListening(self):
        """
        Start listening on this port.

        @raise CannotListenError: If it cannot listen on this port (e.g., it is
                                  a TCP port and it cannot bind to the required
                                  port number).
        """
        self.protocol.makeConnection(self)

    def stopListening(self):
        """
        Stop listening on this port.

        If it does not complete immediately, will return Deferred that fires
        upon completion.
        """
        if self.connected_addr is not None:
            self.relay_proto.disconnect_protocol(self.connected_addr)
            self.connected_addr = None
        if self.on_stop is not None:
            self.on_stop()

    def getHost(self):
        """
        Get the host that this port is listening for.

        @return: An L{IAddress} provider.
        """
        host, port = self.connected_addr
        try:
            ipobj = ip_address(host)
        except ValueError:
            return address.HostnameAddress(host, port)
        else:
            if isinstance(ipobj, IPv4Address):
                return address.IPv4Address('UDP', host, port)
            else:
                assert isinstance(ipobj, IPv6Address)
                return address.IPv6Address('UDP', host, port)

    def connect(self, host, port):
        if self.connected_addr is not None:
            raise RuntimeError("already connected, reconnecting is not currently supported")
        self.connected_addr = (host, port)
        self.relay_proto.connect_protocol(self.connected_addr, self.protocol)

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
        try:
            host = ip_address(host)
        except ValueError:
            pass
        self.relay_proto.send_datagram(datagram, host, port, max_size=self.max_size)


@implementer(IReactorUDP)
class UDPRelay:
    def __init__(self, ctrl_protocol: 'Socks5ControlProtocol', reactor=None):
        self.ctrl_proto = ctrl_protocol
        self.relay_proto = UDPRelayProtocol()
        self.listening_ports = set()

        def set_flag(result):
            self.relay_done = True
            return result
        self.relay_defer = defer.Deferred().addCallback(set_flag)
        self.relay_done = False
        self.relay_port = None

        self._stop_defer = None

        if reactor is None:
            from twisted.internet import reactor
        self.reactor = reactor

    def setup_relay(self):
        def connect(result: Tuple[SocksHost, int]):
            host, port = result
            host = str(host)
            self.relay_port.connect(host, port)
            return result

        def authed(ignore):
            # TODO: interface
            self.relay_port = self.reactor.listenUDP(0, self.relay_proto)

            relay_port_bind = self.relay_port.getHost()
            client_host, client_port = relay_port_bind.host, relay_port_bind.port
            # FIXME: hacks
            client_host = {
                '0.0.0.0': '127.0.0.1',
                '::': '::1',
            }.get(client_host, client_host)

            d = self.ctrl_proto \
                .request_udp_associate(ip_address(client_host), client_port)
            d.addCallback(connect)
            d.chainDeferred(self.relay_defer)

        self.ctrl_proto.auth_defer.addCallbacks(authed, self.relay_defer.errback)
        return self.relay_defer

    def listenUDP(self, port, protocol, interface='', maxPacketSize=8192):
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
        transport = UDPRelayTransport(
            port, protocol, relay_protocol=self.relay_proto, max_packet_size=maxPacketSize,
            on_stop=lambda: self.listening_ports.remove(transport),
        )
        self.listening_ports.add(transport)
        transport.startListening()
        return transport

    def stop(self):
        if self._stop_defer is None:
            dl = [ defer.maybeDeferred(port.stopListening)
                   for port in self.listening_ports.copy() ]
            if self.relay_port is not None:
                dl.append(defer.maybeDeferred(self.relay_port.stopListening))
            self._stop_defer = defer.DeferredList(dl)
        return self._stop_defer


class Socks5ControlProtocol(Protocol):
    def __init__(self):
        self.data = b''
        self.status = 'init'
        self.auth_defer = defer.Deferred()
        self.request_defer = None   # type: Optional[defer.Deferred]
        self.udp_relay = UDPRelay(self)
        self._udp_relay_defer = None

    def get_udp_relay(self):
        if self._udp_relay_defer is not None:
            return self._udp_relay_defer
        else:
            d = self._udp_relay_defer = defer.Deferred()
            self.udp_relay.setup_relay().addCallbacks(
                lambda ignore: d.callback(self.udp_relay),
                d.errback,
            )
            return d

    def connectionMade(self):
        self.greet()

    def connectionLost(self, reason=connectionDone):
        if self.status == 'greeted':
            self.auth_defer.errback(reason)
        elif self.status == 'udp_req':
            self.request_defer.errback(reason)

        self.status = 'failed'
        self.udp_relay.stop()

    def greet(self):
        data = (
            b'\x05'     # version
            + b'\x01'   # number of authentication methods supported
            + b'\x00'   # no authentication
        )
        self.transport.write(data)
        self.status = 'greeted'
        logger.debug('socks5 greeted')

    def check_greet_reply(self):
        def fail():
            self.transport.loseConnection()
            self.data = b''
            self.status = 'failed'
            self.auth_defer.errback(Failure(Exception('greeting failed')))

        if len(self.data) < 2:
            return

        ver = self.data[0]
        if ver != 5:
            logger.error('bad socks version: %r', ver)
            fail()
            return

        method = self.data[1]
        if method != 0:
            logger.error('authentication required. method: %r', method)
            fail()
            return

        self.data = self.data[2:]
        self.status = 'authed'
        logger.debug('socks5 authed')
        self.auth_defer.callback(self)

    def request_udp_associate(self, client_host: SocksHost, client_port: int) -> defer.Deferred:
        data = (
            b'\x05'     # version
            + b'\x03'   # udp associate
            + b'\0'     # reserve
            + encode_socks_host(client_host)    # DST.ADDR
            + struct.pack('!H', client_port)    # DST.PORT
        )
        self.transport.write(data)
        self.status = 'udp_req'
        assert self.request_defer is None
        self.request_defer = defer.Deferred()
        return self.request_defer

    def check_udp_associate_reply(self):
        def fail(exc_value=None):
            exc_value = exc_value or Exception('udp associate: bad reply')
            self.transport.loseConnection()
            self.data = b''
            self.status = 'failed'
            self.request_defer.errback(Failure(exc_value))

        bio = BytesIO(self.data)

        ver = bio.read(1)
        if not ver:
            return
        if ver != b'\x05':
            logger.error('bad socks version: %r', ver)
            fail()
            return

        rep = bio.read(1)
        if not rep:
            return

        rsv = bio.read(1)
        if not rsv:
            return
        if rsv != b'\x00':
            logger.error('bad socks reply. RSV: %r', rsv)
            fail()
            return

        try:
            bind_addr = read_socks_host(bio)
        except InsufficientData:
            return
        except BadSocksHost as exc:
            logger.error('bad socks reply. bad SocksHost.')
            fail(exc)
            return

        bport = bio.read(2)
        if len(bport) < 2:
            return
        bind_port, = struct.unpack('!H', bport)

        if rep != b'\x00':
            logger.error('non-success reply: %r', rep)
            self.data = bio.read()
            self.status = 'req_failed'
            self.request_defer.errback(Failure(Exception('udp associate: server rejected')))
            return

        self.data = bio.read()
        self.status = 'success'
        logger.debug('socks5 udp associate: %r', (bind_addr, bind_port))
        self.request_defer.callback((bind_addr, bind_port))

    def dataReceived(self, data):
        self.data += data
        if self.status == 'greeted':
            self.check_greet_reply()
        elif self.status == 'udp_req':
            self.check_udp_associate_reply()
        else:
            logger.error('unexpected server data: %r', data)


def get_client_endpoint(reactor, addr: Tuple[str, int]):
    host, port = addr
    try:
        ipobj = ip_address(host)
    except ValueError:
        return HostnameEndpoint(reactor, host.encode(), port)
    else:
        if isinstance(ipobj, IPv4Address):
            return TCP4ClientEndpoint(reactor, host, port)
        else:
            return TCP6ClientEndpoint(reactor, host, port)


@implementer(IReactorUDP)
class Socks5Relay:
    def __init__(self, proxy_addr, reactor=None):
        self.proxy_addr = proxy_addr
        if reactor is None:
            from twisted.internet import reactor
        self.reactor = reactor

        self._setup_udp_relay()

    # noinspection PyAttributeOutsideInit
    def _setup_udp_relay(self):
        def proxy_connected(ignore):
            d = self.ctrl_proto.get_udp_relay()
            d.addCallbacks(got_relay, self.udp_relay_defer.errback)

        def got_relay(relay):
            self.udp_relay = relay
            self.udp_relay_defer.callback(relay)

        self.proxy_endpoint = get_client_endpoint(self.reactor, self.proxy_addr)
        self.udp_relay = None   # type: Optional[UDPRelay]
        self.udp_relay_defer = defer.Deferred()
        self.ctrl_proto = Socks5ControlProtocol()
        ctrl_connected = connectProtocol(self.proxy_endpoint, self.ctrl_proto)
        ctrl_connected.addCallbacks(proxy_connected, self.udp_relay_defer.errback)

    def listenUDP(self, port, protocol, interface='', maxPacketSize=8192):
        if self.udp_relay is None:
            if not self.udp_relay_defer.called:
                raise CannotListenError(interface, port, socket.error('relay not set up'))
            else:
                raise CannotListenError(interface, port, socket.error('fail to set up relay'))
        else:
            return self.udp_relay.listenUDP(
                port, protocol, interface=interface, maxPacketSize=maxPacketSize,
            )

    def stop(self):
        self.ctrl_proto.transport.loseConnection()
        if self.udp_relay is not None:
            return self.udp_relay.stop()
        else:
            return defer.succeed(None)
