import math
import socket
import struct
from ipaddress import IPv4Network, IPv6Network, ip_network
from typing import Union, List, Callable

from twisted.internet import defer
from twisted.internet.protocol import ClientFactory
from twisted.names import dns
from twisted.names.dns import (
    Message, _EDNSMessage, _OPTHeader, _OPTVariableOption,
)

from dnsagent.resolver.bugfix import (
    BugFixDNSProtocol, BugFixDNSDatagramProtocol, BugFixDNSClientFactory, BugFixResolver,
)
from dnsagent.socks import SocksProxy, UDPRelay


__all__ = ('ExtendedResolver', 'TCPExtendedResolver')


NetworkType = Union[IPv4Network, IPv6Network]


class EDNSMessage(_EDNSMessage):
    """
    Fixed bugs:
        1. No options field.
    """

    compareAttributes = _EDNSMessage.compareAttributes + ('options',)

    def __init__(
            self, id=0, answer=False, opCode=dns.OP_QUERY, auth=False,
            trunc=False, recDes=False, recAv=False, rCode=0,
            ednsVersion=0, dnssecOK=False, authenticData=False,
            checkingDisabled=False, maxSize=512,
            queries=None, answers=None, authority=None, additional=None, options=None
    ):
        super().__init__(
            id=id, answer=answer, opCode=opCode, auth=auth,
            trunc=trunc, recDes=recDes, recAv=recAv, rCode=rCode,
            ednsVersion=ednsVersion, dnssecOK=dnssecOK, authenticData=authenticData,
            checkingDisabled=checkingDisabled, maxSize=maxSize,
            queries=queries, answers=answers, authority=authority, additional=additional,
        )
        self.options = options

    @classmethod
    def _fromMessage(cls, message: Message):
        """
        Construct and return a new L{_EDNSMessage} whose attributes and records
        are derived from the attributes and records of C{message} (a L{Message}
        instance).

        If present, an C{OPT} record will be extracted from the C{additional}
        section and its attributes and options will be used to set the EDNS
        specific attributes C{extendedRCODE}, C{ednsVersion}, C{dnssecOK},
        C{ednsOptions}.

        The C{extendedRCODE} will be combined with C{message.rCode} and assigned
        to C{self.rCode}.

        @param message: The source L{Message}.
        @type message: L{Message}

        @return: A new L{_EDNSMessage}
        @rtype: L{_EDNSMessage}
        """
        opt_records = [
            OPTHeader.fromRRHeader(r) for r in message.additional
            if r.type == dns.OPT
        ]

        new_message = cls(
            id=message.id,
            answer=message.answer,
            opCode=message.opCode,
            auth=message.auth,
            trunc=message.trunc,
            recDes=message.recDes,
            recAv=message.recAv,
            rCode=message.rCode,
            authenticData=message.authenticData,
            checkingDisabled=message.checkingDisabled,
            # Default to None, it will be updated later when the OPT records are
            # parsed.
            ednsVersion=None,
            dnssecOK=False,
            queries=message.queries[:],
            answers=message.answers[:],
            authority=message.authority[:],
            additional=[ r for r in message.additional if r.type != dns.OPT ],
        )

        if opt_records:
            # XXX: If multiple OPT records are received, an EDNS server should
            # respond with FORMERR. See ticket:5669#comment:1.
            opt = opt_records[0]
            new_message.ednsVersion = opt.version
            new_message.dnssecOK = opt.dnssecOK
            new_message.maxSize = opt.udpPayloadSize
            new_message.rCode = opt.extendedRCODE << 4 | message.rCode
            new_message.options = opt.options   # FIXED: options field

        return new_message

    def _toMessage(self):
        """
        Convert to a standard L{dns.Message}.

        If C{ednsVersion} is not None, an L{OPTHeader} instance containing all
        the I{EDNS} specific attributes and options will be appended to the list
        of C{additional} records.

        @return: A L{dns.Message}
        @rtype: L{dns.Message}
        """
        m = self._messageFactory(
            id=self.id,
            answer=self.answer,
            opCode=self.opCode,
            auth=self.auth,
            trunc=self.trunc,
            recDes=self.recDes,
            recAv=self.recAv,
            # Assign the lower 4 bits to the message
            rCode=self.rCode & 0xf,
            authenticData=self.authenticData,
            checkingDisabled=self.checkingDisabled,
        )

        m.queries = self.queries[:]
        m.answers = self.answers[:]
        m.authority = self.authority[:]
        m.additional = self.additional[:]

        if self.ednsVersion is not None:
            o = OPTHeader(
                version=self.ednsVersion,
                dnssecOK=self.dnssecOK,
                udpPayloadSize=self.maxSize,
                # Assign the upper 8 bits to the OPT record
                extendedRCODE=self.rCode >> 4,
                options=self.options,   # FIXED: options field
            )
            m.additional.append(o)

        return m


class OPTHeader(_OPTHeader):
    pass


class BadOPTClientSubnetData(Exception):
    pass


class OPTClientSubnetOption(_OPTVariableOption):
    CLIENT_SUBNET_OPTION_CODE = 8
    FAMILY_IPV4 = 1
    FAMILY_IPV6 = 2

    DATA_FMT = '!HBB'

    @classmethod
    def from_subnet(cls, subnet: NetworkType, scope_prefix=0):
        if subnet.version == 4:
            addr_family = cls.FAMILY_IPV4
            so_af = socket.AF_INET
        else:
            addr_family = cls.FAMILY_IPV6
            so_af = socket.AF_INET6

        source_prefix = subnet.prefixlen
        addr_data = socket.inet_pton(so_af, str(subnet.network_address))

        # address MUST be truncated to the number of bits
        # indicated by the SOURCE PREFIX-LENGTH field,
        # padding with 0 bits to pad to the end of the last octet needed.
        addr_data = addr_data[:math.ceil(source_prefix / 8)]

        data = struct.pack(cls.DATA_FMT, addr_family, source_prefix, scope_prefix) + addr_data
        return cls(cls.CLIENT_SUBNET_OPTION_CODE, data)

    @classmethod
    def parse_data(cls, data: bytes):
        def pad_zero(b: bytes, n: int):
            pad_len = n - len(b)
            return b + b'\0' * pad_len

        headsize = struct.calcsize(cls.DATA_FMT)
        if len(data) < headsize:
            raise BadOPTClientSubnetData('data too short: %r' % data)

        head = data[:headsize]
        addr_family, source_prefix, scope_prefix = struct.unpack(cls.DATA_FMT, head)

        addr_data = data[headsize:]
        if len(addr_data) != math.ceil(source_prefix / 8):
            raise BadOPTClientSubnetData(
                'address too short or too long: %r, prefix=%d' % (addr_data, source_prefix)
            )

        if addr_family == cls.FAMILY_IPV4:
            so_af = socket.AF_INET
            full_addr_len = 4
        elif addr_family == cls.FAMILY_IPV6:
            so_af = socket.AF_INET6
            full_addr_len = 16
        else:
            raise BadOPTClientSubnetData('bad addr_family: %d' % addr_family)

        ip_string = socket.inet_ntop(so_af, pad_zero(addr_data, full_addr_len))
        try:
            subnet = ip_network('{ip_string}/{source_prefix}'.format_map(locals()))
        except ValueError as exc:
            raise BadOPTClientSubnetData('bad address') from exc

        return subnet, scope_prefix


class ECSDNSProtocolMixin:
    """Add EDNS client subnet support for DNSProtocol and DNSDatagramProtocol"""

    def _query(
            self: Union[dns.DNSMixin, 'ECSDNSProtocolMixin'],
            queries: List[dns.Query], timeout: float, id: int,
            write_message: Callable[[Message], None], client_subnet: NetworkType = None
    ):
        m = self.create_query_message(id=id, client_subnet=client_subnet)
        m.queries = queries

        try:
            write_message(m)
        except Exception:
            return defer.fail()

        d = defer.Deferred()
        canceller = self.callLater(timeout, self._clearFailed, d, id)
        self.liveMessages[id] = (d, canceller)
        return d

    def create_query_message(self, id: int, client_subnet: NetworkType):
        if client_subnet:
            ecs_option = OPTClientSubnetOption.from_subnet(client_subnet)
            msg = EDNSMessage(id=id, recDes=True, options=[ecs_option])
            return msg
        else:
            return Message(id=id, recDes=True)


class ExtendedDNSProtocol(ECSDNSProtocolMixin, BugFixDNSProtocol):
    def query(self, queries, timeout=60, client_subnet: NetworkType = None):
        id = self.pickID()
        return self._query(queries, timeout, id, self.writeMessage, client_subnet=client_subnet)


class ExtendedDNSDatagramProtocol(ECSDNSProtocolMixin, BugFixDNSDatagramProtocol):
    def query(self, address, queries, timeout=10, id=None, client_subnet: NetworkType = None):
        assert self.transport
        if id is None:
            id = self.pickID()
        else:
            self.resends[id] = 1

        def write_message(m):
            self.writeMessage(m, address)

        return self._query(queries, timeout, id, write_message, client_subnet=client_subnet)


class DNSDatagramProtocolOverSocks(ExtendedDNSDatagramProtocol):
    def __init__(self, controller, reactor=None, relay: UDPRelay = None):
        super().__init__(controller, reactor=reactor)
        self.relay = relay

    def startListening(self):
        self.relay.listenUDP(0, self, maxPacketSize=512)    # ???


class ExtendedDNSClientFactory(BugFixDNSClientFactory):
    protocol = ExtendedDNSProtocol


class ExtendedResolver(BugFixResolver):
    """A resolver that supports SOCKS5 proxy."""

    client_factory_cls = ExtendedDNSClientFactory

    def __init__(
            self, resolv=None, servers=None, timeout=(1, 3, 11, 45), reactor=None,
            socks_proxy: SocksProxy = None
    ):
        super().__init__(resolv=resolv, servers=servers, timeout=timeout, reactor=reactor)
        self.socks_proxy = socks_proxy

    def _got_udp_relay(self, relay: UDPRelay, query_d, *query_args):
        def stop_relay(ignore):
            relay.stop()
            return ignore

        proto = DNSDatagramProtocolOverSocks(self, reactor=self._reactor, relay=relay)
        relay.listenUDP(0, proto, maxPacketSize=512)

        proto.query(*query_args).chainDeferred(query_d)
        query_d.addBoth(stop_relay)

    def _query(self, *args):
        """Run UDP query"""
        if self.socks_proxy is not None:
            d = defer.Deferred()
            relay_d = self.socks_proxy.get_udp_relay()
            relay_d.addCallback(self._got_udp_relay, d, *args)
            relay_d.addErrback(d.errback)
            return d
        else:
            def stop_listening(ignore):
                protocol.transport.stopListening()
                return ignore

            protocol = ExtendedDNSDatagramProtocol(self, reactor=self._reactor)
            self._reactor.listenUDP(0, protocol)

            d = protocol.query(*args)
            d.addBoth(stop_listening)
            return d

    def connect_tcp(self, host: str, port: int, factory: ClientFactory):
        if self.socks_proxy:
            return self.socks_proxy.connectTCP(host, port, self.factory)
        else:
            return super().connect_tcp(host, port, factory)


class TCPExtendedResolver(ExtendedResolver):
    # TODO: merge this into ExtendedResolver
    def queryUDP(self, queries, timeout=None):
        return self.queryTCP(queries)

    def _repr_short_(self):
        return 'tcp://' + super()._repr_short_()
