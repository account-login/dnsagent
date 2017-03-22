from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network
import time
from typing import Optional, Union

from twisted.names.server import DNSServerFactory
from twisted.names import dns

from dnsagent import logger
from dnsagent.pubip import get_public_ip
from dnsagent.resolver.bugfix import BugFixDNSProtocol
from dnsagent.resolver.extended import ExtendedDNSProtocol, EDNSMessage, OPTClientSubnetOption


NetworkType = Union[IPv4Network, IPv6Network]


class BugFixDNSServerFactory(DNSServerFactory):
    """
    Fixed bugs:
        1. Timeout argument not set for query.
    """

    protocol = BugFixDNSProtocol

    def __init__(self, resolver, resolve_timeout=(5,)):
        super().__init__(clients=[resolver])
        self.resolver = resolver    # overide ResolverChain set in super().__init__()
        self.resolve_timeout = resolve_timeout

    def handleQuery(self, message, protocol, address):
        """
        Overrided for custom logging.

        Called by L{DNSServerFactory.messageReceived} when a query message is
        received.

        Takes the first query from the received message and dispatches it to
        C{self.resolver.query}.

        Adds callbacks L{DNSServerFactory.gotResolverResponse} and
        L{DNSServerFactory.gotResolverError} to the resulting deferred.

        Note: Multiple queries in a single message are not supported because
        there is no standard way to respond with multiple rCodes, auth,
        etc. This is consistent with other DNS server implementations. See
        U{http://tools.ietf.org/html/draft-ietf-dnsext-edns1-03} for a proposed
        solution.

        @param protocol: The DNS protocol instance to which to send a response
            message.
        @type protocol: L{dns.DNSDatagramProtocol} or L{dns.DNSProtocol}

        @param message: The original DNS query message for which a response
            message will be constructed.
        @type message: L{dns.Message}

        @param address: The address to which the response message will be sent
            or L{None} if C{protocol} is a stream protocol.
        @type address: L{tuple} or L{None}

        @return: A C{deferred} which fires with the resolved result or error of
            the first query in C{message}.
        @rtype: L{Deferred<twisted.internet.defer.Deferred>}
        """
        logger.info('[%d]handleQuery(%r), from %s', message.id, message.queries[0], address)

        d = self.do_query(message, address)
        d.addCallback(self.gotResolverResponse, protocol, message, address)
        d.addErrback(self.gotResolverError, protocol, message, address)
        return d

    def do_query(self, message: dns.Message, addr):
        query = message.queries[0]
        # FIXED:  timeout argument
        return self.resolver.query(query, timeout=self.resolve_timeout, request_id=message.id)

    def sendReply(self, protocol, message, address):
        """
        Overrided for custom logging.

        Send a response C{message} to a given C{address} via the supplied
        C{protocol}.

        Message payload will be logged if C{DNSServerFactory.verbose} is C{>1}.

        @param protocol: The DNS protocol instance to which to send the message.
        @type protocol: L{dns.DNSDatagramProtocol} or L{dns.DNSProtocol}

        @param message: The DNS message to be sent.
        @type message: L{dns.Message}

        @param address: The address to which the message will be sent or L{None}
            if C{protocol} is a stream protocol.
        @type address: L{tuple} or L{None}
        """
        if address is None:
            protocol.writeMessage(message)          # L{dns.DNSProtocol}
        else:
            protocol.writeMessage(message, address) # L{dns.DNSDatagramProtocol}

        logger.info(
            '[%d]reply: %r, cost: %.1f ms', message.id,
            (message.answers, message.authority, message.additional),
            (time.time() - message.timeReceived) * 1000,
        )


class BaseClientSubnetPolicy:
    def __call__(self, message: EDNSMessage, addr) -> Optional[NetworkType]:
        raise NotImplementedError


def passing_policy(message: EDNSMessage, addr):
    for option in message.options:
        if option.code == OPTClientSubnetOption.CLIENT_SUBNET_OPTION_CODE:
            client_subnet, scope_prefix = OPTClientSubnetOption.parse_data(option.data)
            return client_subnet


class AutoDiscoveryPolicy(BaseClientSubnetPolicy):
    def __init__(self, max_ipv4_prefixlen=24, max_ipv6_prefixlen=96):
        self.max_prefix_lens = {
            4: max_ipv4_prefixlen,
            6: max_ipv6_prefixlen,
        }
        self.get_public_ip_called = False
        self.server_public_ip = None

    def __call__(self, message: EDNSMessage, addr):
        subnet = passing_policy(message, addr)
        if not subnet:
            ip, port = addr
            ip = ip_address(ip)
            if not ip.is_private and not ip.is_unspecified:
                subnet = ip_network(ip)
                logger.debug('got client_subnet from client address: %s', subnet)
        else:
            logger.debug('got client_subnet from request: %s', subnet)

        if not subnet:
            if not self.get_public_ip_called:
                def set_server_public_ip(ip):
                    self.server_public_ip = ip

                self.get_public_ip_called = True
                get_public_ip().addCallback(set_server_public_ip)

            if self.server_public_ip:
                subnet = ip_network(self.server_public_ip)
                logger.debug('got client_subnet from server ip: %s', subnet)

        if subnet:
            max_prefix_len = self.max_prefix_lens[subnet.version]
            if subnet.prefixlen > max_prefix_len:
                # do not leak exact ip address
                net_string = '%s/%d' % (subnet.network_address, max_prefix_len)
                subnet = ip_network(net_string, strict=False)
                logger.debug('client_subnet truncated to %s', subnet)

        return subnet


class ExtendedDNSServerFactory(BugFixDNSServerFactory):
    # TODO: respond with edns message
    protocol = ExtendedDNSProtocol

    def __init__(self, resolver, resolve_timeout=(5,), client_subnet_policy=None):
        super().__init__(resolver, resolve_timeout=resolve_timeout)
        self.client_subnet_policy = client_subnet_policy or passing_policy

    def do_query(self, message: EDNSMessage, addr):
        query = message.queries[0]
        client_subnet = self.client_subnet_policy(message, addr)
        return self.resolver.query(
            query, timeout=self.resolve_timeout, request_id=message.id,
            client_subnet=client_subnet,
        )
