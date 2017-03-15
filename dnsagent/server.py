import time
from twisted.names.server import DNSServerFactory
from twisted.names import dns

from dnsagent import logger
from dnsagent.resolver.bugfix import BugFixDNSProtocol
from dnsagent.resolver.extended import ExtendedDNSProtocol


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
        request_id = message.id
        logger.info('[%d]handleQuery(%r), from %s', request_id, message.queries[0], address)

        query = message.queries[0]
        # FIXED:  timeout argument
        d = self.resolver.query(query, timeout=self.resolve_timeout, request_id=request_id)
        return d.addCallback(
            self.gotResolverResponse, protocol, message, address,
        ).addErrback(
            self.gotResolverError, protocol, message, address,
        )

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


class ExtendedDNSServerFactory(BugFixDNSServerFactory):
    protocol = ExtendedDNSProtocol
