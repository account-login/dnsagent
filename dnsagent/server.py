from twisted.names import server

from dnsagent import logger


class TimeoutableDNSServerFactory(server.DNSServerFactory):
    def __init__(
            self, authorities=None, caches=None, clients=None, verbose=0,
            resolve_timeout=None,
    ):
        super().__init__(authorities=authorities, caches=caches, clients=clients, verbose=verbose)
        self.resolve_timeout = resolve_timeout or [5]

    def handleQuery(self, message, protocol, address):
        """
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
        # """

        logger.info('handleQuery: %s, from %s', message.queries[0], address)
        query = message.queries[0]
        return self.resolver.query(query, timeout=self.resolve_timeout).addCallback(
            self.gotResolverResponse, protocol, message, address
        ).addErrback(
            self.gotResolverError, protocol, message, address
        )
