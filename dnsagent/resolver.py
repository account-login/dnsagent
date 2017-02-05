from ipaddress import IPv4Address, IPv6Address, ip_address
import socket
from collections import defaultdict
import itertools
from twisted.internet import defer
from twisted.names import dns
from twisted.names.error import DomainError
from twisted.names.common import ResolverBase
from twisted.names.client import Resolver as OriginResolver
from twisted.names.resolve import ResolverChain as OriginResolverChain
from twisted.python.failure import Failure
from iprir.ipset import IpSet

from dnsagent import logger
from dnsagent.utils import watch_modification, PrefixedLogger


# TODO: round robin
# TODO: edns_client_subnet
# TODO: dns over https: https://developers.google.com/speed/public-dns/docs/dns-over-https
# TODO: persistant tcp connection
# TODO: socks5 proxy
# TODO: dispaching based on input
# TODO: structured log


class MyBaseResolver(ResolverBase):
    """
    Add kwargs to query() method, so additional information
    can by passed to resolver and sub-resovler.
    """
    def query(self, query, timeout=None, **kwargs):
        request_id = kwargs.get('request_id', -1)
        logger.info('[%d]%r.query(%r)', request_id, self, query)
        try:
            method = self.typeToMethod[query.type]
        except KeyError:
            return defer.fail(
                Failure(NotImplementedError(self.__class__ + " " + str(query.type))))
        else:
            return defer.maybeDeferred(method, query.name.name, timeout, **kwargs)

    def _lookup(self, name, cls, type, timeout, **kwargs):
        return defer.fail(NotImplementedError("ResolverBase._lookup"))

    def lookupAddress(self, name, timeout=None, **kwargs):
        return self._lookup(name, dns.IN, dns.A, timeout=timeout, **kwargs)

    def lookupIPV6Address(self, name, timeout=None, **kwargs):
        return self._lookup(name, dns.IN, dns.AAAA, timeout=timeout, **kwargs)

    def lookupAddress6(self, name, timeout=None, **kwargs):
        return self._lookup(name, dns.IN, dns.A6, timeout=timeout, **kwargs)

    def lookupMailExchange(self, name, timeout=None, **kwargs):
        return self._lookup(name, dns.IN, dns.MX, timeout=timeout, **kwargs)

    def lookupNameservers(self, name, timeout=None, **kwargs):
        return self._lookup(name, dns.IN, dns.NS, timeout=timeout, **kwargs)

    def lookupCanonicalName(self, name, timeout=None, **kwargs):
        return self._lookup(name, dns.IN, dns.CNAME, timeout=timeout, **kwargs)

    def lookupMailBox(self, name, timeout=None, **kwargs):
        return self._lookup(name, dns.IN, dns.MB, timeout=timeout, **kwargs)

    def lookupMailGroup(self, name, timeout=None, **kwargs):
        return self._lookup(name, dns.IN, dns.MG, timeout=timeout, **kwargs)

    def lookupMailRename(self, name, timeout=None, **kwargs):
        return self._lookup(name, dns.IN, dns.MR, timeout=timeout, **kwargs)

    def lookupPointer(self, name, timeout=None, **kwargs):
        return self._lookup(name, dns.IN, dns.PTR, timeout=timeout, **kwargs)

    def lookupAuthority(self, name, timeout=None, **kwargs):
        return self._lookup(name, dns.IN, dns.SOA, timeout=timeout, **kwargs)

    def lookupNull(self, name, timeout=None, **kwargs):
        return self._lookup(name, dns.IN, dns.NULL, timeout=timeout, **kwargs)

    def lookupWellKnownServices(self, name, timeout=None, **kwargs):
        return self._lookup(name, dns.IN, dns.WKS, timeout=timeout, **kwargs)

    def lookupService(self, name, timeout=None, **kwargs):
        return self._lookup(name, dns.IN, dns.SRV, timeout=timeout, **kwargs)

    def lookupHostInfo(self, name, timeout=None, **kwargs):
        return self._lookup(name, dns.IN, dns.HINFO, timeout=timeout, **kwargs)

    def lookupMailboxInfo(self, name, timeout=None, **kwargs):
        return self._lookup(name, dns.IN, dns.MINFO, timeout=timeout, **kwargs)

    def lookupText(self, name, timeout=None, **kwargs):
        return self._lookup(name, dns.IN, dns.TXT, timeout=timeout, **kwargs)

    def lookupSenderPolicy(self, name, timeout=None, **kwargs):
        return self._lookup(name, dns.IN, dns.SPF, timeout=timeout, **kwargs)

    def lookupResponsibility(self, name, timeout=None, **kwargs):
        return self._lookup(name, dns.IN, dns.RP, timeout=timeout, **kwargs)

    def lookupAFSDatabase(self, name, timeout=None, **kwargs):
        return self._lookup(name, dns.IN, dns.AFSDB, timeout=timeout, **kwargs)

    def lookupZone(self, name, timeout=None, **kwargs):
        return self._lookup(name, dns.IN, dns.AXFR, timeout=timeout, **kwargs)

    def lookupNamingAuthorityPointer(self, name, timeout=None, **kwargs):
        return self._lookup(name, dns.IN, dns.NAPTR, timeout=timeout, **kwargs)

    def lookupAllRecords(self, name, timeout=None, **kwargs):
        return self._lookup(name, dns.IN, dns.ALL_RECORDS, timeout=timeout, **kwargs)


def patch_resolver(cls):
    for k, v in MyBaseResolver.__dict__.items():
        if k.startswith('lookup') or k in ('query', '_lookup'):
            if k not in cls.__dict__:
                setattr(cls, k, v)

    return cls


@patch_resolver
class Resolver(OriginResolver):
    def _lookup(self, name, cls, type, timeout, **kwargs):
        return super()._lookup(name, cls, type, timeout=timeout)

    def __repr__(self):
        ip, port = self.servers[0]
        cls = self.__class__.__name__
        return '<{cls} {ip}:{port}>'.format_map(locals())


class TCPResovlver(Resolver):
    def queryUDP(self, queries, timeout=None):
        if timeout is None:
            timeout = [10]
        return self.queryTCP(queries, timeout[0])


@patch_resolver
class ChainedResolver(OriginResolverChain):
    def _lookup(self, name, cls, type, timeout, **kwargs):
        """
        Build a L{dns.Query} for the given parameters and dispatch it
        to each L{IResolver} in C{self.resolvers} until an answer or
        L{error.AuthoritativeDomainError} is returned.

        @type name: C{str}
        @param name: DNS name to resolve.

        @type type: C{int}
        @param type: DNS record type.

        @type cls: C{int}
        @param cls: DNS record class.

        @type timeout: Sequence of C{int}
        @param timeout: Number of seconds after which to reissue the query.
            When the last timeout expires, the query is considered failed.

        @rtype: L{Deferred}
        @return: A L{Deferred} which fires with a three-tuple of lists of
            L{twisted.names.dns.RRHeader} instances.  The first element of the
            tuple gives answers.  The second element of the tuple gives
            authorities.  The third element of the tuple gives additional
            information.  The L{Deferred} may instead fail with one of the
            exceptions defined in L{twisted.names.error} or with
            C{NotImplementedError}.
        """
        if not self.resolvers:
            return defer.fail(DomainError())
        q = dns.Query(name, type, cls)
        d = self.resolvers[0].query(q, timeout, **kwargs)
        for r in self.resolvers[1:]:
            d = d.addErrback(ChainedFailureHandler(r.query, q, timeout, **kwargs))
        return d

    def __repr__(self):
        sub = '|'.join(map(repr, self.resolvers))
        return '<Chain {}>'.format(sub)


class ChainedFailureHandler:
    def __init__(self, resolver, query, timeout, **kwargs):
        self.resolver = resolver
        self.query = query
        self.timeout = timeout
        self.kwargs = kwargs

    def __call__(self, failure):
        # AuthoritativeDomainErrors should halt resolution attempts
        failure.trap(dns.DomainError, defer.TimeoutError, NotImplementedError)
        return self.resolver(self.query, self.timeout, **self.kwargs)


class ParallelResolver(MyBaseResolver):
    """
    Lookup an address using multiple L{IResolver}s in parallel.
    """
    def __init__(self, resolvers):
        """
        @type resolvers: L{list}
        @param resolvers: A L{list} of L{IResolver} providers.
        """
        super().__init__()
        self.resolvers = resolvers

    def _lookup(self, name, cls, type_, timeout, **kwargs):
        """
        Build a L{dns.Query} for the given parameters and dispatch it
        to each L{IResolver} in C{self.resolvers} until an answer or
        L{error.AuthoritativeDomainError} is returned.

        @type name: C{str}
        @param name: DNS name to resolve.

        @type type_: C{int}
        @param type_: DNS record type.

        @type cls: C{int}
        @param cls: DNS record class.

        @type timeout: Sequence of C{int}
        @param timeout: Number of seconds after which to reissue the query.
            When the last timeout expires, the query is considered failed.

        @rtype: L{Deferred}
        @return: A L{Deferred} which fires with a three-tuple of lists of
            L{twisted.names.dns.RRHeader} instances.  The first element of the
            tuple gives answers.  The second element of the tuple gives
            authorities.  The third element of the tuple gives additional
            information.  The L{Deferred} may instead fail with one of the
            exceptions defined in L{twisted.names.error} or with
            C{NotImplementedError}.
        """
        if not self.resolvers:
            return defer.fail(DomainError())

        q = dns.Query(name, type_, cls)
        d = defer.Deferred()
        ResolverHub(q, timeout, self.resolvers, d, **kwargs)
        return d

    def __repr__(self):
        sub = '|'.join(map(repr, self.resolvers))
        return '<Parallel {}>'.format(sub)


class ResolverHub:
    def __init__(self, query, timeout, resolvers, output: defer.Deferred, **kwargs):
        self.resolvers = resolvers
        self.inputs = []
        self.output = output
        self.succeeded = False
        self.errcount = 0

        log_prefix = '[%d]' % kwargs.get('request_id', -1)
        self.logger = PrefixedLogger(logger, log_prefix)

        for res in resolvers:
            d = res.query(query, timeout=timeout, **kwargs)
            d.addCallbacks(
                callback=self.success, callbackArgs=[res],
                errback=self.fail, errbackArgs=[res],
            )
            self.inputs.append(d)

    def success(self, result, resolver):
        self.logger.info(
            'success! %r, succeeded: %s, result: %s',
            resolver, self.succeeded, result)
        if not self.succeeded:
            self.succeeded = True
            self.output.callback(result)
            # cancel other attempts
            for d, res in zip(self.inputs, self.resolvers):
                if res is not resolver:
                    d.cancel()

    def fail(self, failure: Failure, resolver):
        if isinstance(failure.value, defer.CancelledError):
            self.logger.info('canceled! %r', resolver)
        else:
            self.logger.info(
                'fail! %r, succeeded: %s, failure: %s',
                resolver, self.succeeded, failure)
        if not self.succeeded:
            self.errcount += 1
            # all failed
            self.logger.info('all fail! %r', self.resolvers)
            if self.errcount == len(self.inputs):
                self.output.errback(failure)


class DualResovlver(MyBaseResolver):
    def __init__(self, cn_resolver, ab_resolver):
        super().__init__()
        self.cn_resolver = cn_resolver
        self.ab_resolver = ab_resolver

    def _lookup(self, name, cls, type_, timeout, **kwargs):
        q = dns.Query(name, type_, cls)
        output = defer.Deferred()
        DualHandler(
            self.cn_resolver.query(q, timeout=timeout, **kwargs),
            self.ab_resolver.query(q, timeout=timeout, **kwargs),
            output, **kwargs
        )
        return output

    def __repr__(self):
        return '<Dual cn={} ab={}>'.format(self.cn_resolver, self.ab_resolver)


def rrheader_to_ip(rr):
    payload = rr.payload
    if isinstance(payload, dns.Record_A):
        return IPv4Address(payload.dottedQuad())
    elif isinstance(payload, dns.Record_AAAA):
        return IPv6Address(socket.inet_ntop(socket.AF_INET6, payload.address))
    else:
        return None


class DualHandler:
    cn4_set = None
    cn6_set = None

    STATUS_FAIL = 'fail'
    STATUS_SUCC = 'succ'
    STATUS_UNK = 'unk'

    def __init__(
            self, cn_defered: defer.Deferred, ab_defered: defer.Deferred,
            output: defer.Deferred, **kwargs
    ):
        self.output = output
        log_prefix = '[%d]' % kwargs.get('request_id', -1)
        self.logger = PrefixedLogger(logger, log_prefix)
        self.sent = False

        self.cn_status = self.STATUS_UNK
        self.ab_status = self.STATUS_UNK
        self.cn_result = None
        self.ab_result = None

        cn_defered.addCallback(self.cn_success)
        cn_defered.addErrback(self.cn_fail)
        ab_defered.addCallback(self.ab_success)
        ab_defered.addErrback(self.ab_fail)

    @classmethod
    def is_cn_ip(cls, ip) -> bool:
        if isinstance(ip, IPv4Address):
            if cls.cn4_set is None:
                cls.cn4_set = IpSet.by_country('ipv4', 'CN')
            return ip in cls.cn4_set
        elif isinstance(ip, IPv6Address):
            if cls.cn6_set is None:
                cls.cn6_set = IpSet.by_country('ipv6', 'CN')
            return ip in cls.cn6_set
        else:
            assert not 'possible'

    def may_be_polluted(self, result):
        answers, authority, additional = result
        if len(answers) == 1:
            rr = answers[0]  # type: dns.RRHeader
            ip = rrheader_to_ip(rr)
            if ip is not None and not self.is_cn_ip(ip):
                self.logger.debug('maybe polluted: %s', ip)
                return True

        return False

    def status_updated(self, failure=None):
        #    Cn   Ab
        # [('U', 'U'),	W
        #  ('U', 'S'),	W
        #  ('U', 'F'),	W
        #  ('S', 'U'),	C
        #  ('S', 'S'),	C
        #  ('S', 'F'),	C
        #  ('F', 'U'),	W
        #  ('F', 'S'),	A
        #  ('F', 'F')]	F

        assert not self.sent

        if self.cn_status == self.STATUS_SUCC:
            self.logger.debug('use cn_result')
            self.output.callback(self.cn_result)
        elif (self.cn_status, self.ab_status) == (self.STATUS_FAIL, self.STATUS_SUCC):
            self.logger.debug('use ab_result')
            self.output.callback(self.ab_result)
        elif (self.cn_status, self.ab_status) == (self.STATUS_FAIL, self.STATUS_FAIL):
            self.logger.debug('both cn & ab failed')
            assert failure is not None
            self.output.errback(failure)
        else:
            # wait for the other resolver
            return

        self.sent = True

    def cn_success(self, result):
        if not self.sent:
            self.cn_result = result
            if self.may_be_polluted(result):
                self.cn_status = self.STATUS_FAIL
            else:
                self.cn_status = self.STATUS_SUCC

            self.status_updated()
        else:
            self.logger.debug('response already sent, drop cn result')

    def ab_success(self, result):
        if not self.sent:
            self.ab_result = result
            self.ab_status = self.STATUS_SUCC

            self.status_updated()
        else:
            self.logger.debug('response already sent, drop ab result')

    def cn_fail(self, failure):
        self.logger.debug('cn_failed: %s', failure)
        if not self.sent:
            self.cn_status = self.STATUS_FAIL
            self.status_updated(failure)

    def ab_fail(self, failure):
        self.logger.debug('ab_failed: %s', failure)
        if not self.sent:
            self.ab_status = self.STATUS_FAIL
            self.status_updated(failure)


def validate_domain_name(name: str):
    # TODO:
    # name = name.encode('utf-8').decode('idna').lower()
    return True


def parse_hosts_file(lines):
    def bad_line(lineno, line):
        logger.error('bad host file. line %d, %r', lineno, line)

    name2ip = defaultdict(list)
    for lineno, line in enumerate(lines):
        line = line.partition('#')[0].strip()
        if line:
            # TODO: distinguish between canonical name and aliases
            ip, *domains = line.split()
            if not domains:
                bad_line(lineno, line)
                continue

            try:
                ipobj = ip_address(ip)
            except ValueError:
                bad_line(lineno, line)
                continue

            for do in domains:
                name = do.lower()
                if not validate_domain_name(name):
                    logger.error('bad domain. line %d, domain %r', lineno, name)
                    continue

                if ipobj not in name2ip[name]:
                    name2ip[name].append(ipobj)

    return dict(name2ip)


def read_hosts_file(filename: str):
    with open(filename, 'rt') as fp:
        return parse_hosts_file(fp)


class HostsResolver(MyBaseResolver):
    """
    A resolver that services hosts(5) format files.

    ref: twisted.names.hosts.Resolver
    """
    def __init__(self, filename, *, ttl=60*60, reload=False):
        super().__init__()
        self.filename = filename
        self.ttl = ttl
        self._load_hosts()

        if reload:
            watch_modification(filename, self._load_hosts)

    def _load_hosts(self):
        logger.debug('loading hosts file: %s', self.filename)
        self.name2ip = read_hosts_file(self.filename)

    def _get_a_records(self, name: bytes):
        """
        Return a tuple of L{dns.RRHeader} instances for all of the IPv4
        addresses in the hosts file.
        """
        name_str = name.decode('utf8').lower()
        return tuple(
            dns.RRHeader(
                name, dns.A, dns.IN, self.ttl,
                dns.Record_A(addr.exploded, self.ttl))
            for addr in self.name2ip.get(name_str, [])
            if isinstance(addr, IPv4Address)
        )

    def _get_aaaa_records(self, name: bytes):
        """
        Return a tuple of L{dns.RRHeader} instances for all of the IPv6
        addresses in the hosts file.
        """
        name_str = name.decode('utf8').lower()
        return tuple(
            dns.RRHeader(
                name, dns.AAAA, dns.IN, self.ttl,
                dns.Record_AAAA(addr.exploded, self.ttl))
            for addr in self.name2ip.get(name_str, [])
            if isinstance(addr, IPv6Address)
        )

    def _get_all_records(self, name: bytes):
        ip_type_to_dns_type = {
            IPv4Address: dns.A,
            IPv6Address: dns.AAAA,
        }
        ip_type_to_record_type = {
            IPv4Address: dns.Record_A,
            IPv6Address: dns.Record_AAAA,
        }

        name_str = name.decode('utf8').lower()
        return tuple(
            dns.RRHeader(
                name, ip_type_to_dns_type[addr.__class__], dns.IN, self.ttl,
                ip_type_to_record_type[addr.__class__](addr.exploded, self.ttl))
            for addr in self.name2ip.get(name_str, [])
        )

    def _respond(self, name, records, **kwargs):
        """
        Generate a response for the given name containing the given result
        records, or a failure if there are no result records.

        @param name: The DNS name the response is for.
        @type name: C{str}

        @param records: A tuple of L{dns.RRHeader} instances giving the results
            that will go into the response.

        @return: A L{Deferred} which will fire with a three-tuple of result
            records, authority records, and additional records, or which will
            fail with L{dns.DomainError} if there are no result records.
        """
        if records:
            logger.info('[%d]answer from hosts: %r', kwargs.get('request_id', -1), records)
            return defer.succeed((records, (), ()))
        else:
            return defer.fail(Failure(dns.DomainError(name)))

    def lookupAddress(self, name, timeout=None, **kwargs):
        """
        Return any IPv4 addresses from C{self.name2ip} as L{Record_A} instances.
        """
        return self._respond(name, self._get_a_records(name), **kwargs)

    def lookupIPV6Address(self, name, timeout=None, **kwargs):
        """
        Return any IPv6 addresses from C{self.name2ip} as L{Record_AAAA} instances.
        """
        return self._respond(name, self._get_aaaa_records(name), **kwargs)

    def lookupAllRecords(self, name, timeout=None, **kwargs):
        """
        Return any addresses from C{self.name2ip} as either
        L{Record_AAAA} or L{Record_A} instances.
        """
        return self._respond(name, self._get_all_records(name), **kwargs)

    def lookupPointer(self, name, timeout=None, **kwargs):
        # TODO: ptr
        return defer.fail(NotImplementedError("HostsResolver.lookupPointer"))

    def __repr__(self):
        return '<Hosts: {}>'.format(self.filename)


class CachingResolver(MyBaseResolver):
    """
    A resolver that caches the output of another resolver.

    ref: twisted.names.cache.CacheResolver
    """
    def __init__(self, resolver, reactor=None):
        super().__init__()

        self.resolver = resolver
        if reactor is None:
            from twisted.internet import reactor
        self.reactor = reactor
        self.cache = dict()
        self.cancel = dict()

    def _lookup(self, name, cls, type_, timeout, **kwargs):
        # TODO: queue identical query
        request_id = kwargs.get('request_id', -1)

        def cache_miss(query):
            logger.debug('[%d]cache miss: %s', request_id, name.decode('latin1'))

            def add_to_cache(res):
                self.cache_result(query, res, **kwargs)
                return res

            d = self.resolver.query(query, timeout=timeout, **kwargs)
            return d.addCallback(add_to_cache)

        def adjust_ttl(rr: dns.RRHeader, diff):
            return dns.RRHeader(
                name=rr.name.name, type=rr.type, cls=rr.cls, ttl=int(rr.ttl - diff),
                payload=rr.payload,
            )

        q = dns.Query(name, type_, cls)
        try:
            when, (ans, auth, add) = self.cache[q]
        except KeyError:
            return cache_miss(q)
        else:
            now = self.reactor.seconds()
            diff = now - when
            try:
                result = (
                    [adjust_ttl(r, diff) for r in ans],
                    [adjust_ttl(r, diff) for r in auth],
                    [adjust_ttl(r, diff) for r in add],
                )
            except ValueError:
                # negative ttl
                return cache_miss(q)
            else:
                logger.debug('[%d]cache hit: %s', request_id, name.decode('latin1'))
                return defer.succeed(result)

    def cache_result(self, query, payload, cache_time=None, **kwargs):
        """
        Cache a DNS entry.

        @param query: a L{dns.Query} instance.
        @param payload: a 3-tuple of lists of L{dns.RRHeader} records, the
            matching result of the query (answers, authority and additional).
        @param cache_time: The time (seconds since epoch) at which the entry is
            considered to have been added to the cache. If L{None} is given,
            the current time is used.
        """
        minttl = min(
            map(lambda rr: rr.ttl, itertools.chain.from_iterable(payload)),
            default=0,
        )

        logger.debug('[%d]adding to cache: %r', kwargs.get('request_id', -1), query)
        self.cache[query] = (cache_time or self.reactor.seconds(), payload)

        if query in self.cancel:
            # reset count down
            self.cancel[query].cancel()
        self.cancel[query] = self.reactor.callLater(minttl, self.clear_entry, query)

    def clear_entry(self, query):
        del self.cache[query]
        del self.cancel[query]

    def clear(self):
        for d in self.cancel.values():
            d.cancel()
        for query in list(self.cancel.keys()):
            self.clear_entry(query)

    def __repr__(self):
        return '<Cache for={}>'.format(self.resolver.__class__.__name__)
