from collections import defaultdict
from ipaddress import ip_address, IPv4Address, IPv6Address
from typing import Mapping

from twisted.internet import defer
from twisted.names import dns
from twisted.python.failure import Failure

from dnsagent import logger
from dnsagent.resolver.base import BaseResolver
from dnsagent.utils import watch_modification


__all__ = ('HostsResolver',)


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


class HostsResolver(BaseResolver):
    """
    A resolver that services hosts(5) format files.

    ref: twisted.names.hosts.Resolver
    """
    def __init__(self, *, filename=None, mapping: Mapping[str, str]=None, ttl=60*60, reload=False):
        super().__init__()
        self.filename = filename
        self.ttl = ttl

        if filename is not None:
            assert mapping is None
            self._load_hosts()
            if reload:
                watch_modification(filename, self._load_hosts)
        elif mapping is not None:
            self.name2ip = {
                domain.lower(): [ ip_address(ip) ]
                for domain, ip in mapping.items()
            }

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
