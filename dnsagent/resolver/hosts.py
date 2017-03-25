from collections import defaultdict
from ipaddress import ip_address, IPv4Address, IPv6Address
from typing import Dict, Union, List

from twisted.internet import defer
from twisted.names import dns
from twisted.python.failure import Failure

from dnsagent import logger
from dnsagent.resolver.base import BaseResolver
from dnsagent.utils import watch_modification


__all__ = ('HostsResolver',)


Name2IpListType = Dict[str, List[Union[IPv4Address, IPv6Address]]]


def validate_domain_name(name: str):
    # TODO:
    # name = name.encode('utf-8').decode('idna').lower()
    return True


def parse_hosts_file(lines) -> Name2IpListType:
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
    def __init__(self, *, filename=None, mapping=None, ttl=60*60, reload=False):
        super().__init__()
        self.filename = filename
        self.ttl = ttl

        if filename is not None:
            assert mapping is None
            self._load_hosts()
            if reload:
                watch_modification(filename, self._load_hosts)
        elif mapping is not None:
            self.name2iplist = dict()   # type: Name2IpListType
            for domain, value in mapping.items():
                if isinstance(value, str):
                    value = [value]
                self.name2iplist[domain.lower()] = [ip_address(ip) for ip in value]

    def _load_hosts(self):
        logger.debug('loading hosts file: %s', self.filename)
        self.name2iplist = read_hosts_file(self.filename)

    _ipversion_to_dns_type = {
        4: dns.A, 6: dns.AAAA,
    }
    _ipversion_to_record_type = {
        4: dns.Record_A, 6: dns.Record_AAAA,
    }

    def _get_records(self, name: Union[str, bytes], ip_versions):
        if isinstance(name, bytes):
            name_str, name_bytes = name.decode('ascii').lower(), name
        else:
            name_str, name_bytes = name, name.encode('idna')

        return tuple(
            dns.RRHeader(
                name_bytes, self._ipversion_to_dns_type[addr.version], dns.IN, self.ttl,
                self._ipversion_to_record_type[addr.version](addr.exploded, self.ttl),
            )
            for addr in self.name2iplist.get(name_str, [])
            if addr.version in ip_versions
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
        return self._respond(name, self._get_records(name, {4}), **kwargs)

    def lookupIPV6Address(self, name, timeout=None, **kwargs):
        """
        Return any IPv6 addresses from C{self.name2ip} as L{Record_AAAA} instances.
        """
        return self._respond(name, self._get_records(name, {6}), **kwargs)

    def lookupAllRecords(self, name, timeout=None, **kwargs):
        """
        Return any addresses from C{self.name2ip} as either
        L{Record_AAAA} or L{Record_A} instances.
        """
        return self._respond(name, self._get_records(name, {4, 6}), **kwargs)

    def lookupPointer(self, name, timeout=None, **kwargs):
        # TODO: ptr
        return defer.fail(NotImplementedError("HostsResolver.lookupPointer"))

    def __repr__(self):
        return '<Hosts: {}>'.format(self.filename)
