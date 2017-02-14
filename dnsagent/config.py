import os
from ipaddress import IPv4Address, IPv6Address, AddressValueError
from collections import namedtuple
from twisted.names.common import ResolverBase

from dnsagent.resolver import (
    Resolver, TCPResovlver, ParallelResolver, ChainedResolver,
    DualResovlver, HostsResolver, CachingResolver,
)
from dnsagent.server import MyDNSServerFactory


__all__ = ('make_resolver', 'chain', 'parallel', 'dual', 'hosts', 'cache', 'server')


class InvalidDnsServerString(Exception):
    pass


class DnsServerInfo(namedtuple('DnsServerInfo', 'proto host port'.split())):
    pass


def parse_dns_server_string(string: str) -> DnsServerInfo:
    # TODO: support domain name
    try:
        IPv6Address(string)
    except AddressValueError:
        pass
    else:
        return DnsServerInfo('udp', string, 53)

    if string.startswith('tcp://'):
        proto = 'tcp'
        string = string[len('tcp://'):]
    elif string.startswith('udp://'):
        string = string[len('udp://'):]
        proto = 'udp'
    else:
        proto = 'udp'

    if string.startswith('['):
        # ipv6
        try:
            idx = string.index(']')
        except ValueError:
            raise InvalidDnsServerString

        host = string[1:idx]
        try:
            IPv6Address(host)
        except AddressValueError:
            raise InvalidDnsServerString

        colon = idx + 1
        string = string[colon:]
    else:
        try:
            colon = string.index(':')
        except ValueError:
            colon = len(string)

        host = string[:colon]
        try:
            IPv4Address(host)
        except AddressValueError:
            raise InvalidDnsServerString

        string = string[colon:]

    if string:
        if string[0] != ':':
            raise InvalidDnsServerString
        try:
            port = int(string[1:])
        except ValueError:
            raise InvalidDnsServerString
    else:
        port = 53

    return DnsServerInfo(proto, host, port)


def make_resolver(arg):
    if isinstance(arg, str):
        server_info = parse_dns_server_string(arg)
        if server_info.proto == 'tcp':
            return TCPResovlver(servers=[(server_info.host, server_info.port)])
        else:
            return Resolver(servers=[(server_info.host, server_info.port)])
    else:
        assert isinstance(arg, ResolverBase)
        return arg


def chain(resolvers):
    return ChainedResolver([make_resolver(res) for res in resolvers])


def parallel(resolvers):
    return ParallelResolver([make_resolver(res) for res in resolvers])


def dual(cn, ab):
    cn = make_resolver(cn)
    ab = make_resolver(ab)
    return DualResovlver(cn, ab)


def hosts(filename_or_mapping=None, *, ttl=5*60, reload=False):
    if filename_or_mapping is None:
        if os.name == 'nt':
            filename = os.path.join(os.environ['SYSTEMROOT'], 'system32/drivers/etc/hosts')
        else:
            filename = '/etc/hosts'
        return HostsResolver(filename=filename, ttl=ttl, reload=reload)
    elif isinstance(filename_or_mapping, str):
        return HostsResolver(filename=filename_or_mapping, ttl=ttl, reload=reload)
    else:
        return HostsResolver(mapping=filename_or_mapping, ttl=ttl, reload=reload)


def cache(resolver):
    return CachingResolver(make_resolver(resolver))


def _make_server(resolver, *, verbose=5, timeout=None):
    return MyDNSServerFactory(resolver=resolver, verbose=verbose, resolve_timeout=timeout)


def server(
        resolver, *, port=None, interface=None, binds=None,
        verbose=5, timeout=None
):
    if binds is None:
        if port is None:
            port = 53
        if interface is None:
            interface = '127.0.0.1'
        binds = [(interface, port)]
    else:
        assert port is interface is None

    return (
        _make_server(make_resolver(resolver), verbose=verbose, timeout=timeout),
        binds,
    )
