import os
from ipaddress import IPv4Address, IPv6Address, AddressValueError
from collections import namedtuple
from twisted.names.common import ResolverBase
from twisted.names.client import Resolver
from twisted.names.resolve import ResolverChain

from dnsagent.resolver import (
    ForceTCPResovlver, ParallelResolver, DualResovlver, HostsResolver, CachingResolver,
)
from dnsagent.server import TimeoutableDNSServerFactory


__all__ = ('chain', 'parallel', 'dual', 'hosts', 'cache', 'server')


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


def _make_resolver(arg):
    if isinstance(arg, str):
        server_info = parse_dns_server_string(arg)
        if server_info.proto == 'tcp':
            return ForceTCPResovlver(servers=[(server_info.host, server_info.port)])
        else:
            return Resolver(servers=[(server_info.host, server_info.port)])
    else:
        assert isinstance(arg, ResolverBase)
        return arg


def chain(resolvers):
    return ResolverChain([_make_resolver(res) for res in resolvers])


def parallel(resolvers):
    return ParallelResolver([_make_resolver(res) for res in resolvers])


def dual(cn, ab):
    cn = _make_resolver(cn)
    ab = _make_resolver(ab)
    return DualResovlver(cn, ab)


def hosts(filename=None, *, ttl=5*60, reload=False):
    if filename is None:
        if os.name == 'nt':
            filename = os.path.join(os.environ['SYSTEMROOT'], 'system32/driver/etc/hosts')
        else:
            filename = '/etc/hosts'
    return HostsResolver(filename, ttl=ttl, reload=reload)


def cache(resolver):
    resolver = _make_resolver(resolver)
    return chain([CachingResolver(resolver), resolver])


class ServerInfo(namedtuple('ServerInfo', 'server port interface'.split())):
    pass


def _make_server(resolver, *, verbose=5, timeout=None):
    return TimeoutableDNSServerFactory(
        clients=[resolver],
        verbose=verbose,
        resolve_timeout=timeout,
    )


def server(
        resolver, *, port=53, interface='127.0.0.1',
        verbose=5, timeout=None
):
    return ServerInfo(
        _make_server(
            _make_resolver(resolver), verbose=verbose, timeout=timeout,
        ),
        port,
        interface,
    )
