import os
from typing import NamedTuple

from dnsagent.resolver import (
    ExtendedResolver, TCPExtendedResolver, ParallelResolver, ChainedResolver,
    DualResolver, HostsResolver, CachingResolver,
)
from dnsagent.server import MyDNSServerFactory
from dnsagent.socks import SocksProxy
from dnsagent.utils import parse_url

from twisted.names.common import ResolverBase


__all__ = ('make_resolver', 'chain', 'parallel', 'dual', 'hosts', 'cache', 'server')


def parse_proxy_string(string: str) -> SocksProxy:
    scheme, host, port = parse_url(string)
    scheme = scheme or 'socks5'
    assert scheme in ('socks5', 'socks')
    port = port or 1080
    return SocksProxy(host, port)


DnsServerInfo = NamedTuple('DnsServerInfo', [('proto', str), ('host', str), ('port', int)])


def parse_dns_server_string(string: str) -> DnsServerInfo:
    # TODO: support domain name
    scheme, host, port = parse_url(string)
    scheme = scheme or 'udp'
    assert scheme in ('tcp', 'udp')
    port = port or 53
    return DnsServerInfo(scheme, host, port)


def make_resolver(arg, proxy=None):
    if isinstance(arg, str):
        if isinstance(proxy, str):
            proxy = parse_proxy_string(proxy)

        server_info = parse_dns_server_string(arg)
        resolver_cls = dict(tcp=TCPExtendedResolver, udp=ExtendedResolver)[server_info.proto]
        return resolver_cls(servers=[(server_info.host, server_info.port)], socks_proxy=proxy)
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
    return DualResolver(cn, ab)


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
