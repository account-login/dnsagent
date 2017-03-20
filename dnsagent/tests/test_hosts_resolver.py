import os
import tempfile

from dnsagent.config import hosts
from dnsagent.resolver.hosts import HostsResolver, parse_hosts_file
from dnsagent.tests import iplist, BaseTestResolver


def test_parse_hosts_file():
    name2ip = parse_hosts_file('''
        127.0.0.1   localhost loopback
        ::1         localhost   # asdf
        127.0.0.1   localhost loopback  # duplicated

        # asdf
        0.0.0.0     a b
        0.0.0.1     c a

        # bad lines
        0.0.0.256 asdf
        0.0.0.0
    '''.splitlines())
    assert name2ip == dict(
        localhost=iplist('127.0.0.1', '::1'),
        loopback=iplist('127.0.0.1'),
        a=iplist('0.0.0.0', '0.0.0.1'),
        b=iplist('0.0.0.0'),
        c=iplist('0.0.0.1'),
    )


class TestHostsResolver(BaseTestResolver):
    def setUp(self):
        super().setUp()

        hosts_string = '''
            127.0.0.1   localhost loopback
            ::1         localhost   # asdf
        '''
        self.setup_resolver(hosts_string)

    def setup_resolver(self, hosts_string):
        fd, hosts_file = tempfile.mkstemp(prefix='hosts_', suffix='.txt', text=True)
        os.write(fd, hosts_string.encode('utf8'))
        os.close(fd)
        self.resolver = HostsResolver(filename=hosts_file)
        self.addCleanup(os.unlink, hosts_file)

    def test_resolve(self):
        self.check_a('localhost', iplist('127.0.0.1'))
        self.check_aaaa('localhost', iplist('::1'))
        self.check_all('localhost', iplist('127.0.0.1', '::1'))
        self.check_a('loopback', iplist('127.0.0.1'))

        self.check_a('asdf.asdf', fail=True)


class TestHostResolverMapping(BaseTestResolver):
    def setUp(self):
        super().setUp()
        self.resolver = HostsResolver(mapping=dict(ASDF='1.2.3.4', localhost='::1'))

    def test_resolve(self):
        self.check_a('asdf', iplist('1.2.3.4'))
        self.check_aaaa('LocalHost', iplist('::1'))
        self.check_a('qwer', fail=True)


def test_config_hosts():
    # use system hosts file
    resolver = hosts()
    assert os.path.exists(resolver.filename)

    resolver = hosts(dict(ABC='1.2.3.4'))
    assert resolver.name2iplist == dict(abc=iplist('1.2.3.4'))


del BaseTestResolver
