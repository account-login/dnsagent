from ipaddress import ip_address
import logging

import iprir
from twisted.internet import defer
from twisted.trial import unittest

from dnsagent.pubip import (
    get_public_ip, get_public_ip_from_netifaces, get_public_ip_from_web_api,
    BaseIpApi, DEFAULT_IP_APIS,
)
from dnsagent.tests import require_internet, clean_treq_connection_pool


logger = logging.getLogger(__name__)


def test_get_public_ip_from_netifaces():
    ip = get_public_ip_from_netifaces()
    if ip is None:
        logger.error('failed to get public ip netifaces')
    else:
        logger.info('public ip from netifaces: %s', ip)


@require_internet
class TestAllPublicIpWebApi(unittest.TestCase):
    def test_run(self):
        return defer.DeferredList(
            [api.get_ip() for api in DEFAULT_IP_APIS],
            fireOnOneErrback=True,
        )

    def tearDown(self):
        return clean_treq_connection_pool()


class FailedApi(BaseIpApi):
    def get_ip(self):
        return defer.fail(Exception('haha'))


class FakeApi(BaseIpApi):
    def get_ip(self):
        return defer.succeed(ip_address('1.2.3.4'))


class TestGetPublicIpFromWebApi(unittest.TestCase):
    def test_all_fail(self):
        def check(result):
            assert result is None

        apis = [FailedApi(), FailedApi()]
        d = get_public_ip_from_web_api(apis)
        return d.addCallback(check)

    def test_partial_fail(self):
        def check(result):
            assert result == ip_address('1.2.3.4')

        apis = [FailedApi(), FakeApi()]
        d = get_public_ip_from_web_api(apis)
        return d.addCallback(check)

    @require_internet
    def test_default(self):
        def check(result):
            logger.info('public ip from web api: %s', result)

        d = get_public_ip_from_web_api()
        return d.addCallback(check)

    def tearDown(self):
        return clean_treq_connection_pool()


@require_internet
class TestGetPublicIp(unittest.TestCase):
    def test_run(self):
        def check(ip):
            assert ip is not None
            assert not ip.is_private
            assert iprir.by_ip(ip) is not None
            logger.info('get_public_ip() got %s', ip)

        d = get_public_ip()
        return d.addCallback(check)

    def tearDown(self):
        return clean_treq_connection_pool()
