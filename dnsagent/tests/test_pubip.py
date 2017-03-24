from ipaddress import ip_address
import logging

import iprir
from twisted.internet import defer
from twisted.trial import unittest

from dnsagent.pubip import (
    get_public_ip, get_public_ip_from_netifaces, get_public_ip_from_web_api,
    BaseIpApi, DEFAULT_IP_APIS,
)
from dnsagent.tests import require_internet, need_clean_treq


logger = logging.getLogger(__name__)


def test_get_public_ip_from_netifaces():
    ip = get_public_ip_from_netifaces()
    if ip is None:
        logger.error('failed to get public ip from netifaces')
    else:
        logger.info('public ip from netifaces: %s', ip)


@require_internet
@need_clean_treq
class TestAllPublicIpWebApi(unittest.TestCase):
    @defer.inlineCallbacks
    def test_run(self):
        yield defer.DeferredList(
            [api.get_ip() for api in DEFAULT_IP_APIS],
            fireOnOneErrback=True,
        )


class FailedApi(BaseIpApi):
    def get_ip(self):
        return defer.fail(Exception('haha'))


class FakeApi(BaseIpApi):
    def get_ip(self):
        return defer.succeed(ip_address('1.2.3.4'))


@need_clean_treq
class TestGetPublicIpFromWebApi(unittest.TestCase):
    @defer.inlineCallbacks
    def test_all_fail(self):
        apis = [FailedApi(), FailedApi()]
        ip = yield get_public_ip_from_web_api(apis)
        assert ip is None

    @defer.inlineCallbacks
    def test_partial_fail(self):
        apis = [FailedApi(), FakeApi()]
        ip = yield get_public_ip_from_web_api(apis)
        assert ip == ip_address('1.2.3.4')

    @require_internet
    @defer.inlineCallbacks
    def test_default(self):
        ip = yield get_public_ip_from_web_api()
        logger.info('public ip from web api: %s', ip)


@require_internet
@need_clean_treq
class TestGetPublicIp(unittest.TestCase):
    def test_run(self):
        def check(ip):
            assert ip is not None
            assert not ip.is_private
            assert iprir.by_ip(ip) is not None
            logger.info('get_public_ip() got %s', ip)

        d = get_public_ip()
        return d.addCallback(check)
