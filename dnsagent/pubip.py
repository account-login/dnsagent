import logging
import json
import re
from ipaddress import ip_address, IPv4Address
from typing import Optional, Sequence

import netifaces
from twisted.internet import defer

from dnsagent.utils import sequence_deferred_call, get_treq


logger = logging.getLogger(__name__)


def get_public_ip():
    ip = get_public_ip_from_netifaces()
    if ip:
        return defer.succeed(ip)
    else:
        return get_public_ip_from_web_api()


def get_public_ip_from_netifaces() -> Optional[IPv4Address]:
    if_addresses = sum((
        netifaces.ifaddresses(ifname).get(netifaces.AF_INET, [])
        for ifname in netifaces.interfaces()), [])
    ips = (ip_address(x['addr']) for x in if_addresses)

    for ip in ips:
        if not ip.is_private:
            return ip


def get_public_ip_from_web_api(
        apis: Sequence['BaseIpApi'] = None, result_d=None) -> defer.Deferred():

    def retry(err):
        logger.debug('failed to get public ip from %r, reason=%r', first, err)
        get_public_ip_from_web_api(remainds, result_d)

    if apis is None:
        apis = DEFAULT_IP_APIS
    result_d = result_d or defer.Deferred()

    if len(apis) == 0:
        result_d.callback(None)
    else:
        first, *remainds = apis
        d = defer.maybeDeferred(first.get_ip)
        d.addCallbacks(result_d.callback, retry)

    return result_d


class BaseIpApi:
    API_URL = None  # type: str

    def get_ip(self) -> defer.Deferred:
        treq = get_treq()
        return sequence_deferred_call([
            treq.get,
            treq.text_content,
            self.decode,
        ], self.API_URL)

    def decode(self, text: str) -> IPv4Address:
        matched = next(re.finditer(r'\d+\.\d+\.\d+\.\d+', text))
        return ip_address(matched.group(0))


class TaobaoIpApi(BaseIpApi):
    API_URL = 'http://ip.taobao.com/service/getIpInfo.php?ip=myip'

    def decode(self, text: str):
        return ip_address(json.loads(text)['data']['ip'])


class SohuIpApi(BaseIpApi):
    API_URL = 'http://pv.sohu.com/cityjson?ie=utf-8'


class UstcBbsIpApi(BaseIpApi):
    API_URL = 'http://bbs.ustc.edu.cn/cgi-bin/myip'


class IpifyApi(BaseIpApi):
    API_URL = 'http://api.ipify.org/'


class WhatIsMyIpAddressApi(BaseIpApi):
    API_URL = 'http://ipv4bot.whatismyipaddress.com/'


DEFAULT_IP_APIS = [
    UstcBbsIpApi(),
    TaobaoIpApi(),
    SohuIpApi(),
    IpifyApi(),
    WhatIsMyIpAddressApi(),
]
