import urllib.parse
from typing import Dict, List

from twisted.names import dns

from dnsagent import logger
from dnsagent.resolver import BaseResolver
from dnsagent.utils import patch_twisted_ssl_root_bug, sequence_deferred_call, get_treq


__all__ = ('HTTPSResolver',)


# TODO: socks5 proxy


class BadResponse(Exception):
    pass


class BadRData(Exception):
    pass


class HTTPSResolver(BaseResolver):
    API_BASE_URL = 'https://dns.google.com/resolve'

    def __init__(self, http_client=None):
        super().__init__()
        patch_twisted_ssl_root_bug()

        self.http_client = http_client or get_treq()

    def _lookup(self, name: bytes, cls, type_, timeout, **kwargs):
        d = self.make_request(name, cls, type_, timeout, **kwargs)
        return d.addCallback(self.decode_response)

    def make_request(self, name: bytes, cls, type_, timeout, **kwargs):
        treq = get_treq()
        url = self.make_request_url(name, cls, type_, **kwargs)
        return sequence_deferred_call([
            self.http_client.get,
            treq.json_content,
        ], url)

    def make_request_url(self, name: bytes, cls, type_, *, client_subnet=None, **kwargs):
        param = dict(name=name, type=type_)
        if client_subnet:
            param['edns_client_subnet'] = str(client_subnet)
        # TODO: cd flag

        return self.API_BASE_URL + '?' + urllib.parse.urlencode(param)

    @staticmethod
    def split_rdata(string) -> List[str]:
        in_quote = False
        escape = False
        ans = []
        word = ''
        for ch in string:
            last_escape, escape = escape, False
            if not in_quote:
                if ch == '"':
                    in_quote = True
                    continue
            elif not last_escape:
                if ch == '\\':
                    escape = True
                    continue
                elif ch == '"':
                    in_quote = False
                    continue

            if in_quote or not ch.isspace():
                word += ch
            elif word:
                ans.append(word)
                word = ''

        if escape or in_quote:
            raise BadRData('escape=%r, in_quote=%r' % (escape, in_quote))

        # append last word to ans
        if word:
            ans.append(word)
        return ans

    def decode_to_rrheader(self, entry: dict) -> dns.RRHeader:
        def strip_trailing_dot(string: str):
            # XXX: hacks
            if string and string[-1] == '.':
                string = string[:-1]
            return string

        name = strip_trailing_dot(entry['name'])
        header = dns.RRHeader(
            name=name.encode(),
            type=entry['type'],
            ttl=entry.get('TTL', 0),
        )

        record_type = dns.Message().lookupRecordType(header.type) or dns.UnknownRecord
        try:
            # XXX: may not work
            header.payload = record_type(
                *map(strip_trailing_dot, self.split_rdata(entry['data'])), ttl=header.ttl
            )
        except BadRData as exc:
            raise BadResponse from exc
        return header

    def decode_response(self, response: Dict):
        if 'Comment' in response:
            logger.debug('%s: comment from server: %s', type(self).__name__, response['Comment'])

        rcode = response['Status']
        if rcode != 0:
            raise self.exceptionForCode(rcode)(response)
        if response.get('TC', False):
            logger.error('truncated message from https: %r', response)

        return tuple(
            [self.decode_to_rrheader(entry) for entry in response.get(attr, [])]
            for attr in ('Answer', 'Authority', 'Additional')
        )
