import argparse
from ipaddress import ip_address
from itertools import chain
import logging
from multiprocessing import Process, Queue
from time import perf_counter
import statistics
from typing import Tuple, List, Optional

from dnsagent.app import App, init_log
from dnsagent.resolver import HostsResolver, ExtendedResolver, TCPExtendedResolver
from dnsagent.server import MyDNSServerFactory
from dnsagent.socks import get_client_endpoint
from dnsagent.utils import get_reactor

from twisted.internet import defer
from twisted.internet.endpoints import connectProtocol
from twisted.internet.protocol import Protocol
from twisted.python.failure import Failure


init_log()
logging.getLogger().setLevel(logging.ERROR)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

DEFAULT_SERVER_ADDR = ('127.0.1.88', 5353)
_server_process = None


def gen_host_name(num: int):
    return 'a%08d' % (num % int(1e8))


def gen_ip_address(num: int):
    return str(ip_address(0x7f000001 + (num % int(1e8))))


def run_server(bind: Tuple[str, int]):
    logger.info('starting server on %r', bind)

    mapping = dict((gen_host_name(i), gen_ip_address(i)) for i in range(10000))
    resolver = HostsResolver(mapping=mapping)
    server = MyDNSServerFactory(resolver=resolver)

    reactor = get_reactor()
    app = App(reactor=reactor)
    app.start((server, [bind]))

    reactor.run()


def wait_for_server(addr, retries=20, timeout=0.2, d=None):
    # TODO: merge this with dnsagent.tests.test_socks.SSRunner#wait_for_ss
    def connected(result):
        logger.debug('server up on %r', addr)
        protocol.transport.loseConnection()
        d.callback(addr)
        return result

    def failed(ignore):
        logger.debug('dns server not started. retries left: %d', retries - 1)
        reactor.callLater(
            timeout, wait_for_server,
            addr=addr, retries=(retries - 1), timeout=timeout, d=d,
        )

    reactor = get_reactor()
    d = d or defer.Deferred()

    if retries <= 0:
        d.errback(Exception('dns server not started on %r' % addr))
    else:
        protocol = Protocol()
        connect_d = connectProtocol(
            get_client_endpoint(
                reactor, addr, timeout=timeout),
            protocol,
        )
        connect_d.addCallbacks(connected, failed)

    return d


class QueryRunner:
    def __init__(
            self, addr: Tuple[str, int], count: int, concurrency=100,
            tcp_only=False, no_reuse_resolver=False,
            reactor=None, **extra
    ):
        assert count > 0 and concurrency > 0
        self.addr = addr
        self.count = count
        self.concurrency = concurrency
        self.tcp_only = tcp_only
        self.no_reuse_resolver = no_reuse_resolver
        self.reactor = get_reactor(reactor)

        self._resolver = None
        self.done = defer.Deferred()
        self.results = [None] * self.count      # type: List[Optional[float]]
        self.waitting = 0
        self.finished = 0
        self.started = 0

    def run(self):
        self.tick()
        return self.done

    def tick(self):
        if self.started < self.count:
            n = min(self.concurrency - self.waitting, self.count - self.started)
            for _ in range(n):
                self.waitting += 1
                self.spawn(self.started)
                self.started += 1
        else:
            assert self.started == self.count
            if self.finished == self.count:
                assert self.waitting == 0
                self.done.callback(self.results)

    def spawn(self, index):
        hostname = gen_host_name(index).encode()
        d = self.get_resolver().lookupAddress(hostname)
        d.addCallbacks(
            callback=self.got_answer, callbackArgs=(index, perf_counter()),
            errback=self.failed,
        ).addErrback(self.unexpected)

    def got_answer(self, answer, index: int, started_time: float):
        diff = perf_counter() - started_time
        self.results[index] = diff
        self.finished_one()

    def failed(self, err):
        self.finished_one()

    def finished_one(self):
        self.finished += 1
        self.waitting -= 1
        self.tick()

    def unexpected(self, err):
        logger.error('unhandled exception: %r', err)
        self.done.errback(err)
        return err

    def get_resolver(self):
        if not self._resolver or self.no_reuse_resolver:
            resolver_cls = ExtendedResolver if not self.tcp_only else TCPExtendedResolver
            self._resolver = resolver_cls(servers=[self.addr], reactor=self.reactor)
        return self._resolver


RunQueryResultType = Tuple[float, List[Optional[float]]]


def run_query(server_addr, inqueue: Queue, outqueue: Queue):
    addr, options = inqueue.get()
    logger.info('run_query() begins')

    def got_result(result: List[Optional[float]]):
        diff = perf_counter() - started_time
        logger.info('%d requests finished in %.3f s', options.count, diff)
        outqueue.put((diff, result))

    querier = QueryRunner(addr=server_addr, **vars(options))
    started_time = perf_counter()
    d = querier.run()
    d.addCallback(got_result)

    reactor = get_reactor()
    reactor.run()


def process_results(results: List[RunQueryResultType], options):
    def convert_none(arg):
        if arg is None:
            return float('+inf')
        else:
            return arg

    total_queries = options.process * options.count
    concurrency = options.process * options.concurrency
    avg_process_time = statistics.mean(process_time for process_time, _ in results)
    qps = total_queries / avg_process_time

    proc_query_times_cat = chain.from_iterable(times for _, times in results)
    query_times = sorted(map(convert_none, proc_query_times_cat))

    failure_rate = sum(int(t == float('+inf')) for t in query_times) / total_queries

    median_query_time = statistics.median(query_times)

    print('options: ', options)

    interesting_vars = [
        'qps', 'failure_rate', 'median_query_time', 'total_queries', 'concurrency',
    ]
    for name in interesting_vars:
        value = locals()[name]
        print('{name}: {value}'.format_map(locals()))

    # TODO: print bar chart of query time


def run_controller(server_addr, options):
    def server_ready(ignore):
        for inq, outq, proc in queriers:
            inq.put((server_addr, options))

        results = []     # type: List[Tuple[float, List[Optional[float]]]
        for inq, outq, proc in queriers:
            results.append(outq.get(timeout=60))
            proc.terminate()

        try:
            process_results(results, options)
        except Exception:
            logger.exception('process_result()')

    def server_failed(err):
        logger.error('failed to start server: %r', err)
        for _, _, proc in queriers:
            proc.terminate()

    def teardown(result):
        if isinstance(result, Failure):
            logger.error('unhandled error: %r', result)
            reactor.stop()

        if _server_process:
            _server_process.terminate()
        reactor.stop()

    queriers = []   # type: List[Tuple[Queue, Queue, Process]]
    for n in range(options.process):
        inqueue, outqueue = Queue(), Queue()
        client = Process(target=run_query, args=(server_addr, inqueue, outqueue))
        client.start()
        queriers.append((inqueue, outqueue, client))

    d = wait_for_server(server_addr)
    d.addCallbacks(server_ready, server_failed).addBoth(teardown)

    reactor = get_reactor()
    reactor.run()


def parse_args():
    parser = argparse.ArgumentParser()

    modes = parser.add_mutually_exclusive_group()
    modes.add_argument(
        '-s', '--server', dest='mode', action='store_const', const='server',
        help='server only mode',
    )
    modes.add_argument(
        '-c', '--client', dest='mode', action='store_const', const='client',
        help='client only mode',
    )

    parser.add_argument(
        '--address', help='server address',
    )
    parser.add_argument(
        '-p', '--process', default=2, type=int,
        help='number of client process',
    )
    parser.add_argument(
        '-n', '--count', default=4000, type=int,
        help='number of queries to run per process',
    )
    parser.add_argument(
        '--con', '--concurrency', dest='concurrency', default=500, type=int,
        help='maximum concurrent queries per process',
    )
    parser.add_argument(
        '--tcp-only', default=False, action='store_true',
        help='only use TCP for query',
    )
    parser.add_argument(
        '--no-reuse-resolver', default=False, action='store_true',
        help='use a new resolver for every query',
    )

    return parser.parse_args()


def main():
    global _server_process

    options = parse_args()
    if options.address:
        host, port = options.address.split(':')
        port = int(port)
        server_addr = host, port    # type: Tuple[str, int]
    else:
        server_addr = DEFAULT_SERVER_ADDR

    if options.mode == 'server':
        run_server(server_addr)
    else:
        if options.mode != 'client':
            _server_process = Process(target=run_server, args=(server_addr,))
            _server_process.start()

        run_controller(server_addr, options)


if __name__ == '__main__':
    main()
