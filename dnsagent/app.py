import sys
import logging
from logging.handlers import MemoryHandler
from argparse import ArgumentParser
from twisted.internet import defer
from twisted.names.dns import DNSDatagramProtocol
from twisted.python.log import PythonLoggingObserver

from dnsagent import logger
from dnsagent.utils import watch_modification, get_reactor


def eval_config_file(filename):
    result = dict()
    with open(filename, 'rt') as fp:
        exec(fp.read(), result)
    return result


class App:
    def __init__(self, reactor=None):
        self.reactor = get_reactor(reactor)
        self.ports = []
        self._is_running = False

    @property
    def running(self):
        return self._is_running

    def start(self, server_info):
        assert not self._is_running
        logger.info('starting server: %s', server_info)
        self._start(server_info)
        logger.info('started')
        self._is_running = True

    def _start(self, server_info):
        factory, binds = server_info
        self.ports.clear()
        for interface, port in binds:
            protocol = DNSDatagramProtocol(controller=factory)
            self.ports.append(self._start_udp(port, protocol, interface))
            self.ports.append(self._start_tcp(port, factory, interface))

    def _start_udp(self, port, protocol, interface):
        udp_port = self.reactor.listenUDP(port, protocol, interface=interface)
        logger.info('listening udp port %s', port)
        return udp_port

    def _start_tcp(self, port, factory, interface):
        tcp_port = self.reactor.listenTCP(port, factory, interface=interface)
        logger.info('listening tcp port %s', port)
        return tcp_port

    def restart(self, server_info):
        assert self._is_running
        logger.info('restarting: %s', server_info)
        self.reactor.callFromThread(self._restart, server_info)

    def stop(self):
        return defer.DeferredList(
            [ defer.maybeDeferred(port.stopListening) for port in self.ports ],
            consumeErrors=True,
        )

    def _restart(self, server_info):
        self.stop().addBoth(lambda ignore: self._start(server_info))


class ConfigLoader:
    def __init__(self, filename: str, app: App, *, reload=False):
        self.filename = filename
        self.app = app

        if reload:
            watch_modification(self.filename, self.load)

    def load(self):
        try:
            config = eval_config_file(self.filename)
        except:
            logger.exception('eval configuration file failed')
            return False

        try:
            server_info = config['SERVER']
        except KeyError:
            logger.error('No `SERVER` varible found in configuration file.')
            return False

        log_enabled = config.get('LOG', False)
        if log_enabled:
            enable_log()

        if self.app.running:
            self.app.restart(server_info)
        else:
            self.app.start(server_info)

        if not log_enabled:
            logger.info('disable logging.')
            disable_log()

        return True


def main(args=None):
    ap = ArgumentParser(prog='dnsagent', description='A configurable dns proxy')
    ap.add_argument('-c', '--config', required=True, help='configuration file')
    ap.add_argument(
        '-r', '--reload', action='store_true',
        help='automatically reload configuration file')
    ap.add_argument('--log', default=None, help='path to log file')
    option = ap.parse_args(args=args)

    init_log(option.log)

    reactor = get_reactor()
    app = App(reactor)
    loader = ConfigLoader(option.config, app, reload=option.reload)
    succ = loader.load()
    if not succ:
        logger.error('loading server failed. config file: %s', option.config)
        raise SystemExit(1)

    reactor.run()


LOG_FMT = '%(asctime)s.%(msecs)03d %(name)s[%(process)d] %(levelname)8s %(message)s'
LOG_DATE_FMT = '%Y-%m-%d %H:%M:%S'


def init_log(filename=None):
    import logging.handlers
    if filename is not None:
        file_handler = logging.FileHandler(filename)
        file_handler.setFormatter(logging.Formatter(fmt=LOG_FMT, datefmt=LOG_DATE_FMT))
        buf_handler = MemoryHandler(64, target=file_handler)
        logging.getLogger().addHandler(buf_handler)

    # Output twisted messages to Python standard library logging module.
    PythonLoggingObserver().start()

    # Initialize coloredlogs.
    try:
        import coloredlogs
    except ImportError:
        logging.basicConfig(
            stream=sys.stderr, level=logging.DEBUG, format=LOG_FMT, datefmt=LOG_DATE_FMT)
    else:
        coloredlogs.install(level=logging.DEBUG, fmt=LOG_FMT, datefmt=LOG_DATE_FMT)


def enable_log():
    logging.getLogger().setLevel(logging.DEBUG)


def disable_log():
    logging.getLogger().setLevel(logging.CRITICAL)
