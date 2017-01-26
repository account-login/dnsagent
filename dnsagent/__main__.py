import sys
import logging
from argparse import ArgumentParser
from twisted.internet import reactor, defer
from twisted.names.dns import DNSDatagramProtocol
from twisted.python import log

from dnsagent import logger
from dnsagent.watcher import watch_modification


def eval_config_file(filename):
    result = dict()
    with open(filename, 'rt') as fp:
        exec(fp.read(), result)
    return result


class App:
    def __init__(self, reactor):
        self.reactor = reactor
        self.udp_port = None
        self.tcp_port = None
        self._is_running = False

    @property
    def running(self):
        return self._is_running

    def start(self, server_info):
        assert not self._is_running
        logger.info('starting server: %s', server_info)
        port, interface, factory, protocol = self._extract_server_info(server_info)
        self._start_udp(port, protocol, interface)
        self._start_tcp(port, factory, interface)
        logger.info('started')
        self._is_running = True

    @staticmethod
    def _extract_server_info(server_info):
        port = server_info.port
        interface = server_info.interface
        factory = server_info.server
        protocol = DNSDatagramProtocol(controller=factory)
        return port, interface, factory, protocol

    def _start_udp(self, port, protocol, interface):
        self.udp_port = self.reactor.listenUDP(port, protocol, interface=interface)
        logger.info('listening udp port %s', self.udp_port.port)

    def _start_tcp(self, port, factory, interface):
        self.tcp_port = self.reactor.listenTCP(port, factory, interface=interface)
        logger.info('listening tcp port %s', self.tcp_port.port)

    def restart(self, server_info):
        assert self._is_running
        logger.info('restarting: %s', server_info)
        self.reactor.callFromThread(self._restart, server_info)

    def _restart(self, server_info):
        port, interface, factory, protocol = self._extract_server_info(server_info)
        defer.maybeDeferred(self.udp_port.stopListening).addBoth(
            lambda ignore: self._start_udp(port, protocol, interface)
        )
        defer.maybeDeferred(self.tcp_port.stopListening).addBoth(
            lambda ignore: self._start_tcp(port, factory, interface)
        )


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


def main():
    ap = ArgumentParser(prog='dnsagent', description='A configurable dns proxy')
    ap.add_argument('-c', '--config', required=True, help='configuration file')
    ap.add_argument(
        '-r', '--reload', action='store_true',
        help='automatically reload configuration file')
    option = ap.parse_args()

    # Output twisted messages to Python standard library logging module.
    log.PythonLoggingObserver().start()

    app = App(reactor)
    loader = ConfigLoader(option.config, app, reload=option.reload)
    succ = loader.load()
    if not succ:
        logger.error('loading server failed. config file: %s', option.config)
        raise SystemExit(1)

    reactor.run()


def enable_log():
    # Initialize coloredlogs.
    try:
        import coloredlogs
    except ImportError:
        logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    else:
        coloredlogs.install(level=logging.DEBUG)


def disable_log():
    try:
        import coloredlogs
    except ImportError:
        logging.basicConfig(stream=sys.stderr, level=logging.CRITICAL)
    else:
        coloredlogs.set_level(logging.CRITICAL)


if __name__ == '__main__':
    main()
