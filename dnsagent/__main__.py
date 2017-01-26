import os
import sys
import logging
from argparse import ArgumentParser
from watchdog.events import FileSystemEventHandler, FileModifiedEvent
from watchdog.observers import Observer
from twisted.internet import reactor, defer
from twisted.names.dns import DNSDatagramProtocol
from twisted.python import log

from dnsagent import logger


def eval_config_file(filename):
    result = dict()
    with open(filename, 'rt') as fp:
        exec(fp.read(), result)
    return result


class ReloadHandler(FileSystemEventHandler):
    def __init__(self, filepath: str, runner: 'Runner'):
        self.filepath = os.path.normpath(filepath)
        self.runner = runner

    def on_modified(self, event: FileModifiedEvent):
        path = os.path.normpath(event.src_path)
        if path != self.filepath:
            return

        try:
            config = eval_config_file(path)
        except:
            logger.exception('eval configuration file failed')
            return

        try:
            server_info = config['SERVER']
        except KeyError:
            logger.error('No `SERVER` varible found in configuration file.')
            return

        self.runner.restart(server_info)


def watch_config_file(filepath: str, runner: 'Runner'):
    path = os.path.realpath(filepath)
    observer = Observer()
    observer.schedule(ReloadHandler(path, runner), os.path.dirname(path))
    observer.start()


class Runner:
    def __init__(self, reactor):
        self.reactor = reactor
        self.udp_port = None
        self.tcp_port = None

    def start(self, server_info):
        logger.info('starting server: %s', server_info)
        port, interface, factory, protocol = self._extract_server_info(server_info)
        self._start_udp(port, protocol, interface)
        self._start_tcp(port, factory, interface)
        logger.info('started')

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


def main():
    ap = ArgumentParser(prog='dnsagent', description='A configurable dns proxy')
    ap.add_argument('-c', '--config', required=True, help='configuration file')

    # TODO: auto reload config file
    option = ap.parse_args()
    config = eval_config_file(option.config)

    if config.get('LOG', False):
        enable_log()

    server_info = config['SERVER']

    runner = Runner(reactor)
    runner.start(server_info)

    watch_config_file(option.config, runner)

    reactor.run()


def enable_log():
    level = logging.DEBUG
    logging.basicConfig(stream=sys.stderr, level=level)
    # logging.getLogger('twisted').setLevel(logging.DEBUG)
    log.PythonLoggingObserver().start()

    # Initialize coloredlogs.
    try:
        import coloredlogs
    except ImportError:
        pass
    else:
        coloredlogs.install(level=level)


if __name__ == '__main__':
    main()
