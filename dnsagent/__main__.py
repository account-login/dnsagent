import sys
import logging
from argparse import ArgumentParser
from twisted.internet import reactor
from twisted.names.dns import DNSDatagramProtocol
from twisted.python import log


def eval_config_file(filename):
    result = dict()
    with open(filename, 'rt') as fp:
        exec(fp.read(), result)
    return result


def main():
    ap = ArgumentParser(prog='dnsagent', description='A configurable dns proxy')
    ap.add_argument('-c', '--config', required=True, help='configuration file')

    # TODO: auto reload config file
    option = ap.parse_args()
    config = eval_config_file(option.config)

    if config.get('LOG', False):
        enable_log()

    server_info = config['SERVER']

    interface = server_info.interface
    port = server_info.port

    factory = server_info.server
    protocol = DNSDatagramProtocol(controller=factory)

    reactor.listenUDP(port, protocol, interface=interface)
    reactor.listenTCP(port, factory, interface=interface)

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
