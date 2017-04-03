def main():
    import argparse
    import asyncio
    import logging
    import signal
    import sys

    import bitcoin

    from . import util, networking, ecdkg

    supparser = argparse.ArgumentParser()
    parsers = supparser.add_subparsers()
    parser = parsers.add_parser('ecdkg', description='Distributedly generate some keys yo')
    parser.add_argument('--host', nargs='?', default='0.0.0.0',
                        help='Hostname to serve on (default: %(default)s)')
    parser.add_argument('-p', '--port', type=int, nargs='?', default=8000,
                        help='Port no. to serve on (default: %(default)s)')
    parser.add_argument('--log-level', type=int, nargs='?', default=logging.INFO,
                        help='Logging level (default: %(default)s)')
    parser.add_argument('--private-key-file', nargs='?', default='private.key',
                        help='File to load private key from (default: %(default)s)')
    parser.add_argument('--addresses-file', nargs='?', default='addresses.txt',
                        help='File to load accepted eth addresses from (default: %(default)s)')
    parser.add_argument('--locations-file', nargs='?', default='locations.txt',
                        help='File containing network locations to attempt connecting with (default: %(default)s)')
    args = supparser.parse_args()


    logging.basicConfig(level=args.log_level, format='%(message)s')

    ecdkg.private_key = util.get_or_generate_private_value(args.private_key_file)
    own_public_key = bitcoin.fast_multiply(bitcoin.G, ecdkg.private_key)
    own_address = util.curve_point_to_eth_address(own_public_key)
    ecdkg.accepted_addresses = util.get_addresses(args.addresses_file)
    ecdkg.accepted_addresses.difference_update((own_address,))
    locations = util.get_locations(args.locations_file)


    logging.debug('own pubkey: ({}, {})'.format(*map(hex, own_public_key)))
    logging.info('own address: {}'.format(hex(own_address)))
    if ecdkg.accepted_addresses:
        logging.info('accepted addresses: {{\n    {}\n}}'.format(
            '\n    '.join(hex(a) for a in ecdkg.accepted_addresses)))
    else:
        logging.warn('not accepting any addresses')

    ssl_context = networking.set_ssl_using_key(ecdkg.private_key)


    def shutdown(signum, frame):
        logging.info('\nShutting down...')
        sys.exit()

    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, shutdown)


    loop = asyncio.get_event_loop()
    loop.run_until_complete(networking.server(args.host, args.port, loop=loop))
    for hostname, port in locations:
        loop.create_task(networking.attempt_to_establish_channel(hostname, port))

    try:
        loop.run_forever()
    except SystemExit:
        loop.run_until_complete(loop.shutdown_asyncgens())
        loop.stop()
        logging.info('Goodbye')
