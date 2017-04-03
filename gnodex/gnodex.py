#!/usr/bin/env python3

import sys
from server import master_state_service
from client import trade_client
from signer import signer_service

services = {
    'client': trade_client,
    'server': master_state_service,
    'signer': signer_service,
}


def print_usage():
    print("Usage: gnodex.py [SERVICE] [OPTIONS...]")
    print("Services: " + ' '.join(sorted(services.keys())))


def main():
    argc = len(sys.argv)
    if argc < 2:
        print("Please specify a service to run.")
        print_usage()
        return

    service = sys.argv[1]
    if service in services.keys():
        entry_point = services[service]
        entry_point()
    else:
        print("Unknown service specified: " + service)
        print_usage()
        return


if __name__ == "__main__":
    main()
