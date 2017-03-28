#!/usr/bin/env python3

import sys
from server import master_state_service
from client import trade_client

services = {
    'client': trade_client,
    'server': master_state_service,
}

def print_usage():
    print("Usage: gnodex.py [SERVICE] [OPTIONS...]")
    print("Services: client server")

def main():
    argc = len(sys.argv)
    if (argc < 2):
        print("Please specify a service to run.")
        print_usage()
        return

    service = sys.argv[1]
    if (service in services.keys()):
        entryPoint = services[service]
        entryPoint()
    else:
        print("Unknown service specified: " + service)
        print_usage()
        return



if __name__ == "__main__":
    main()