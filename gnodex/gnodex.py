#!/usr/bin/env python3

import argparse
import importlib
import sys

PACKAGE_NAME = 'gnodex'
SERVICES = ('client', 'ecdkg', 'server', 'signer')


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    for mod_name in SERVICES:
        mod = importlib.import_module('.'+mod_name, package=PACKAGE_NAME)
        subparser = subparsers.add_parser(mod.__name__[mod.__name__.rfind('.')+1:], description=mod.__doc__)
        mod.setup_argparser(subparser)

    args = parser.parse_args()

    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
