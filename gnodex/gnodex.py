#!/usr/bin/env python3

import argparse
import importlib
import sys

SERVICES = ('client', 'ecdkg', 'server', 'signer')


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    for mod_name in SERVICES:
        mod = importlib.import_module(mod_name, package='.')
        subparser = subparsers.add_parser(mod.__name__, description=mod.__doc__)
        mod.setup_argparser(subparser)

    args = parser.parse_args()

    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
