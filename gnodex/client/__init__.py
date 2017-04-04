"""Trade client"""

from .client import trade_client

def setup_argparser(parser):
    parser.set_defaults(func=trade_client)
