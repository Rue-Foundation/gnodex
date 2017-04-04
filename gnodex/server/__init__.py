"""Master state service server"""

from .server import master_state_service

def setup_argparser(parser):
    parser.set_defaults(func=master_state_service)
