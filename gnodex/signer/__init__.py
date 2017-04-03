"""Signing service"""

from .signer import signer_service

def setup_argparser(parser):
    parser.set_defaults(func=signer_service)
    parser.add_argument('id', type=int, help='The ID of the signer instance')
