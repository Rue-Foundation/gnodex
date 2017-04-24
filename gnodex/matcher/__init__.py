from .. import certs
from ..util import crypto
from .service import batch_matcher_service

public_key = None
private_key = None


def init(args):
    global public_key
    global private_key

    # Load public key for signature verification
    public_key = crypto.load_public_cert_key(certs.path_to('server.crt'))
    # Load private key for signatures
    private_key = crypto.load_private_key(certs.path_to('server.key'))

    return batch_matcher_service(args)


def setup_argparser(parser):
    parser.set_defaults(func=init)
