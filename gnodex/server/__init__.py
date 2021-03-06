"""Master state service server"""

import threading
from .. import certs
from ..util import crypto, locking
from .service import master_state_service, State

"""Package-wide variables"""
public_key = None
private_key = None
orders = None
batches = None
matchings = None
matched_batches = None
current_state = None
state_lock = None

def init(args):
    global public_key
    global private_key
    global orders
    global batches
    global current_state
    global state_lock
    global matchings
    global matched_batches

    # Load public key for signature verification
    public_key = crypto.load_public_cert_key(certs.path_to('server.crt'))
    # Load private key for signatures
    private_key = crypto.load_private_key(certs.path_to('server.key'))

    # Create order buffer
    orders = list()

    # Create batch history
    batches = list()

    # create match buffer
    matchings = list()

    # Create matching history
    matched_batches = list()

    current_state = State.RECEIVE_ORDERS
    state_lock = locking.RWLock()

    return master_state_service(args)


def setup_argparser(parser):
    parser.set_defaults(func=init)
