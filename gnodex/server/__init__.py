"""Master state service server"""

import threading
from .. import certs
from ..util import crypto, locking
from .service import master_state_service, State

"""Package-wide variables"""
public_key = None
private_key = None
orders = None
state_lock = None
current_round = None
last_signed_batch = None
last_commitment = None
last_merkle_tree = None
last_order_digest_list = None
current_state = None

def init(args):
    global public_key
    global private_key
    global orders
    global state_lock
    global current_round
    global last_signed_batch
    global last_commitment
    global last_merkle_tree
    global last_order_digest_list
    global current_state

    # Load public key for signature verification
    public_key = crypto.load_public_cert_key(certs.path_to('server.crt'))
    # Load private key for signatures
    private_key = crypto.load_private_key(certs.path_to('server.key'))

    # Create order buffer
    orders = list()

    state_lock = locking.RWLock()
    current_round = 0
    last_signed_batch = None
    last_commitment = None
    last_merkle_tree = None
    last_order_digest_list = list()
    current_state = State.RECEIVE_ORDERS

    return master_state_service(args)


def setup_argparser(parser):
    parser.set_defaults(func=init)
