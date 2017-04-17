"""Master state service server"""

from .service import master_state_service, State
from util import crypto, locking
import certs

"""Package-wide variables"""
public_key = None
private_key = None
orders = None
last_signed_batch = None
last_commitment = None
last_merkle_tree = None
last_order_digest_list = None
current_state = None
state_lock = None
current_round = None


def init(args):
    global public_key
    global private_key
    global orders
    global last_signed_batch
    global last_commitment
    global last_merkle_tree
    global last_order_digest_list
    global current_state
    global state_lock
    global current_round

    # Load public key for signature verification
    public_key = crypto.load_public_cert_key(certs.path_to('server.crt'))
    # Load private key for signatures
    private_key = crypto.load_private_key(certs.path_to('server.key'))

    # Create order buffer
    orders = list()

    last_signed_batch = None
    last_commitment = None
    last_merkle_tree = None
    last_order_digest_list = list()
    current_state = State.RECEIVE_ORDERS
    state_lock = locking.RWLock()
    current_round = 0

    return master_state_service(args)


def setup_argparser(parser):
    parser.set_defaults(func=init)
