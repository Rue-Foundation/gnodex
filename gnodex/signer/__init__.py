"""Signing service"""

import certs
from util import crypto, locking
from .service import signer_service, State

"""Package-wide variables"""
private_key = None
instance_id = None
current_state = None
state_lock = None
current_round = None


def init(args):
    global private_key
    global instance_id
    global current_state
    global state_lock
    global current_round

    current_state = State.RECEIVE_ORDER_BATCH
    state_lock = locking.RWLock()
    current_round = 0

    instance_id = args.id

    if instance_id < 0:
        print("Instance ID must be non-negative!")
        return

    # Load private key for signatures
    private_key = crypto.load_private_key(certs.path_to('server.key'))

    return signer_service(args)


def setup_argparser(parser):
    parser.set_defaults(func=init)
    parser.add_argument('id', type=int, help='The ID of the signer instance')
