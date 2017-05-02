import socket
import threading
from enum import Enum, auto
from jsonrpc import Dispatcher
from .. import certs
from .. import server
from ..server import client_handler, sig_collector
from ..util.rpc import handle_rpc_client_stateful
from . import matcher_handler


def master_state_service(args):
    # Start listening for connections
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', 31337))
    sock.listen()

    # Create order batch submission timer
    t = threading.Thread(target=sig_collector.send_batch_to_signer_services, daemon=True)
    t.start()

    # Configure RPC dispatchers
    state_dispatchers = {
        State.RECEIVE_ORDERS: Dispatcher({
            "receive_order": client_handler.receive_order
        }),
        State.COLLECT_BATCH_SIGNATURES: Dispatcher({}),
        State.RETRIEVE_DKG_PK_FOR_ORDERS: Dispatcher({}),
        State.RECEIVE_MATCHES: Dispatcher({
            'receive_matching': matcher_handler.receive_matching,
            'return_latest_signed_batch': matcher_handler.return_latest_signed_batch
        }),
        State.COLLECT_MATCHINGS_SIGNATURES: Dispatcher({}),
        State.RETRIEVE_DKG_PK_FOR_MATCHINGS: Dispatcher({}),
        State.CHOOSE_OPTIMAL_MATCHING: Dispatcher({}),
    }
    global_dispatcher = Dispatcher({
        "return_confirmation": client_handler.return_confirmation,
        "return_matching_confirmation": matcher_handler.return_matching_confirmation,
    })

    # Accept connections and start handling them in own thread
    print("Gnodex Master State Server Started")
    while True:
        try:
            new_sock = sock.accept()[0]
            thread = threading.Thread(
                target=handle_rpc_client_stateful,
                args=(
                    new_sock,
                    certs.path_to('server.crt'),
                    certs.path_to('server.key'),
                    state_dispatchers,
                    global_dispatcher,
                    get_state_lock_func),
                daemon=True)
            thread.start()
        except KeyboardInterrupt:
            print("Master State Service Exit.")
            break


def get_state_lock_func():
    return (server.current_state, server.state_lock)


class State(Enum):
    RECEIVE_ORDERS = auto()
    COLLECT_BATCH_SIGNATURES = auto()
    RETRIEVE_DKG_PK_FOR_ORDERS = auto()
    RECEIVE_MATCHES = auto()
    COLLECT_MATCHINGS_SIGNATURES = auto()
    RETRIEVE_DKG_PK_FOR_MATCHINGS = auto()
    CHOOSE_OPTIMAL_MATCHING = auto()
