import socket
import threading
import certs
import server
from server import client_handler, matcher_handler, sig_collector
from jsonrpc import Dispatcher
from util.rpc import handle_rpc_client_stateful
from enum import Enum, auto


def master_state_service(args):
    # Start listening for connections
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', 31337))
    sock.listen()

    # Create order batch submission timer
    t = threading.Timer(interval=10.0, function=sig_collector.send_batch_to_signer_services)
    t.start()

    # Configure RPC dispatchers
    state_dispatchers = {
        State.RECEIVE_ORDERS: Dispatcher({
            "receive_order": client_handler.receive_order}),
        State.COLLECT_BATCH_SIGNATURES: Dispatcher({}),
        State.RETRIEVE_DKG_PK_FOR_ORDERS: Dispatcher({}),
        State.RECEIVE_MATCHES: Dispatcher({
            'receive_matching': matcher_handler.receive_matching}),
        State.COLLECT_MATCHINGS_SIGNATURES: Dispatcher({}),
        State.RETRIEVE_DKG_PK_FOR_MATCHINGS: Dispatcher({}),
        State.CHOOSE_OPTIMAL_MATCHING: Dispatcher({}),
    }
    global_dispatcher = Dispatcher({
        "return_confirmation": client_handler.return_confirmation,
    })

    # Accept connections and start handling them in own thread
    print("Gnodex Master State Server Started")
    while True:
        new_sock = sock.accept()[0]
        thread = threading.Thread(
            target=handle_rpc_client_stateful,
            args=(
                new_sock,
                certs.path_to('server.crt'),
                certs.path_to('server.key'),
                state_dispatchers,
                global_dispatcher,
                get_state_lock_func))
        thread.start()


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
