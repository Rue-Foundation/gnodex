import socket
import threading
from enum import Enum, auto
from jsonrpc import Dispatcher
from .. import certs
from .. import signer
from ..signer import server_handler
from ..util.rpc import handle_rpc_client_stateful, handle_rpc_state_changes


def signer_service(args):
    # Start listening for connections
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', 31338 + signer.instance_id))
    sock.listen()

    # Configure RPC dispatchers
    state_dispatchers = {
        State.RECEIVE_ORDER_BATCH: Dispatcher({
            "receive_batch": server_handler.receive_order_batch}),
        State.RECEIVE_MATCH_COLLECTION: Dispatcher({
            "receive_match_collection": server_handler.receive_match_collection}),
    }
    global_dispatcher = Dispatcher({})

    # Accept connections and start handling them in own thread
    print("Gnodex Signing Service %d Started" % signer.instance_id)
    thread = threading.Thread(
        target=handle_rpc_state_changes,
        args=(get_state_lock_func, set_state_func),
        daemon=True)
    thread.start()
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
                    get_state_lock_func))
            thread.setDaemon(True)
            thread.start()
        except KeyboardInterrupt:
            print("Signing Service %d Exit." % signer.instance_id)
            break


class State(Enum):
    RECEIVE_ORDER_BATCH = auto()
    RECEIVE_MATCH_COLLECTION = auto()


def get_state_lock_func():
    return (signer.current_state, signer.state_lock, signer.pending_states, signer.state_condition)


def set_state_func(state: State):
    signer.current_state = state
