import socket
import threading
import certs
from server import client_handler, sig_collector
from jsonrpc import dispatcher
from util.rpc import handle_rpc_client


def master_state_service(args):
    # Start listening for connections
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', 31337))
    sock.listen()

    # Create order batch submission timer
    t = threading.Timer(interval=10.0, function=sig_collector.send_batch_to_signer_services)
    t.start()

    # Configure RPC dispatcher
    dispatcher.add_method(client_handler.return_confirmation, "return_confirmation")
    dispatcher.add_method(client_handler.receive_order, "receive_order")

    # Accept connections and start handling them in own thread
    print("Gnodex Master State Server Started")
    while True:
        new_sock = sock.accept()[0]
        thread = threading.Thread(
            target=handle_rpc_client,
            args=(new_sock, certs.path_to('server.crt'), certs.path_to('server.key'), dispatcher))
        thread.start()
