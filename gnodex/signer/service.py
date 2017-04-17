import socket
import threading
import certs
import signer
from jsonrpc import dispatcher
from util.rpc import handle_rpc_client
from .server_handler import receive_batch


def signer_service(args):
    # Start listening for connections
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', 31338 + signer.instance_id))
    sock.listen()

    dispatcher.add_method(receive_batch, "receive_batch")

    # Accept connections and start handling them in own thread
    print("Gnodex Signing Service %d Started" % signer.instance_id)
    while True:
        try:
            new_sock = sock.accept()[0]
            thread = threading.Thread(
                target=handle_rpc_client,
                args=(new_sock, certs.path_to('server.crt'), certs.path_to('server.key'), dispatcher))
            thread.start()
        except KeyboardInterrupt:
            print("Signing Service %d Exit." % signer.instance_id)
            # TODO: Kill other running threads
            break
