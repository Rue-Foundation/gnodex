import socket
import rlp
import threading
import certs
import sys
from cryptography.exceptions import InvalidSignature
from models import BatchCommitment, SignedBatch, Signature
from util import crypto, ssl_context, merkle_helper
from util.ssl_sock_helper import recv_ssl_msg, send_ssl_msg

def signer_service(args):
    global private_key
    global instance_id
    global last_round

    last_round = -1

    instance_id = args.id

    if instance_id < 0:
        print("Instance ID must be non-negative!")
        return

    # Load private key for signatures
    private_key = crypto.load_private_key(certs.path_to('server.key'))

    # Start listening for connections
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', 31338 + instance_id))
    sock.listen()

    # Accept connections and start handling them in own thread
    print("Gnodex Signing Service %d Started" % instance_id)
    while True:
        try:
            new_sock, addr = sock.accept()
            thread = threading.Thread(target=handle_client, args=(new_sock, addr))
            thread.start()
        except KeyboardInterrupt:
            print("Signing Service %d Exit." % instance_id)
            # TODO: Kill other running threads
            break


def handle_client(sock, addr):
    ssl_sock = ssl_context.wrap_server_socket(sock, certs.path_to('server.crt'), certs.path_to('server.key'))

    # Receive batch
    data =  recv_ssl_msg(ssl_sock)
    signed_batch = rlp.decode(data, SignedBatch)
    print("BATCH RECEIVED")
    batch = signed_batch.batch
    commitment = batch.commitment

    # Empty signature
    commitment_signature = ''
    try:
        # Verify Merkle Tree construction
        merkle_tree = merkle_helper.merkle_tree_from_order_list(batch.orders)
        merkle_root = merkle_tree.build()
        if merkle_root != commitment.merkle_root:
            print("COULD NOT RECONSTRUCT MERKLE TREE")
            return
        # Verify server signature
        server_signature = signed_batch.signatures[0].signature
        public_key = crypto.load_public_cert_key(certs.path_to('server.crt'))
        crypto.verify(public_key, rlp.encode(commitment), server_signature)
        # All ok, sign commitment
        print("BATCH SIGNED")
        commitment_signature = crypto.sign_rlp(private_key, commitment)
    except InvalidSignature:
        print("COULD NOT VERIFY SERVER SIGNATURE!")
    finally:
        # Return result
        signature = Signature('signer_%d' % instance_id, commitment_signature)
        with ssl_sock:
            send_ssl_msg(ssl_sock, rlp.encode(signature))
        print("RESPONSE SENT")
