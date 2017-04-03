import socket
import rlp
import threading
import certs
import sys
from cryptography.exceptions import InvalidSignature
from models import Batch, SignedBatch, Signature
from util import crypto, ssl_context


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
    data = ssl_sock.recv()
    print("RECV: " + str(data))
    signed_batch = rlp.decode(data, SignedBatch)
    print("DECD: " + str(signed_batch))
    # Verify server signature
    try:
        server_signature = signed_batch.signatures[0].signature
        public_key = crypto.load_public_cert_key(certs.path_to('server.crt'))
        crypto.verify(public_key, rlp.encode(signed_batch.batch), server_signature)
    except InvalidSignature:
        print("COULD NOT VERIFY SERVER SIGNATURE!")
        ssl_sock.send(rlp.encode(Signature(instance_id, '')))
        ssl_sock.close()
        return
    # Sign and return
    batch_hash_signed = crypto.sign_rlp(private_key, signed_batch.batch)
    signature = Signature('signer_%d' % instance_id, batch_hash_signed)
    ssl_sock.send(rlp.encode(signature))
    ssl_sock.close()
