import socket, ssl, rlp, threading, certs, sys
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_v1_5
from Cryptodome.Hash import SHA256
from models import Batch



def signer_service():
    global key
    global instance_id
    global last_round

    last_round = -1

    # Find Signer instance
    if len(sys.argv) < 3:
        print("Please specify which signer instance is running.")
        print("OPTIONS: signer_instance_number")
        return

    instance_id = int(sys.argv[2])

    if instance_id < 0:
        print("Instance ID must be non-negative!")
        return

    # Load private key for signatures
    key = RSA.import_key(open(certs.path_to('server.key'), 'rb').read())

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
    pkcs = PKCS1_v1_5.new(key)  # TODO: Check if this object is thread-safe
    ssl_sock = ssl.wrap_socket(sock,
                               server_side=True,
                               certfile=certs.path_to('server.crt'),
                               keyfile=certs.path_to('server.key'),
                               ssl_version=ssl.PROTOCOL_TLSv1_2,
                               ciphers="ECDHE-RSA-AES256-GCM-SHA384")
    # Wait for input, and respond
    while True:
        # Receive batch
        data = ssl_sock.recv()
        print("RECV: " + str(data))
        order = rlp.decode(data, Batch)
        print("DECD: " + str(order))