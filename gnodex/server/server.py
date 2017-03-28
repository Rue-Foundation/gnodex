import socket, ssl, pickle, rlp, threading, certs
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_v1_5
from Cryptodome.Hash import SHA256
from models import Order

# One thread per client
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
        data = pickle.loads(ssl_sock.recv())  # TODO: Safe object loading
        print("RECV: " + str(data))
        order = rlp.decode(data, Order)
        print("DECD: " + str(order))
        orders.append(order)
        # Hash and sign
        hash = SHA256.new(data)
        resp = pkcs.sign(hash)
        ssl_sock.send(pickle.dumps(resp))
        print("RESP: " + str(resp))

def master_state_service():
    global key
    global orders
    # Start listening for connections
    sock = socket.socket()
    sock.bind(('', 31337))
    sock.listen()

    # Load private key for signatures
    key = RSA.import_key(open(certs.path_to('server.key'), 'rb').read())
    orders = list()

    # Accept connections and start handling them in own thread
    print("Gnodex Master State Server Started")
    while True:
        newsock, addr = sock.accept()
        thread = threading.Thread(target=handle_client, args=(newsock, addr))
        thread.start()