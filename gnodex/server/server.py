import socket, ssl, rlp, threading, certs
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_v1_5
from Cryptodome.Hash import SHA256
from models import Order, Receipt, SignedReceipt, Batch, SignedBatch, Signature
from util import sign_rlp, sha256_utf8


def master_state_service():
    global key
    global orders
    global order_list_lock
    global current_round

    # Start listening for connections
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', 31337))
    sock.listen()

    # Load private key for signatures
    key = RSA.import_key(open(certs.path_to('server.key'), 'rb').read())

    # Create order buffer
    orders = list()
    order_list_lock = threading.RLock()
    current_round = 0

    # Create order batch submission timer
    t = threading.Timer(interval=15.0, function=send_batch)
    t.start()

    # Accept connections and start handling them in own thread
    print("Gnodex Master State Server Started")
    while True:
        new_sock, addr = sock.accept()
        thread = threading.Thread(target=handle_client, args=(new_sock, addr))
        thread.start()


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
        # Receive order
        data = ssl_sock.recv()
        print("RECV: " + str(data))
        order = rlp.decode(data, Order)
        print("DECD: " + str(order))
        receipt_round = None
        with order_list_lock:
            orders.append(order)
            receipt_round = current_round
        # Create Receipt
        order_hash = sha256_utf8(data)
        print("DIGEST: " + str(order_hash.digest()))
        receipt = Receipt(receipt_round, order_hash.digest())
        # Create Signed Receipt
        receipt_hash_signed = sign_rlp(pkcs, receipt)
        signed_receipt = SignedReceipt(receipt, receipt_hash_signed)
        ssl_sock.send(rlp.encode(signed_receipt))
        print("RESP: " + str(signed_receipt))

static_signers = [
    ('localhost', 1338),
    ('localhost', 1339),
    ('localhost', 1340),
]

# Send off current batch to signing services
def send_batch():
    pkcs = PKCS1_v1_5.new(key)  # TODO: Check if this object is thread-safe
    global current_round

    with order_list_lock:
        # Sign batch
        batch = Batch(current_round, orders)
        batch_hash_signed = sign_rlp(pkcs, batch)
        batch_signature = Signature('master_server', batch_hash_signed)
        batch_signed = SignedBatch([batch_signature], batch)
        batch_signed_rlp = rlp.encode(batch_signed)
        print("SEND BATCH!")
        # communicate with signing services
        current_round += 1
    # Create order batch submission timer
    t = threading.Timer(interval=15.0, function=send_batch)
    t.start()
