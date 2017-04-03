import socket, ssl, rlp, threading, certs
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_v1_5
from Cryptodome.Hash import SHA256
from models import Order, Receipt, SignedReceipt


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
    t = threading.Timer(interval=5.0, function=send_batch)
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
        receipt_round = -1
        with order_list_lock:
            orders.append(order)
            receipt_round = current_round
        # Create Receipt
        order_hash = SHA256.new(str(data).encode('UTF-8'))
        print("DIGEST: " + str(order_hash.digest()))
        receipt = Receipt(receipt_round, order_hash.digest())
        # Sign Receipt
        receipt_rlp_encoded = rlp.encode(receipt)
        receipt_hash = SHA256.new(str(receipt_rlp_encoded).encode('UTF-8'))
        receipt_signature = pkcs.sign(receipt_hash)
        # Create Signed Receipt
        signed_receipt = SignedReceipt(receipt, receipt_signature)
        signed_receipt_rlp_encoded = rlp.encode(signed_receipt)
        ssl_sock.send(signed_receipt_rlp_encoded)
        print("RESP: " + str(signed_receipt))


# Send off current batch to signing services
def send_batch():
    global current_round

    with order_list_lock:
        print("SEND BATCH!")
        # communicate with signing service
        current_round += 1
    # Create order batch submission timer
    t = threading.Timer(interval=5.0, function=send_batch)
    t.start()
