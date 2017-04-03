import socket
import ssl
import rlp
import threading
import certs
from cryptography.exceptions import InvalidSignature
from models import Receipt, SignedReceipt, Batch, SignedBatch, Signature, SignedOrder, Order
from util import crypto, ssl_context


def master_state_service(args):
    global private_key
    global orders
    global order_list_lock
    global current_round

    # Start listening for connections
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', 31337))
    sock.listen()

    # Load private key for signatures
    private_key = crypto.load_private_key(certs.path_to('server.key'))

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
    ssl_sock = ssl_context.wrap_server_socket(sock, certs.path_to('server.crt'), certs.path_to('server.key'))

    # Wait for input, and respond
    while True:
        # Receive order
        data = ssl_sock.recv()
        print("RECV: " + str(data))
        order = rlp.decode(data, SignedOrder)
        print("DECD: " + str(order))
        receipt_round = None
        with order_list_lock:
            orders.append(order)
            receipt_round = current_round
        # Create Receipt
        order_hash = crypto.sha256_utf8(data)
        print("DIGEST: " + str(order_hash))
        receipt = Receipt(receipt_round, order_hash)
        # Create Signed Receipt
        receipt_hash_signed = crypto.sign_rlp(private_key, receipt)
        signed_receipt = SignedReceipt(receipt, receipt_hash_signed)
        ssl_sock.send(rlp.encode(signed_receipt))
        print("RESP: " + str(signed_receipt))

static_signers = [
    ('localhost', 31338),
    ('localhost', 31339),
    ('localhost', 31340),
]


# Send off current batch to signing services
def send_batch():
    global current_round

    with order_list_lock:
        if orders:
            # Sign batch
            batch = Batch(current_round, orders, 'XYZ')
            batch_signature = crypto.sign_rlp(private_key, batch)
            signed_batch = SignedBatch(
                [Signature('master_server', batch_signature)],
                batch)

            signed_batch_rlp = rlp.encode(signed_batch)
            print("SEND BATCH! " + str(signed_batch) + "\n" + str(signed_batch_rlp))
            # Communicate with signing services
            for signer in static_signers:
                # Open SSL Connection
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

                ssl_sock = ssl_context.wrap_client_socket(sock, certs.path_to("server.crt"))

                try:
                    ssl_sock.connect(signer)
                except ConnectionError:
                    print("CONNECTION FAILED")
                    continue

                with ssl_sock:
                    print("CONNECTED TO SIGNER")
                    ssl_sock.send(signed_batch_rlp)
                    response = ssl_sock.recv()
                    signature = rlp.decode(response, Signature)
                    print("ID: " + str(signature.owner_id))
                    print("SIG: " + str(signature.signature))

                    public_key = crypto.load_public_cert_key(certs.path_to('server.crt'))

                    try:
                        crypto.verify(public_key, rlp.encode(batch), signature.signature)
                        print("SIGNATURE OK!")
                    except InvalidSignature:
                        print("SIGNATURE VERIFICATION FAILED!!")
            orders.clear()
        current_round += 1
    # Create order batch submission timer
    t = threading.Timer(interval=5.0, function=send_batch)
    t.start()
