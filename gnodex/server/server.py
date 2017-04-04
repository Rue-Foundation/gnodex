import socket
import rlp
import threading
import certs
from cryptography.exceptions import InvalidSignature
from models import Receipt, SignedReceipt, Batch, SignedBatch, Signature, SignedOrder, BatchCommitment
from util import crypto, ssl_context, merkle_helper
from util.ssl_sock_helper import recv_ssl_msg, send_ssl_msg, ssl_connect


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
    t = threading.Timer(interval=10.0, function=send_batch)
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
        data = recv_ssl_msg(ssl_sock)
        order = rlp.decode(data, SignedOrder)
        print("ORDER RECEIVED")
        receipt_round = None
        with order_list_lock:
            orders.append(order)
            receipt_round = current_round
        # Create Receipt
        order_hash = crypto.sha256_utf8(data)
        receipt = Receipt(receipt_round, order_hash)
        # Create Signed Receipt
        receipt_hash_signed = crypto.sign_rlp(private_key, receipt)
        signed_receipt = SignedReceipt(receipt, receipt_hash_signed)
        # Send response
        send_ssl_msg(ssl_sock, rlp.encode(signed_receipt))
        print("RECEIPT SENT")

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
            # Commit to batch
            merkle_tree = merkle_helper.merkle_tree_from_order_list(orders)
            merkle_root = merkle_tree.build()
            commitment = BatchCommitment(current_round, merkle_root)
            # Sign batch
            batch = Batch(orders, commitment)
            commitment_signature = crypto.sign_rlp(private_key, commitment)
            signed_batch = SignedBatch(
                [Signature('master_server', commitment_signature)],
                batch)
            signed_batch_rlp = rlp.encode(signed_batch)
            print("SENDING BATCH! ")
            # Communicate with signing services
            for signer in static_signers:
                try:
                    ssl_sock = ssl_connect(signer, certs.path_to('server.crt'))
                except ConnectionError:
                    print("CONNECTION FAILED")
                    continue

                with ssl_sock:
                    print("CONNECTED TO SIGNER")
                    send_ssl_msg(ssl_sock, signed_batch_rlp)
                    response = recv_ssl_msg(ssl_sock)
                    signature = rlp.decode(response, Signature)

                    public_key = crypto.load_public_cert_key(certs.path_to('server.crt'))

                    try:
                        crypto.verify(public_key, rlp.encode(commitment), signature.signature)
                        print("SIGNATURE OK!")
                    except InvalidSignature:
                        print("SIGNATURE VERIFICATION FAILED!!")
            orders.clear()
        current_round += 1
    # Create order batch submission timer
    t = threading.Timer(interval=10.0, function=send_batch)
    t.start()
