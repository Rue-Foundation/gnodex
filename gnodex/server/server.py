import socket
import rlp
import threading
import certs
from cryptography.exceptions import InvalidSignature
from models import *
from util import crypto, merkle_helper
from util.ssl_sock_helper import ssl_connect
from jsonrpc import dispatcher
from util.rpc import rpc_call_rlp, rpc_response, rpc_param_decode, handle_rpc_client


def master_state_service(args):
    global public_key
    global private_key
    global orders
    global order_list_lock
    global current_round
    global last_signed_batch
    global last_commitment
    global last_merkle_tree
    global last_order_digest_list

    # Start listening for connections
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', 31337))
    sock.listen()

    # Load public key for signature verification
    public_key = crypto.load_public_cert_key(certs.path_to('server.crt'))
    # Load private key for signatures
    private_key = crypto.load_private_key(certs.path_to('server.key'))

    # Create order buffer
    orders = list()
    order_list_lock = threading.RLock()
    current_round = 0
    last_signed_batch = None
    last_commitment = None
    last_merkle_tree = None
    last_order_digest_list = list()

    # Create order batch submission timer
    t = threading.Timer(interval=10.0, function=send_batch_to_signer_services)
    t.start()

    # Accept connections and start handling them in own thread
    print("Gnodex Master State Server Started")
    while True:
        new_sock = sock.accept()[0]
        thread = threading.Thread(
            target=handle_rpc_client,
            args=(new_sock, certs.path_to('server.crt'), certs.path_to('server.key'), dispatcher))
        thread.start()


@dispatcher.add_method
def return_confirmation(signed_receipt_rlp_rpc):
    global order_list_lock

    signed_receipt_rlp = rpc_param_decode(signed_receipt_rlp_rpc)
    signed_receipt = rlp.decode(signed_receipt_rlp, SignedReceipt)
    receipt = signed_receipt.receipt
    with order_list_lock:
        try:
            crypto.verify(public_key, rlp.encode(receipt), signed_receipt.signature)
            print("RECEIPT SIGNATURE OK!")
            if receipt.round < current_round - 1:
                # TODO Store Old Batch Signatures
                print("EXPIRED RECEIPT")
                return
            elif receipt.round == current_round:
                print("NOT YET CONFIRMED")
                return
            elif receipt.order_digest not in last_order_digest_list:
                print("FATAL ERROR. ORDER IS MISSING!")
                return
            idx = last_order_digest_list.index(receipt.order_digest)
            chain_links = [ChainLink(value, side) for (value, side) in last_merkle_tree.get_chain(idx)]
            chain = Chain(chain_links)
            # TODO Sign This Response
            print("ORDER CONFIRMATION SENT")
            return rpc_response(rlp.encode(chain))
        except InvalidSignature:
            print("RECEIPT SIGNATURE VERIFICATION FAILED!!")


@dispatcher.add_method
def receive_order(signed_order_rlp_rpc):
    signed_order_rlp = rpc_param_decode(signed_order_rlp_rpc)
    signed_order = rlp.decode(signed_order_rlp, SignedOrder)
    print("ORDER RECEIVED")
    receipt_round = None
    with order_list_lock:
        orders.append(signed_order)
        receipt_round = current_round
    # Create Receipt
    order_hash = crypto.sha256_utf8(signed_order_rlp)
    receipt = Receipt(receipt_round, order_hash)
    # Create Signed Receipt
    receipt_hash_signed = crypto.sign_rlp(private_key, receipt)
    signed_receipt = SignedReceipt(receipt, receipt_hash_signed)
    # Send response
    print("RECEIPT SENT")
    return rpc_response(rlp.encode(signed_receipt))


static_signers = [
    ('localhost', 31338),
    ('localhost', 31339),
    ('localhost', 31340),
]


# Send off current batch to signing services
def send_batch_to_signer_services():
    global orders
    global current_round
    global last_signed_batch
    global last_commitment
    global last_merkle_tree
    global last_order_digest_list

    with order_list_lock:
        if orders:
            # Commit to batch
            merkle_tree = merkle_helper.merkle_tree_from_order_list(orders)
            merkle_root = merkle_tree.build()
            commitment = BatchCommitment(current_round, merkle_root)
            # Sign batch
            batch = Batch(orders, commitment)
            commitment_signature = crypto.sign_rlp(private_key, commitment)
            signature_collection = [Signature('master_server', commitment_signature)]
            signed_batch = SignedBatch(
                signature_collection,
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
                    signature = send_signed_batch(ssl_sock, signed_batch_rlp)

                    signer_public_key = crypto.load_public_cert_key(certs.path_to('server.crt'))

                    try:
                        crypto.verify(signer_public_key, rlp.encode(commitment), signature.signature)
                        print("SIGNATURE OK!")
                        signature_collection.append(signature)
                    except InvalidSignature:
                        print("SIGNATURE VERIFICATION FAILED!!")
            last_signed_batch = SignedBatch(
                signature_collection,
                batch)
            last_commitment = commitment
            last_merkle_tree = merkle_tree
            last_order_digest_list = merkle_helper.order_list_to_digest_list(orders)
            orders = list()
            current_round += 1
    # Create order batch submission timer
    t = threading.Timer(interval=10.0, function=send_batch_to_signer_services)
    t.start()


def send_signed_batch(ssl_sock, signed_batch_rlp: SignedBatch):
    signature_rlp = rpc_call_rlp(
        ssl_sock,
        "receive_batch",
        { "signed_batch_rlp_rpc": signed_batch_rlp })
    return rlp.decode(signature_rlp, Signature)
