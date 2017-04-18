import rlp
import threading
import certs
import server
from cryptography.exceptions import InvalidSignature
from models import *
from util import crypto, merkle_helper
from util.ssl_sock_helper import ssl_connect
from util.rpc import rpc_call_rlp

_static_signers = [
    ('localhost', 31338),
    ('localhost', 31339),
    ('localhost', 31340),
]

# Send off current batch to signing services
def send_batch_to_signer_services():
    with server.state_lock.writer:
        server.current_state = server.State.COLLECT_BATCH_SIGNATURES
    # Create order batch submission timer
    if server.orders:
        # Commit to batch
        merkle_tree = merkle_helper.merkle_tree_from_order_list(server.orders)
        merkle_root = merkle_tree.build()
        commitment = BatchCommitment(len(server.batches), merkle_root)
        # Sign batch
        batch = Batch(server.orders, commitment)
        commitment_signature = crypto.sign_rlp(server.private_key, commitment)
        signature_collection = [Signature('master_server', commitment_signature)]
        signed_batch = SignedBatch(
            signature_collection,
            batch)
        signed_batch_rlp = rlp.encode(signed_batch)
        print("SENDING BATCH! ")
        # Communicate with signing services
        for signer in _static_signers:
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
        with server.state_lock.writer:
            latest_batch = {
                'signed_batch': SignedBatch(signature_collection, batch),
                'commitment': commitment,
                'merkle_tree': merkle_tree,
                'order_digest_list': merkle_helper.order_list_to_digest_list(server.orders)
            }
            server.batches.append(latest_batch)
            server.orders = list()
            # TODO: Transition to RETRIEVE_DKG_PK_FOR_ORDERS
            server.current_state = server.State.RECEIVE_MATCHES
        t = threading.Timer(interval=10.0, function=send_matches_to_signer_services)
        t.setDaemon(True)
        t.start()
    else:
        with server.state_lock.writer:
            server.current_state = server.State.RECEIVE_ORDERS
        t = threading.Timer(interval=10.0, function=send_batch_to_signer_services)
        t.setDaemon(True)
        t.start()


def send_signed_batch(ssl_sock, signed_batch_rlp: SignedBatch):
    signature_rlp = rpc_call_rlp(
        ssl_sock,
        "receive_batch",
        {"signed_batch_rlp_rpc": signed_batch_rlp})
    return rlp.decode(signature_rlp, Signature)


def send_matches_to_signer_services():
    print("ATTEMPT TO SEND MATCHES TO SIGNER SERVICES")
    t = threading.Timer(interval=10.0, function=send_matches_to_signer_services)
    t.setDaemon(True)
    t.start()
