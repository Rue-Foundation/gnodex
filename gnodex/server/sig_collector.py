import rlp
import threading
import time
from cryptography.exceptions import InvalidSignature
from .. import certs
from .. import server
from ..models import *
from ..util import crypto, merkle_helper
from ..util.ssl_sock_helper import ssl_connect
from ..util.rpc import rpc_call_rlp

_static_signers = [
    ('localhost', 31338),
    ('localhost', 31339),
    ('localhost', 31340),
]

# Send off current batch to signing services
def send_batch_to_signer_services():
    repeat_thread = True

    while repeat_thread:
        time.sleep(10)
        repeat_thread = False
        print("ATTEMPT TO SEND ORDERS TO SIGNER SERVICES")

        with server.state_lock.writer:
            server.current_state = server.State.COLLECT_BATCH_SIGNATURES
        # Create order batch submission timer
        if server.orders:
            # Commit to batch
            merkle_tree = merkle_helper.merkle_tree_from_order_list(server.orders)
            merkle_root = merkle_tree.build()
            commitment = Commitment(len(server.batches), merkle_root)
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
            signature_collection.extend(request_signatures(signed_batch_rlp, rlp.encode(commitment), send_signed_batch))
            with server.state_lock.writer:
                latest_batch = {
                    'signed_batch': SignedBatch(signature_collection, batch),
                    'commitment': commitment,
                    'merkle_tree': merkle_tree,
                    'order_digest_list': merkle_helper.rlp_list_to_digest_list(server.orders)
                }
                server.batches.append(latest_batch)
                server.orders = list()
                # TODO: Transition to RETRIEVE_DKG_PK_FOR_ORDERS
                server.current_state = server.State.RECEIVE_MATCHES
            send_matches_to_signer_services()
        else:
            with server.state_lock.writer:
                server.current_state = server.State.RECEIVE_ORDERS
            repeat_thread = True


def send_signed_batch(ssl_sock, signed_batch_rlp: SignedBatch):
    signature_rlp = rpc_call_rlp(
        ssl_sock,
        "receive_batch",
        {"signed_batch_rlp_rpc": signed_batch_rlp})
    return rlp.decode(signature_rlp, Signature)


def request_signatures(signed_rlp, commitment_rlp, sender_func):
    signature_collection = list()
    for signer in _static_signers:
        try:
            ssl_sock = ssl_connect(signer, certs.path_to('server.crt'))
        except ConnectionError:
            print("CONNECTION FAILED")
            continue

        with ssl_sock:
            print("CONNECTED TO SIGNER")
            signature = sender_func(ssl_sock, signed_rlp)

            signer_public_key = crypto.load_public_cert_key(certs.path_to('server.crt'))

            try:
                crypto.verify(signer_public_key, rlp.encode(commitment_rlp), signature.signature)
                print("SIGNATURE OK!")
                signature_collection.append(signature)
            except InvalidSignature:
                print("SIGNATURE VERIFICATION FAILED!!")
    return signature_collection


def send_matches_to_signer_services():
    repeat_thread = True
    while repeat_thread:
        time.sleep(10)
        repeat_thread = False
        print("ATTEMPT TO SEND MATCHES TO SIGNER SERVICES")

        with server.state_lock.writer:
            server.current_state = server.State.COLLECT_MATCHINGS_SIGNATURES

        if server.matchings:
            # Commit to matchings
            merkle_tree = merkle_helper.merkle_tree_from_order_list(server.matchings)
            merkle_root = merkle_tree.build()
            commitment = Commitment(len(server.matched_batches), merkle_root)
            # Sign match collection
            matching_collection = MatchingCollection(server.matchings, commitment)
            commitment_signature = crypto.sign_rlp(server.private_key, commitment)
            signature_collection = [Signature('master_server', commitment_signature)]
            signed_matching_collection = SignedMatchingCollection(
                signature_collection,
                matching_collection)
            signed_matching_collection_rlp = rlp.encode(signed_matching_collection)
            print("SENDING MATCHING COLLECTION!")
            # Comm with signers
            signature_collection.extend(request_signatures(
                signed_matching_collection_rlp,
                rlp.encode(commitment),
                send_signed_matching_collection))
            with server.state_lock.writer:
                latest_match_batch = {
                    'signed_matching_collection': SignedMatchingCollection(signature_collection, matching_collection),
                    'commitment': commitment,
                    'merkle_tree': merkle_tree,
                    'matching_digest_list': merkle_helper.rlp_list_to_digest_list(server.matchings)
                }
                server.matched_batches.append(latest_match_batch)
                server.matchings = list()
                # TODO: Transition to RETRIEVE_DKG_PK_FOR_MATCHINGS
                server.current_state = server.State.CHOOSE_OPTIMAL_MATCHING

        else:
            with server.state_lock.writer:
                server.current_state = server.State.RECEIVE_MATCHES
            repeat_thread = True


def send_signed_matching_collection(ssl_sock, signed_matching_collection_rlp: SignedBatch):
    signature_rlp = rpc_call_rlp(
        ssl_sock,
        "receive_match_collection",
        {"signed_match_collection_rlp_rpc": signed_matching_collection_rlp})
    return rlp.decode(signature_rlp, Signature)
