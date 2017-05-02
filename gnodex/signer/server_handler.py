import rlp
from cryptography.exceptions import InvalidSignature
from .. import certs
from .. import signer
from ..models import SignedBatch, Signature, SignedMatchingCollection
from ..util import crypto, merkle_helper
from ..util.rpc import rpc_response, rpc_param_decode


def receive_order_batch(signed_batch_rlp_rpc):
    signed_batch_rlp = rpc_param_decode(signed_batch_rlp_rpc)
    signed_batch = rlp.decode(signed_batch_rlp, SignedBatch)
    print("BATCH RECEIVED")
    batch = signed_batch.batch
    commitment = batch.commitment

    # Empty signature
    commitment_signature = ''
    try:
        # Verify Merkle Tree construction
        merkle_tree = merkle_helper.merkle_tree_from_order_list(batch.orders)
        merkle_root = merkle_tree.build()
        if merkle_root != commitment.merkle_root:
            print("COULD NOT RECONSTRUCT MERKLE TREE")
            return
        # Verify server signature
        server_signature = signed_batch.signatures[0].signature
        public_key = crypto.load_public_cert_key(certs.path_to('server.crt'))
        crypto.verify(public_key, rlp.encode(commitment), server_signature)
        # All ok, sign commitment
        print("BATCH SIGNED")
        commitment_signature = crypto.sign_rlp(signer.private_key, commitment)
        # Wait for match collection
        signer.pending_states.append(signer.State.RECEIVE_MATCH_COLLECTION)
        with signer.state_condition:
            signer.state_condition.notify()
        print("AWAITING BATCH MATCHING!")
    except InvalidSignature:
        print("COULD NOT VERIFY SERVER SIGNATURE!")
    finally:
        # Return result
        signature = Signature('signer_%d' % signer.instance_id, commitment_signature)
        print("RESPONSE SENT")
        return rpc_response(rlp.encode(signature))


def receive_match_collection(signed_match_collection_rlp_rpc):
    signed_match_collection_rlp = rpc_param_decode(signed_match_collection_rlp_rpc)
    signed_match_collection = rlp.decode(signed_match_collection_rlp, SignedMatchingCollection)
    print("MATCHING COLLECTION RECEIVED")
    match_collection = signed_match_collection.matching_collection
    commitment = match_collection.commitment

    commitment_signature = ''
    try:
        # Verify Merkle Tree construction
        merkle_tree = merkle_helper.merkle_tree_from_order_list(match_collection.matchings)
        merkle_root = merkle_tree.build()
        if merkle_root != commitment.merkle_root:
            print("COULD NOT RECONSTRUCT MERKLE TREE")
            return
        # Verify server signature
        server_signature = signed_match_collection.signatures[0].signature
        public_key = crypto.load_public_cert_key(certs.path_to('server.crt'))
        crypto.verify(public_key, rlp.encode(commitment), server_signature)
        # All ok, sign commitment
        print("MATCHING SIGNED")
        commitment_signature = crypto.sign_rlp(signer.private_key, commitment)
        # Wait for match collection
        signer.pending_states.append(signer.State.RECEIVE_ORDER_BATCH)
        with signer.state_condition:
            signer.state_condition.notify()
        print("AWAITING NEXT BATCH!")
    except InvalidSignature:
        print("COULD NOT VERIFY SERVER SIGNATURE!")
    finally:
        # Return result
        signature = Signature('signer_%d' % signer.instance_id, commitment_signature)
        print("RESPONSE SENT")
        return rpc_response(rlp.encode(signature))
