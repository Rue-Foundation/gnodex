import certs
import rlp
import signer
from cryptography.exceptions import InvalidSignature
from models import SignedBatch, Signature
from util import crypto, merkle_helper
from util.rpc import rpc_response, rpc_param_decode


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
        signer.state_condition.notify()
        print("AWAITING BATCH MATCHING!")
    except InvalidSignature:
        print("COULD NOT VERIFY SERVER SIGNATURE!")
    finally:
        # Return result
        signature = Signature('signer_%d' % signer.instance_id, commitment_signature)
        print("RESPONSE SENT")
        return rpc_response(rlp.encode(signature))

