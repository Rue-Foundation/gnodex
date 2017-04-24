import rlp
from .. import server
from ..models import *
from ..util import crypto
from ..util.rpc import rpc_response, rpc_param_decode


def receive_matching(signed_matching_rlp_rpc):
    # TODO Verify Matcher Sig
    signed_matching_rlp = rpc_param_decode(signed_matching_rlp_rpc)
    signed_matching = rlp.decode(signed_matching_rlp, SignedMatching)
    print("MATCHING RECEIVED")
    server.matchings.append(signed_matching)
    receipt_round = len(server.batches)
    # Create Receipt
    matching_hash = crypto.sha256_utf8(signed_matching_rlp)
    receipt = Receipt(receipt_round, matching_hash)
    # Create Signed Receipt
    receipt_hash_signed = crypto.sign_rlp(server.private_key, receipt)
    signed_receipt = SignedReceipt(receipt, receipt_hash_signed)
    # Send response
    print("RECEIPT SENT")
    return rpc_response(rlp.encode(signed_receipt))


def return_latest_signed_batch():
    with server.state_lock.reader:
        latest = len(server.batches)
    print("BATCH SENT TO MATCHER")
    return rpc_response(rlp.encode(server.batches[latest-1]['signed_batch'])) if latest > 0 else None
