import rlp
from .. import server
from ..models import *
from ..util import crypto
from ..util.rpc import rpc_response, rpc_param_decode
from cryptography.exceptions import InvalidSignature


def receive_matching(signed_matching_rlp_rpc):
    # TODO Verify Matcher Sig
    signed_matching_rlp = rpc_param_decode(signed_matching_rlp_rpc)
    signed_matching = rlp.decode(signed_matching_rlp, SignedMatching)
    print("MATCHING RECEIVED")
    server.matchings.append(signed_matching)
    receipt_round = len(server.matched_batches)
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


def return_matching_confirmation(signed_receipt_rlp_rpc):
    signed_receipt_rlp = rpc_param_decode(signed_receipt_rlp_rpc)
    signed_receipt = rlp.decode(signed_receipt_rlp, SignedReceipt)
    receipt = signed_receipt.receipt
    try:
        crypto.verify(server.public_key, rlp.encode(receipt), signed_receipt.signature)
        print("RECEIPT SIGNATURE OK!")
        if receipt.round == len(server.matched_batches):
            print("NOT YET CONFIRMED")
            return
        elif receipt.round > len(server.matched_batches):
            print("AN ORDER FROM THE FUTURE")
            return
        matching = server.matched_batches[receipt.round]
        if receipt.order_digest not in matching['matching_digest_list']:
            print("FATAL ERROR. ORDER IS MISSING FROM BATCH!")
            return
        idx = matching['matching_digest_list'].index(receipt.order_digest)
        chain_links = [ChainLink(value, side) for (value, side) in matching['merkle_tree'].get_chain(idx)]
        chain = Chain(chain_links)
        # TODO Sign This Response
        print("MATCHING CONFIRMATION SENT")
        return rpc_response(rlp.encode(chain))
    except InvalidSignature:
        print("RECEIPT SIGNATURE VERIFICATION FAILED!!")
