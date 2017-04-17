import rlp
import server
from cryptography.exceptions import InvalidSignature
from models import *
from util import crypto
from util.rpc import rpc_response, rpc_param_decode


def return_confirmation(signed_receipt_rlp_rpc):
    signed_receipt_rlp = rpc_param_decode(signed_receipt_rlp_rpc)
    signed_receipt = rlp.decode(signed_receipt_rlp, SignedReceipt)
    receipt = signed_receipt.receipt
    try:
        crypto.verify(server.public_key, rlp.encode(receipt), signed_receipt.signature)
        print("RECEIPT SIGNATURE OK!")
        if receipt.round == len(server.batches):
            print("NOT YET CONFIRMED")
            return
        elif receipt.round > len(server.batches):
            print("AN ORDER FROM THE FUTURE")
            return
        batch = server.batches[receipt.round]
        if receipt.order_digest not in batch['order_digest_list']:
            print("FATAL ERROR. ORDER IS MISSING FROM BATCH!")
            return
        idx = batch['order_digest_list'].index(receipt.order_digest)
        chain_links = [ChainLink(value, side) for (value, side) in batch['merkle_tree'].get_chain(idx)]
        chain = Chain(chain_links)
        # TODO Sign This Response
        print("ORDER CONFIRMATION SENT")
        return rpc_response(rlp.encode(chain))
    except InvalidSignature:
        print("RECEIPT SIGNATURE VERIFICATION FAILED!!")


def receive_order(signed_order_rlp_rpc):
    # TODO Verify Sig
    signed_order_rlp = rpc_param_decode(signed_order_rlp_rpc)
    signed_order = rlp.decode(signed_order_rlp, SignedOrder)
    print("ORDER RECEIVED")
    server.orders.append(signed_order)
    receipt_round = len(server.batches)
    # Create Receipt
    order_hash = crypto.sha256_utf8(signed_order_rlp)
    receipt = Receipt(receipt_round, order_hash)
    # Create Signed Receipt
    receipt_hash_signed = crypto.sign_rlp(server.private_key, receipt)
    signed_receipt = SignedReceipt(receipt, receipt_hash_signed)
    # Send response
    print("RECEIPT SENT")
    return rpc_response(rlp.encode(signed_receipt))
