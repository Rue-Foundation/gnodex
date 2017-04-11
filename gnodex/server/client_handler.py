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
    with server.order_list_lock:
        try:
            crypto.verify(server.public_key, rlp.encode(receipt), signed_receipt.signature)
            print("RECEIPT SIGNATURE OK!")
            if receipt.round < server.current_round - 1:
                # TODO Store Old Batch Signatures
                print("EXPIRED RECEIPT")
                return
            elif receipt.round == server.current_round:
                print("NOT YET CONFIRMED")
                return
            elif receipt.order_digest not in server.last_order_digest_list:
                print("FATAL ERROR. ORDER IS MISSING!")
                return
            idx = server.last_order_digest_list.index(receipt.order_digest)
            chain_links = [ChainLink(value, side) for (value, side) in server.last_merkle_tree.get_chain(idx)]
            chain = Chain(chain_links)
            # TODO Sign This Response
            print("ORDER CONFIRMATION SENT")
            return rpc_response(rlp.encode(chain))
        except InvalidSignature:
            print("RECEIPT SIGNATURE VERIFICATION FAILED!!")


def receive_order(signed_order_rlp_rpc):
    signed_order_rlp = rpc_param_decode(signed_order_rlp_rpc)
    signed_order = rlp.decode(signed_order_rlp, SignedOrder)
    print("ORDER RECEIVED")
    receipt_round = None
    with server.order_list_lock:
        server.orders.append(signed_order)
        receipt_round = server.current_round
    # Create Receipt
    order_hash = crypto.sha256_utf8(signed_order_rlp)
    receipt = Receipt(receipt_round, order_hash)
    # Create Signed Receipt
    receipt_hash_signed = crypto.sign_rlp(server.private_key, receipt)
    signed_receipt = SignedReceipt(receipt, receipt_hash_signed)
    # Send response
    print("RECEIPT SENT")
    return rpc_response(rlp.encode(signed_receipt))
