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

def choose_optimal_matching():
    matched_batch = server.matched_batches[-1]
    signed_matching_collection = matched_batch["signed_matching_collection"]
    matching_collection = signed_matching_collection.matching_collection
    match, volume, utility = None, 0, 0
    batch = server.batches[-1]["signed_batch"].batch
    order_ids = [signed_order.order.id for signed_order in batch.orders]
    for signed_matching in matching_collection.matchings:
        matching = signed_matching.matching
        _volume, _utility, valid = 0, 0, True
        buy, sell = {}, {}
        try:
            for route in matching.routes:
                if route.left_order not in order_ids or route.right_order not in order_ids:
                    raise ValueError("Invalid Matching -- Unknown Order Inserted")

                if route.left_order not in sell:
                    sell[route.left_order] = route.left_amount
                else:
                    sell[route.left_order] += route.left_amount
                if route.right_order not in buy:
                    buy[route.right_order] = route.left_amount
                else:
                    buy[route.right_order] += route.left_amount

                volume += route.left_amount

            for signed_order in batch.orders:
                order = signed_order.order
                if order.buy_amount < buy[order.id]:
                    raise ValueError(
                        "Invalid Matching -- Order %s overflown (%s, %s)" %
                        (order.id, order.buy_amount, buy[order.id]))
                elif order.sell_amount < sell[order.id]:
                    raise ValueError(
                        "Invalid Matching -- Order %s oversold (%s, %s)" %
                        (order.id, order.sell_amount, sell[order.id]))
                elif order.sell_amount*sell[order.id] != buy[order.id]*order.buy_amount:
                    raise ValueError(
                        "Invalid Matching -- Order %s price not kept (%s, %s)" %
                        (order.id, order.sell_amount/order.buy_amount, buy[order.id]/sell[order.id]))

        except ValueError:
            continue

        if _volume > volume or (_volume == volume and _utility < utility):
            match, volume, utility = signed_matching, _volume, _utility

    print("CHOSEN MATCHING: %s volume, %s utility" % (volume, utility))

    with server.state_lock.writer:
        matched_batch["optimal_choice"] = match
        server.current_state = server.State.RECEIVE_ORDERS
