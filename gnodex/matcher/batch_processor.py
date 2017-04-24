import functools
import rlp
import bisect
from .. import matcher
from ..models import Route, Matching, SignedMatching, Signature
from ..util import crypto, search


# TODO Find crossing points using ternary search
"""
def find_crossing_points(bids, asks):
    def f(i):
        # number of elements to the right and lower
        pass
    def g(j):
        # number of elements to the right and higher
        return max(0, len(bids) - max(i, bisect.bisect_left(bids, asks[i])))

    i = search.ternary_search(0, len(bids)-1, f)
    j = search.ternary_search(0, len(asks)-1, g)
    return i, j
"""


def process_batch(signed_batch):
    # TODO Decrypt Order Batch
    # TODO Generalize to match more than 2 token types
    signed_orders = signed_batch.batch.orders
    signed_batch_hash = crypto.sha256_utf8(rlp.encode(signed_batch))
    if len(signed_orders) == 0:
        print("EMTPY BATCH")
        return
    orders = [signed_order.order for signed_order in signed_orders]
    # arbitrarily choose pivot token to divide orders into asks and bids
    pivot = orders[0].buy_token
    bids = list()
    asks = list()
    for order in orders:
        if order.buy_token == pivot:
            bids.append(order)
        elif order.sell_token == pivot:
            asks.append(order)
        else:
            print("ERROR. ALGORITHM CURRENTLY IMPLEMENTED TO MATCH ONLY 2 TOKENS PER BATCH")
            return
    # if we cannot proceed to make any routes, quit
    if not bids or not asks:
        return
    # Calculate uniform trade price
    uniform_price = None
    converged = False
    print("Bids: " + str(len(bids)))
    print("Asks: " + str(len(asks)))
    while not converged:
        # Calculate uniform price of pivot token
        bid_prices = [bid.sell_amount for bid in bids]
        ask_prices = [ask.buy_amount for ask in asks]
        quantities = [bid.buy_amount for bid in bids] + [ask.sell_amount for ask in asks]
        uniform_price = sum(bid_prices + ask_prices)/sum(quantities)

        new_bids = [bid for bid in bids if bid.sell_amount > uniform_price*bid.buy_amount]
        new_asks = [ask for ask in asks if ask.buy_amount < uniform_price*ask.sell_amount]

        if not new_bids or not new_asks:
            return

        converged = (len(new_bids) == len(bids)) and (len(new_asks) == len(asks))
        bids = new_bids
        asks = new_asks

    print("Uniform Price: " + str(uniform_price) + " " + str(converged))
    print("Bids satisfied: " + str(len(bids)))
    print("Asks satisfied: " + str(len(asks)))

    # Create routes from ask sell_amount(s) to bid buy_amount(s) and vice versa
    # Sort bids ascendingly by price
    bids.sort(key=functools.cmp_to_key(lambda a, b: a.sell_amount*b.buy_amount < b.sell_amount*a.buy_amount))
    # Sort asks descendingly by price
    asks.sort(key=functools.cmp_to_key(lambda a, b: a.buy_amount*b.sell_amount < b.buy_amount*a.sell_amount))
    asks.reverse()
    # TODO Filter orders by crossing points rather than uniform clearing price
    """
    i, j = find_crossing_points(bids, asks)
    bids = bids[i:]
    asks = asks[j:]
    """

    # Create routes
    orders = [bids, asks]
    routes = list()
    for p in range(0, 2):
        sell = orders[0]
        buy = orders[1]
        i = 0
        j = 0
        supply = sell[0].sell_amount
        demand = buy[0].buy_amount
        while i < len(sell) and j < len(buy):
            seller = sell[i]
            buyer = buy[j]
            if supply < demand:
                sold_amount = supply
                i += 1
                supply = sell[i].sell_amount if i < len(sell) else None
                demand -= sold_amount
            elif supply > demand:
                sold_amount = demand
                j += 1
                supply -= sold_amount
                demand = buy[j].buy_amount if j < len(buy) else None
            else:
                sold_amount = supply
                i += 1
                j += 1
                supply = sell[i].sell_amount if i < len(sell) else None
                demand = buy[j].buy_amount if j < len(buy) else None

            routes.append(Route(seller.id, buyer.id, sold_amount))
            print('%s -> %s: %s %s' % (seller.id, buyer.id, sold_amount, seller.sell_token))

        if not p:
            orders.reverse()

    # Create Matching
    matching = Matching(routes, signed_batch_hash)
    signed_matching = SignedMatching(
        matching,
        [Signature('matcher', crypto.sign_rlp(matcher.private_key, matching))])
    print(signed_matching)
    return signed_matching
