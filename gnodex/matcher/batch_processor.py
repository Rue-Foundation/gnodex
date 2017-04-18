import functools


def process_batch(signed_batch):
    # TODO Decrypt Order Batch
    # TODO Generalize to match more than 2 token types
    signed_orders = signed_batch.batch.orders
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

    # Move with two pointers across bids and asks
    # Create routes from bids sell_token to asks buy_token until 1) asks satisfied or 2) bids exhausted
    # Create routes from asks sell_token to bids buy_token until <if 1)> asks exhausted <else if 2)> bids satisfied
    # Create routes to collect remaining tokens from EITHER buy_token or sell_token, depending on case, as wellfare
