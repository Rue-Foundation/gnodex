import certs
import matcher
import rlp
import threading
from util.ssl_sock_helper import ssl_connect
from util.rpc import rpc_call_rlp
from models import SignedBatch


def batch_matcher_service(args):
    print("Gnodex Batch Matcher Service Started")
    t = threading.Timer(interval=2.0, function=request_batch)
    t.start()


def request_batch():
    print("REQUESTING BATCH")
    signed_batch = None
    try:
        try:
            ssl_sock = ssl_connect(('localhost', 31337), certs.path_to('server.crt'))
        except ConnectionError:
            print("CONNECTION ERROR")
            return
        with ssl_sock:
            signed_batch_rlp = rpc_call_rlp(ssl_sock, "return_latest_signed_batch", {}, default_timeout=True)
            if signed_batch_rlp:
                signed_batch = rlp.decode(signed_batch_rlp, SignedBatch)
    except TimeoutError:
        print("REQUEST TIMED OUT")

    if not signed_batch:
        print("NO BATCH AVAILABLE YET")
        t = threading.Timer(interval=2.0, function=request_batch)
        t.start()
        return
    print("RECEIVED BATCH")
    print(signed_batch.batch.orders)
    process_batch(signed_batch)


def process_batch(signed_batch):
    # TODO Decrypt Order Batch
    # TODO Generalize to match more than 2 token types
    signed_orders = signed_batch.batch.orders
    if (len(signed_orders) == 0):
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
    if len(bids) == 0 or len(asks) == 0:
        return

    uniform_price = None
    converged = False
    print("Bids: " + str(len(bids)))
    print("Asks: " + str(len(asks)))
    while not converged:
        # Calculate uniform price of pivot token
        bid_prices = [bid.sell_amount for bid in bids]
        ask_prices = [ask.buy_amount for ask in asks]
        print("Bid Prices: " + str(bid_prices))
        print("Ask Prices: " + str(ask_prices))
        quantities = [bid.buy_amount for bid in bids] + [ask.sell_amount for ask in asks]
        uniform_price = sum(bid_prices + ask_prices)/sum(quantities)
        new_bids = [bid for bid in bids if bid.sell_amount > uniform_price*bid.buy_amount]
        new_asks = [ask for ask in asks if ask.buy_amount < uniform_price*ask.sell_amount]
        converged = (len(new_bids) == len(bids)) and (len(new_asks) == len(asks))
        bids = new_bids
        asks = new_asks
        print("Uniform Price: " + str(uniform_price) + " " + str(converged))
        print("Bids satisfied: " + str(len(bids)))
        print("Asks satisfied: " + str(len(asks)))
