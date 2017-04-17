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


def process_batch(batch: SignedBatch):
    pass
