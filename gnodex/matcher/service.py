import certs
import matcher
import rlp
import threading
import time
from util.ssl_sock_helper import ssl_connect
from util.rpc import rpc_call_rlp
from models import SignedBatch
from matcher import batch_processor


def batch_matcher_service(args):
    print("Gnodex Batch Matcher Service Started")
    t = threading.Thread(target=request_batch, daemon=False)
    t.start()


def request_batch():
    repeat_thread = True

    while repeat_thread:
        time.sleep(2)
        repeat_thread = False

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
            repeat_thread = True
            continue
        print("RECEIVED BATCH")
        print(signed_batch.batch.orders)
        batch_processor.process_batch(signed_batch)
