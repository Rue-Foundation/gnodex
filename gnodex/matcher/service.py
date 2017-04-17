import certs
import matcher
import threading
from util.ssl_sock_helper import ssl_connect
from util.rpc import rpc_call
from models import Batch


def batch_matcher_service(args):
    print("Gnodex Batch Matcher Service Started")
    t = threading.Timer(interval=2.0, function=request_batch)
    t.start()


def request_batch():
    print("REQUESTING BATCH")
    batch = None
    try:
        try:
            ssl_sock = ssl_connect(('localhost', 31337), certs.path_to('server.crt'))
        except ConnectionError:
            print("CONNECTION ERROR")
            return
        with ssl_sock:
            batch = rpc_call(ssl_sock, "request_batch", {}, True)
    except TimeoutError:
        print("REQUEST TIMED OUT")
    finally:
        if not batch:
            print("NO BATCH AVAILABLE YET")
            t = threading.Timer(interval=2.0, function=request_batch)
            t.start()
            return
        print("RECEIVED BATCH")
        print(batch)
        process_batch(batch)


def process_batch(batch: Batch):
    pass
