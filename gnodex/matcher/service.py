import rlp
import threading
import time
import merkle
from .. import certs
from ..util.ssl_sock_helper import ssl_connect
from ..util.rpc import rpc_call_rlp
from ..models import Chain, SignedBatch, SignedReceipt
from ..matcher import batch_processor


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
                if not signed_batch:
                    print("NO BATCH AVAILABLE YET")
                    repeat_thread = True
                    continue
                print("RECEIVED BATCH")
                signed_matching = batch_processor.process_batch(signed_batch)
                # TODO Encrypt matching with DKG
                print("SENDING MATCHING")
                signed_receipt = send_signed_matching(ssl_sock, rlp.encode(signed_matching))
                if not signed_receipt:
                    print("RECEIPT NOT RECEIVED")
                    repeat_thread = True
                    continue
                print("RECEIVED RECEIPT")
                request_membership_verification(signed_receipt)

        except TimeoutError:
            repeat_thread = True
            print("REQUEST TIMED OUT")


def send_signed_matching(ssl_sock, signed_matching_rlp):
    signed_receipt_rlp = rpc_call_rlp(
        ssl_sock,
        "receive_matching",
        {'signed_matching_rlp_rpc': signed_matching_rlp},
        default_timeout=True)
    return rlp.decode(signed_receipt_rlp, SignedReceipt) if signed_receipt_rlp else None


def request_membership_verification(signed_receipt):
    repeat_thread = True

    while repeat_thread:
        time.sleep(2)

        print("ASKING FOR VERIFICATION")
        confirmed = False
        try:
            ssl_sock = ssl_connect(('localhost', 31337), certs.path_to('server.crt'))
            with ssl_sock:
                chain = send_verification_request(ssl_sock, rlp.encode(signed_receipt))
                if not chain:
                    continue
                chain_links = [(link.value, link.side.decode()) for link in chain.links]
                # TODO: Cry about missing n out of m signatures
                confirmed = merkle.check_chain(chain_links)
        except ConnectionError:
            print("CONNECTION ERROR")
        except TimeoutError:
            print("VERIFICATION REQUEST TIMEOUT")
        finally:
            if not confirmed:
                print(
                    "MATCHING CONFIRMATION NOT RECEIVED YET (%s, %s)" % (
                    signed_receipt.receipt.order_digest,
                    signed_receipt.receipt.round))
            else:
                repeat_thread = False
                print("MATCHING CONFIRMATION RECEIVED!!!")


def send_verification_request(ssl_sock, signed_receipt_rlp):
    chain_rlp = rpc_call_rlp(
        ssl_sock,
        "return_matching_confirmation",
        {"signed_receipt_rlp_rpc": signed_receipt_rlp},
        default_timeout=True)
    print(chain_rlp)
    return rlp.decode(chain_rlp, Chain) if chain_rlp else None
