import threading
import pprint
import sys
import rlp
import certs
import parse
import merkle
import time
from cryptography.exceptions import InvalidSignature
from models import Order, SignedOrder, SignedReceipt, Chain, ChainLink
from util import crypto
from util.ssl_sock_helper import recv_ssl_msg, send_ssl_msg, ssl_connect, recv_ssl_msg_timeout
from util.rpc import rpc_call_rlp


def trade_client(args):
    global public_key
    global private_key

    # Open SSL Connection
    ssl_sock = ssl_connect(('localhost', 31337), certs.path_to('server.crt'))

    # Load public key for signature verification
    public_key = crypto.load_public_cert_key(certs.path_to('server.crt'))
    # Load private key for signatures
    private_key = crypto.load_private_key(certs.path_to('server.key'))

    # Just print some debugging data
    print(ssl_sock.getpeername())
    print(pprint.pformat(ssl_sock.getpeercert()))
    print(ssl_sock.cipher())

    # input parse pattern
    # "BUY/SELL ### TOKEN FOR ### TOKEN"
    pattern = parse.compile("{operation} {from_amount:d} {from_token} FOR {to_amount:d} {to_token}")

    # Get user input, send to server
    print("Gnodex Trade Client Started")
    while True:
        try:
            # Read input line, and send as RLP
            line = sys.stdin.readline()
            parsed = pattern.parse(line)
            if (parsed == None):
                continue
            order = None
            if (parsed['operation'] == 'BUY'):
                order = Order(parsed['from_token'], parsed['from_amount'], parsed['to_token'], parsed['to_amount'])
            elif (parsed['operation'] == 'SELL'):
                order = Order(parsed['to_token'], parsed['to_amount'], parsed['from_token'], parsed['from_amount'])
            else:
                continue

            signed_order = SignedOrder(order, crypto.sign_rlp(private_key, order))
            signed_order_rlp = rlp.encode(signed_order)
            # Receive signature from state server
            # TODO: Encrypt order with DKG Key
            signed_receipt = send_signed_order(ssl_sock, signed_order_rlp)

            # Verify Signed Order
            order_hash = crypto.sha256_utf8(signed_order_rlp)
            receipt_order_digest = signed_receipt.receipt.order_digest
            if (order_hash != receipt_order_digest):
                print("INVALID ORDER HASH!")
                continue
            print("ROUND: " + str(signed_receipt.receipt.round))

            # Verify Signature
            receipt_rlp_encoded = rlp.encode(signed_receipt.receipt)

            try:
                crypto.verify(public_key, receipt_rlp_encoded, signed_receipt.signature)
                print("SIGNATURE OK!")
                t = threading.Thread(target=request_membership_verification, args=(signed_receipt,), daemon=True)
                t.start()
            except InvalidSignature:
                print("SIGNATURE VERIFICATION FAILED!!")
        except KeyboardInterrupt:
            print("Trade Client Exit.")
            break


def send_signed_order(ssl_sock, signed_order_rlp: SignedOrder):
    signed_receipt_rlp = rpc_call_rlp(
        ssl_sock,
        "receive_order",
        { "signed_order_rlp_rpc": signed_order_rlp })
    return rlp.decode(signed_receipt_rlp, SignedReceipt)


def request_membership_verification(signed_receipt: SignedReceipt):
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
                chain_links = [(link.value, link.side) for link in chain.links]
                # TODO: Cry about missing n out of m signatures
                confirmed = merkle.check_chain(chain_links)
        except ConnectionError:
            print("CONNECTION ERROR")
        except TimeoutError:
            print("VERIFICATION REQUEST TIMEOUT")
        finally:
            if not confirmed:
                print(
                    "ORDER CONFIRMATION NOT RECEIVED YET (%s, %s)" % (
                    signed_receipt.receipt.order_digest,
                    signed_receipt.receipt.round))
            else:
                repeat_thread = False
                print("ORDER CONFIRMATION RECEIVED!!!")


def send_verification_request(ssl_sock, signed_receipt_rlp):
    chain_rlp = rpc_call_rlp(
        ssl_sock,
        "return_confirmation",
        { "signed_receipt_rlp_rpc": signed_receipt_rlp },
        default_timeout=True)
    print(chain_rlp)
    return rlp.decode(chain_rlp, Chain) if chain_rlp else None
