import socket
import pprint
import sys
import rlp
import certs
import parse
from cryptography.exceptions import InvalidSignature
from models import Order, SignedOrder, SignedReceipt
from util import crypto, ssl_context
from util.ssl_sock_helper import recv_ssl_msg, send_ssl_msg

def trade_client(args):
    # Open SSL Connection
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    ssl_sock = ssl_context.wrap_client_socket(sock, certs.path_to('server.crt'))

    ssl_sock.connect(('localhost', 31337))

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

        #order_rlp_encoded = rlp.encode(order)
        signed_order = SignedOrder(order, crypto.sign_rlp(private_key, order))
        signed_order_rlp_encoded = rlp.encode(signed_order)
        # TODO: Encrypt order with DKG Key
        send_ssl_msg(ssl_sock, signed_order_rlp_encoded)
        print("SENT: " + str(signed_order_rlp_encoded))
        # Receive signature from state server
        signed_receipt = rlp.decode(recv_ssl_msg(ssl_sock), SignedReceipt)
        print("RECV: " + str(signed_receipt))

        # Verify Signed Order
        order_hash = crypto.sha256_utf8(signed_order_rlp_encoded)
        receipt_order_digest = signed_receipt.receipt.order_digest
        print("DIGEST: " + str(order_hash))
        print("GOT: " + str(receipt_order_digest))
        if (order_hash != receipt_order_digest):
            print("INVALID ORDER HASH!")
            continue
        print("ROUND: " + str(signed_receipt.receipt.round))

        # Verify Signature
        receipt_rlp_encoded = rlp.encode(signed_receipt.receipt)

        try:
            crypto.verify(public_key, receipt_rlp_encoded, signed_receipt.signature)
            print("SIGNATURE OK!")
        except InvalidSignature:
            print("SIGNATURE VERIFICATION FAILED!!")
