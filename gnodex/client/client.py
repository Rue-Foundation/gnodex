import socket, ssl, pprint, sys, rlp, certs, parse
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_v1_5
from Cryptodome.Hash import SHA256
from models import Order, SignedReceipt
from util import sign_rlp, sha256_utf8

def trade_client():
    # Open SSL Connection
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    ssl_sock = ssl.wrap_socket(sock,
                               ca_certs=certs.path_to("server.crt"),
                               cert_reqs=ssl.CERT_REQUIRED,
                               ssl_version=ssl.PROTOCOL_TLSv1_2)
    ssl_sock.connect(('localhost', 31337))

    # Load public key for signature verification
    cert = RSA.importKey(open(certs.path_to('server.crt'), 'rb').read())
    pkcs = PKCS1_v1_5.new(cert)

    # Just print some debugging data
    print(ssl_sock.getpeername())
    print(pprint.pformat(ssl_sock.getpeercert()))
    print(ssl_sock.cipher())

    # input parse pattern
    # "BUY/SELL ### TOKEN FOR ### TOKEN"
    pattern = parse.compile("{operation} {fromAmount:d} {fromToken} FOR {toAmount:d} {toToken}")

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
            order = Order(parsed['fromToken'], parsed['fromAmount'], parsed['toToken'], parsed['toAmount'])
        elif (parsed['operation'] == 'SELL'):
            order = Order(parsed['toToken'], parsed['toAmount'], parsed['fromToken'], parsed['fromAmount'])
        else:
            continue

        order_rlp_encoded = rlp.encode(order)
        # TODO: Encrypt order with DKG Key
        ssl_sock.send(order_rlp_encoded)
        print("SENT: " + str(order_rlp_encoded))
        # Receive signature from state server
        signed_receipt = rlp.decode(ssl_sock.recv(), SignedReceipt)
        print("RECV: " + str(signed_receipt))

        # Verify Signed Order
        order_hash = sha256_utf8(order_rlp_encoded)
        receipt_order_digest = signed_receipt.receipt.orderDigest
        print("DIGEST: " + str(order_hash.digest()))
        print("GOT: " + str(receipt_order_digest))
        if (order_hash.digest() != receipt_order_digest):
            print("INVALID ORDER HASH!")
            continue
        print("ROUND: " + str(signed_receipt.receipt.round))

        # Verify Signature
        receipt_rlp_encoded = rlp.encode(signed_receipt.receipt)
        receipt_hash = sha256_utf8(receipt_rlp_encoded)

        try:
            pkcs.verify(receipt_hash, signed_receipt.signature)
            print("SIGNATURE OK!")
        except ValueError:
            print("SIGNATURE VERIFICATION FAILED!!")
