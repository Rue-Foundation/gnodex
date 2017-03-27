import socket, ssl, pprint, pickle, sys, rlp
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_v1_5
from Cryptodome.Hash import SHA256
from order import Order
import parse

# Open SSL Connection
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ssl_sock = ssl.wrap_socket(sock,
                           ca_certs="certs/server.crt",
                           cert_reqs=ssl.CERT_REQUIRED,
                           ssl_version=ssl.PROTOCOL_TLSv1_2)
ssl_sock.connect(('localhost', 31337))

# Load public key for signature verification
cert = RSA.importKey(open('certs/server.crt', 'rb').read())
pkcs = PKCS1_v1_5.new(cert)

# Just print some debugging data
print(ssl_sock.getpeername())
print(pprint.pformat(ssl_sock.getpeercert()))
print(ssl_sock.cipher())

# input parse pattern
# "BUY/SELL ### TOKEN FOR ### TOKEN"
pattern = parse.compile("{operation} {fromAmount:d} {fromToken} FOR {toAmount:d} {toToken}")

# Get user input, send to server
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

    rlp_encoded = rlp.encode(order)
    # TODO: Encrypt order with DKG Key
    ssl_sock.send(pickle.dumps(rlp_encoded))
    print("SENT: " + str(rlp_encoded))
    # Receive signature from state server
    resp = pickle.loads(ssl_sock.recv()) # TODO: Safe object loading
    print("RECV: " + str(resp))
    # Verify Signature
    hash = SHA256.new(str(rlp_encoded).encode('utf-8'))
    try:
        pkcs.verify(hash, resp)
        print("SIGNATURE OK!")
    except ValueError:
        print("SIGNATURE FAILED!!")


ssl_sock.close()