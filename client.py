import socket, ssl, pprint, pickle, sys
from ethereum import utils
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_v1_5
from Cryptodome.Hash import SHA256

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

# Get user input, send to server
while True:
    # Read input line, and send as RLP
    order = sys.stdin.readline()
    rlp_encoded = utils._encode_hex(order)
    # TODO: Encrypt order with DKG Key
    ssl_sock.send(pickle.dumps(rlp_encoded))
    print("SENT: " + rlp_encoded)
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