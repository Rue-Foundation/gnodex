import socket, ssl, pickle, _thread
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_v1_5
from Cryptodome.Hash import SHA256

# Start listening for connections
sock = socket.socket()
sock.bind(('', 31337))
sock.listen()

# Load private key for signatures
key = RSA.import_key(open('certs/server.key', 'rb').read())

# One thread per client
def handle_client(sock, addr):
    pkcs = PKCS1_v1_5.new(key) # TODO: Check if this object is thread-safe
    ssl_sock = ssl.wrap_socket(sock,
                               server_side= True,
                               certfile='certs/server.crt',
                               keyfile='certs/server.key',
                               ssl_version=ssl.PROTOCOL_TLSv1_2)
    # Wait for input, and respond
    while True:
        data = pickle.loads(ssl_sock.recv()) # TODO: Safe object loading
        print("INPUT: " + data)
        # Hash and sign
        hash = SHA256.new(str(data).encode('utf-8'))
        resp = pkcs.sign(hash)
        ssl_sock.send(pickle.dumps(resp))
        print("RESP: " + str(resp))

# Accept connections and start handling them in own thread
while True:
    newsock, addr = sock.accept()
    _thread.start_new_thread(handle_client, (newsock, addr))