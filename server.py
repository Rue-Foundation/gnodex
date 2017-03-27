import socket, ssl, pickle

sock = socket.socket()
sock.bind(('', 31337))
sock.listen()

while True:
    newsock, addr = sock.accept()
    ssl_sock = ssl.wrap_socket(newsock,
                               server_side= True,
                               certfile='certs/server.crt',
                               keyfile='certs/server.key',
                               ssl_version=ssl.PROTOCOL_TLSv1_2)

    try:
        data = pickle.loads(ssl_sock.recv())
        print("INPUT: " + data)
    finally:
        ssl_sock.close()