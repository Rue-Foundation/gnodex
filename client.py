import socket, ssl, pprint, pickle

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

ssl_sock = ssl.wrap_socket(sock,
                           ca_certs="certs/server.crt",
                           cert_reqs=ssl.CERT_REQUIRED,
                           ssl_version=ssl.PROTOCOL_TLSv1_2)

ssl_sock.connect(('localhost', 31337))

print(ssl_sock.getpeername())
print(pprint.pformat(ssl_sock.getpeercert()))
print(ssl_sock.cipher())


ssl_sock.send(pickle.dumps("Test"))

ssl_sock.close()