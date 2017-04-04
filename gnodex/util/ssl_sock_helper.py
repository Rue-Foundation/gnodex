"""
A module to help with reading from and writing to SSLSockets as some of the features
implemented in sockets have no SSLSocket counterpart, such as recvmsg().
"""

import ssl
import base64
import socket
from . import ssl_context

socket_buffer_dict = {}


def recv_ssl_msg(sock: ssl.SSLSocket, delimiter=b'\n'):
    if sock not in socket_buffer_dict.keys():
        socket_buffer_dict[sock] = bytearray()

    buff = socket_buffer_dict[sock]

    while True:
        data = sock.recv()
        buff.extend(data)
        if delimiter in data:
            break

    pos = buff.index(delimiter)
    res = buff[0:pos]
    del buff[0:pos+1]
    return base64.standard_b64decode(res)


def send_ssl_msg(sock: ssl.SSLSocket, msg, delimiter='\n'):
    data = base64.standard_b64encode(msg) + delimiter.encode('UTF-8')
    sock.send(data)


def ssl_connect(addr, cert):
    # Open SSL Connection
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    ssl_sock = ssl_context.wrap_client_socket(sock, cert)

    ssl_sock.connect(addr)

    return ssl_sock
