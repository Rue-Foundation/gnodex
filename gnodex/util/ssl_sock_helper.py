"""
A module to help with reading from and writing to SSLSockets as some of the features
implemented in sockets have no SSLSocket counterpart, such as recvmsg().
"""

import ssl
import base64
import socket
import time
import select
from . import ssl_context

socket_buffer_dict = {}


def recv_ssl_msg(sock: ssl.SSLSocket, delimiter=b'\n'):
    if sock not in socket_buffer_dict.keys():
        socket_buffer_dict[sock] = bytearray()#('', 'UTF-8')

    buff = socket_buffer_dict[sock]

    while True:
        data = sock.recv()
        buff.extend(data)
        if not data:
            time.sleep(0.1)
        elif delimiter in data:
            break

    pos = buff.index(delimiter)
    res = buff[0:pos]
    del buff[0:pos+1]
    return base64.standard_b64decode(res)


def recv_ssl_msg_timeout(sock: ssl.SSLSocket, delimiter=b'\n', timeout = 2):
    if sock not in socket_buffer_dict.keys():
        socket_buffer_dict[sock] = bytearray()

    buff = socket_buffer_dict[sock]
    last = time.time()
    received = False

    sock.setblocking(False)
    sock.settimeout(timeout)
    while True:
        available = select.select([sock], [], [], timeout / 25)
        data = None
        if available[0]:
            data = bytearray()
            subdata = sock.recv()
            while subdata:
                data.extend(subdata)
                try:
                    subdata = sock.recv()
                except socket.timeout:
                    subdata = None

        if not data:
            if (time.time() - last > timeout):
                break
            continue

        last = time.time()
        buff.extend(data)
        if delimiter in buff:
            received = True
            break

    sock.setblocking(True)
    if not received:
        raise TimeoutError

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
