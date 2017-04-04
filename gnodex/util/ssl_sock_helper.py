"""
A module to help with reading from and writing to SSLSockets as some of the features
implemented in sockets have no SSLSocket counterpart, such as recvmsg().
"""

import ssl
import base64

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
