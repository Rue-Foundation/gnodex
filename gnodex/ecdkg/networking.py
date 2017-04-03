import asyncio
import collections
import datetime
import json
import logging
import os
import ssl
import tempfile

import bitcoin

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from . import util, ecdkg


DEFAULT_TIMEOUT = 120

class NetworkingError(Exception): pass
ChannelInfo = collections.namedtuple('ChannelInfo', ('reader', 'writer'))

ssl_context = None
channels = {}


def set_ssl_using_key(private_key: int) -> ssl.SSLContext:
    global ssl_context

    private_key_obj = ec.derive_private_key(private_key, ec.SECP256K1(), default_backend())

    certificate = x509.CertificateBuilder(
        ).subject_name(x509.Name([])
        ).issuer_name(x509.Name([])
        ).serial_number(x509.random_serial_number()
        ).not_valid_before(datetime.datetime.utcnow()
        ).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10000)
        ).public_key(private_key_obj.public_key()
        ).sign(private_key_obj, hashes.SHA256(), default_backend())

    certificate_tempfile = tempfile.NamedTemporaryFile(delete=False)
    private_key_tempfile = tempfile.NamedTemporaryFile(delete=False)

    certificate_tempfile.write(certificate.public_bytes(serialization.Encoding.PEM))
    priv_key_byte_count = private_key_tempfile.write(private_key_obj.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption()))

    certificate_tempfile.close()
    private_key_tempfile.close()

    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(certificate_tempfile.name, private_key_tempfile.name)

    with open(private_key_tempfile.name, 'wb') as f:
        f.write(os.urandom(priv_key_byte_count)) # shred

    os.remove(certificate_tempfile.name)
    os.remove(private_key_tempfile.name)

    ssl_context.set_ciphers(':'.join(cipher['name'] for cipher in ssl_context.get_ciphers() if cipher['name'].startswith('ECDHE-ECDSA')))


def get_public_key_from_ssl_socket(sslsocket: ssl.SSLSocket) -> (int, int):
    pubnums = x509.load_der_x509_certificate(sslsocket.getpeercert(binary_form=True), default_backend()).public_key().public_numbers()
    point = (pubnums.x, pubnums.y)
    util.validate_curve_point(point)
    return point


async def json_lines_with_timeout(reader: asyncio.StreamReader, timeout: 'seconds' = DEFAULT_TIMEOUT):
    while not reader.at_eof():
        try:
            yield json.loads(await asyncio.wait_for(reader.readline(), timeout))
        except json.JSONDecodeError as e:
            pass


async def establish_channel(eth_address: int, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    if eth_address in channels:
        logging.warn('channel for {} already exists; closing existing channel...'.format(hex(eth_address)))
        channels[eth_address].writer.close()

    logging.info('establishing channel for {}'.format(hex(eth_address)))
    channels[eth_address] = ChannelInfo(reader=reader, writer=writer)

    try:
        async for obj in json_lines_with_timeout(reader):
            logging.info('received message {} from {}'.format(obj, eth_address))
    except asyncio.TimeoutError:
        logging.warn('channel for {} timed out'.format(hex(eth_address)))
        del channels[eth_address]
    finally:
        logging.info('closing channel for {}'.format(hex(eth_address)))
        writer.close()


################################################################################

async def server(host: str, port: int, *,
                 loop: asyncio.AbstractEventLoop):
    logging.info('(s) serving on {}:{}'.format(host, port))
    async def thing():
        await asyncio.sleep(5.0)
        for addr, info in channels.items():
            info.writer.write(b'{"foo": "bar"}\n')

    loop.create_task(thing())

    await asyncio.start_server(handle_connection,
                               host, port, ssl=ssl_context, loop=loop)


async def handle_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, timeout: 'seconds' = DEFAULT_TIMEOUT):
    logging.info('(s) new connection...')

    nonce = util.random.randrange(2**256)
    noncebytes = nonce.to_bytes(32, byteorder='big')
    logging.debug('(s) sending nonce {}'.format(hex(nonce)))
    writer.write(nonce.to_bytes(32, byteorder='big'))

    rsv_bytes = await asyncio.wait_for(reader.read(65), timeout)
    r, s, v = (int.from_bytes(b, byteorder='big') for b in (rsv_bytes[0:32], rsv_bytes[32:64], rsv_bytes[64:]))
    logging.debug('(s) received signature rsv {}'.format(tuple(map(hex, (r, s, v)))))

    try:
        clipubkey = bitcoin.ecdsa_raw_recover(noncebytes, (v, r, s))
    except ValueError:
        clipubkey = False # I would have used None here but pybitcointools uses False for malformed signatures

    if clipubkey:
        cliethaddr = util.curve_point_to_eth_address(clipubkey)
        logging.debug('(s) got client address: {}'.format(hex(cliethaddr)))
    else:
        cliethaddr = None

    if cliethaddr is None:
        logging.debug('(s) could not verify client signature; closing connection')
        writer.close()
        return

    if cliethaddr not in ecdkg.accepted_addresses:
        logging.info('(s) client address {} not accepted'.format(hex(cliethaddr)))
        writer.close()
        return

    await establish_channel(cliethaddr, reader, writer)


################################################################################

async def attempt_to_establish_channel(host: str, port: int, *,
                                       timeout: 'seconds' = DEFAULT_TIMEOUT,
                                       num_tries: int = 6):
    logging.info('(c) attempting to connect to {}:{}'.format(host, port))
    for i in range(num_tries):
        try:
            reader, writer = await asyncio.open_connection(host, port, ssl=ssl_context)
        except OSError as e:
            if e.errno == 111 or '[Errno 111]' in str(e): # connection refused
                wait_time = 5 * 2**i
                logging.warning('(c) connection to {}:{} refused; trying again in {}s'.format(host, port, wait_time))
                await asyncio.sleep(wait_time)
            else:
                raise
        else:
            break
    else:
        raise NetworkingError('Could not connect to {}:{} after {} tries'.format(host, port, num_tries))

    sslsocket = writer.get_extra_info('ssl_object')
    logging.debug('(c) socket cipher: {}'.format(sslsocket.cipher()))
    srvpubkey = get_public_key_from_ssl_socket(sslsocket)
    srvethaddr = util.curve_point_to_eth_address(srvpubkey)
    logging.debug('(c) server eth address: {}'.format(hex(srvethaddr)))
    if srvethaddr not in ecdkg.accepted_addresses:
        logging.info('(c) server eth address {} not accepted'.format(hex(srvethaddr)))
        writer.close()
        return

    noncebytes = await asyncio.wait_for(reader.read(32), timeout)
    nonce = int.from_bytes(noncebytes, byteorder='big')
    logging.debug('(c) got nonce: {}'.format(hex(nonce)))

    v, r, s = bitcoin.ecdsa_raw_sign(noncebytes, ecdkg.private_key)
    logging.debug('(c) sending nonce signature rsv {}'.format(tuple(map(hex, (r, s, v)))))
    writer.write(r.to_bytes(32, 'big') + s.to_bytes(32, 'big') + v.to_bytes(1, 'big'))

    await establish_channel(srvethaddr, reader, writer)
