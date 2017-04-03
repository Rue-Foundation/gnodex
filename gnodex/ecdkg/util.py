import functools
import logging
import os
import re

import bitcoin
import sha3

try:
    from secrets import SystemRandom
    random = SystemRandom()
except ImportError:
    try:
        from random import SystemRandom
        random = SystemRandom()
    except ImportError:
        logging.warning('Could not obtain randomness source suitable for crypto')
        import random


def random_private_value() -> int:
    return random.randrange(bitcoin.N)


def validate_private_value(value: int):
    if value < 0 or value >= bitcoin.N:
        raise ValueError('invalid EC private value {}'.format(hex(value)))


def validate_polynomial(polynomial: int):
    for i, coeff in enumerate(polynomial):
        try:
            validate_private_value(coeff)
        except ValueError:
            raise ValueError('invalid x^{} coefficient {}'.format(i, hex(coeff)))


def validate_curve_point(point: (int, int)):
    if (any(coord < 0 or coord >= bitcoin.P for coord in point) or
        pow(point[1], 2, bitcoin.P) != (pow(point[0], 3, bitcoin.P) + 7) % bitcoin.P
       ) and point != (0, 0): # (0, 0) is used to represent group identity
        raise ValueError('invalid EC point {}'.format(point))


def validate_eth_address(addr: int):
    if addr < 0 or addr >= 2**160:
        raise ValueError('invalid Ethereum address {}'.format(hex(addr)))


def sequence_256_bit_values_to_bytes(sequence: tuple) -> bytes:
    return b''.join(map(functools.partial(int.to_bytes, length=32, byteorder='big'), sequence))


def curve_point_to_eth_address(curve_point: (int, int)) -> int:
    return int.from_bytes(sha3.keccak_256(sequence_256_bit_values_to_bytes(curve_point)).digest()[-20:], byteorder='big')


PRIVATE_VALUE_RE = re.compile(r'(?P<optprefix>0x)?(?P<value>[0-9A-Fa-f]{64})')
def get_or_generate_private_value(filepath: str) -> int:
    if os.path.isfile(filepath):
        with open(filepath) as private_key_fp:
            private_key_str = private_key_fp.read().strip()
            private_key_match = PRIVATE_VALUE_RE.fullmatch(private_key_str)
            if private_key_match:
                private_key = int(private_key_match.group('value'), 16)
                validate_private_value(private_key)
                return private_key

    logging.warn('could not read key from private key file {}; generating new value...'.format(filepath))
    with open(filepath, 'w') as private_key_fp:
        private_key = random_private_value()
        private_key_fp.write(hex(private_key)+'\n')
        return private_key


ADDRESS_RE = re.compile(r'(?P<optprefix>0x)?(?P<value>[0-9A-Fa-f]{40})')
def get_addresses(filepath: str) -> set:
    with open(filepath, 'r') as f:
        return set(int(m.group('value'), 16) for m in filter(lambda v: v is not None, (ADDRESS_RE.fullmatch(l.strip()) for l in f)))


LOCATION_RE = re.compile(r'(?P<hostname>[^:]*)(?::(?P<port>\d+))?')
DEFAULT_PORT = 80
def get_locations(filepath: str) -> list:
    with open(filepath, 'r') as f:
        return list((m.group('hostname'), int(m.group('port') or DEFAULT_PORT)) for m in filter(lambda v: v is not None, (LOCATION_RE.fullmatch(l.strip()) for l in f if not l.startswith('#'))))