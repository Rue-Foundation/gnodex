import enum
import functools
import itertools
import logging

import bitcoin

from . import db
from .util import random, random_private_value

# TODO: Blind this in the protocol
G2 = bitcoin.fast_multiply(bitcoin.G, random.randrange(bitcoin.N))


def random_polynomial(order: int) -> tuple:
    return tuple(random_private_value() for _ in range(order))


def eval_polynomial(poly: tuple, x: int) -> int:
    return sum(c * pow(x, k, bitcoin.N) for k, c in enumerate(poly)) % bitcoin.N


def generate_public_shares(alt_generator, poly1, poly2):
    util.validate_curve_point(alt_generator)

    if len(poly1) != len(poly2):
        raise ValueError('polynomial lengths must match ({} != {})'.format(len(poly1), len(poly2)))

    return (bitcoin.fast_add(bitcoin.fast_multiply(bitcoin.G, a), bitcoin.fast_multiply(alt_generator, b)) for a, b in zip(poly1, poly2))



class ECDKGPhase(enum.Enum):
    uninitialized = 0
    key_distribution = 1
    key_verification = 2
    key_check = 3
    key_generation = 4
    key_publication = 5


class ECDKG(db.Base):
    decryption_condition = db.Column(db.String(32), index=True, unique=True)
    phase = db.Column(db.Enum(ECDKGPhase), nullable=False, default=ECDKGPhase.uninitialized)
    threshold = db.Column(db.Integer)
    alt_generator = db.Column(db.CurvePoint)
    public_key = db.Column(db.CurvePoint)
    participants = db.relationship('ECDKGParticipant', back_populates='ecdkg')

    alt_generator_part = db.Column(db.CurvePoint)
    secret_poly1 = db.Column(db.Polynomial)
    secret_poly2 = db.Column(db.Polynomial)
    public_key_share = db.Column(db.CurvePoint)


class ECDKGParticipant(db.Base):
    ecdkg_id = db.Column(db.Integer, db.ForeignKey('ecdkg.id'))
    ecdkg = db.relationship('ECDKG', back_populates='participants')
    eth_address = db.Column(db.EthAddress, index=True)
    public_key_share = db.Column(db.CurvePoint)
    verification_shares = db.Column(db.CurvePointTuple)
    secret_share1 = db.Column(db.PrivateValue)
    secret_share2 = db.Column(db.PrivateValue)
