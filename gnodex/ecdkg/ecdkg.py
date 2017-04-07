import enum
import functools
import itertools
import logging

import bitcoin

from . import db, util


def random_polynomial(order: int) -> tuple:
    return tuple(util.random_private_value() for _ in range(order))


def eval_polynomial(poly: tuple, x: int) -> int:
    return sum(c * pow(x, k, bitcoin.N) for k, c in enumerate(poly)) % bitcoin.N


def generate_public_shares(alt_generator, poly1, poly2):
    util.validate_curve_point(alt_generator)

    if len(poly1) != len(poly2):
        raise ValueError('polynomial lengths must match ({} != {})'.format(len(poly1), len(poly2)))

    return (bitcoin.fast_add(bitcoin.fast_multiply(bitcoin.G, a), bitcoin.fast_multiply(alt_generator, b)) for a, b in zip(poly1, poly2))


@enum.unique
class ECDKGPhase(enum.IntEnum):
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


    @classmethod
    def get_or_create_by_decryption_condition(cls, decryption_condition: str) -> 'ECDKG':
        decryption_condition = util.normalize_decryption_condition(decryption_condition)
        ecdkg_obj = (db.Session
            .query(cls)
            .filter(cls.decryption_condition == decryption_condition)
            .scalar())

        if ecdkg_obj is None:
            ecdkg_obj = cls(decryption_condition=decryption_condition,
                            alt_generator_part=bitcoin.fast_multiply(bitcoin.G, util.random_private_value()))
            db.Session.add(ecdkg_obj)
            db.Session.commit()

        return ecdkg_obj


    def get_or_create_participant_by_address(self, address: int) -> 'ECDKGParticipant':
        participant = (db.Session
            .query(ECDKGParticipant)
            .filter(ECDKGParticipant.ecdkg_id == self.id,
                    ECDKGParticipant.eth_address == address)
            .scalar())

        if participant is None:
            participant = ECDKGParticipant(ecdkg_id=self.id, eth_address=address)
            db.Session.add(participant)
            db.Session.commit()

        return participant


    def to_state_message(self, address: int = None) -> dict:
        msg = { attr: getattr(self, attr) for attr in ('decryption_condition', 'phase', 'threshold') }
        msg['participants'] = {'{:040x}'.format(int.from_bytes(p.eth_address, byteorder='big')): p.to_state_message() for p in self.participants}
        return msg


class ECDKGParticipant(db.Base):
    ecdkg_id = db.Column(db.Integer, db.ForeignKey('ecdkg.id'))
    ecdkg = db.relationship('ECDKG', back_populates='participants')
    eth_address = db.Column(db.EthAddress, index=True)

    alt_generator_part = db.Column(db.CurvePoint)
    public_key_share = db.Column(db.CurvePoint)
    verification_shares = db.Column(db.CurvePointTuple)
    secret_share1 = db.Column(db.PrivateValue)
    secret_share2 = db.Column(db.PrivateValue)
    __table_args__ = (db.UniqueConstraint('ecdkg_id', 'eth_address'),)


    def to_state_message(self, address: int = None) -> dict:
        msg = { attr: getattr(self, attr) for attr in ('alt_generator_part', 'public_key_share', 'verification_shares') }
        return msg
