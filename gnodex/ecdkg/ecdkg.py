import asyncio
import collections
import enum
import functools
import itertools
import logging

import bitcoin

from . import db, util


COMS_TIMEOUT = .5
THRESHOLD_FACTOR = .5

secret_share_futures = collections.OrderedDict()
encryption_key_part_futures = collections.OrderedDict()


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
    encryption_key = db.Column(db.CurvePoint)
    decryption_key = db.Column(db.PrivateValue)
    participants = db.relationship('ECDKGParticipant', back_populates='ecdkg')

    alt_generator_part = db.Column(db.CurvePoint)
    secret_poly1 = db.Column(db.Polynomial)
    secret_poly2 = db.Column(db.Polynomial)
    verification_points = db.Column(db.CurvePointTuple)
    encryption_key_part = db.Column(db.CurvePoint)


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

        sfid = (self.id, address)

        if sfid not in secret_share_futures:
            secret_share_futures[sfid] = asyncio.Future()
            if (participant.secret_share1 is not None and
                participant.secret_share2 is not None):
                secret_share_futures[sfid].set_result((participant.secret_share1, participant.secret_share2))

        if sfid not in encryption_key_part_futures:
            encryption_key_part_futures[sfid] = asyncio.Future()
            if participant.encryption_key_part is not None:
                encryption_key_part_futures[sfid].set_result(participant.encryption_key_part)

        return participant


    def to_state_message(self, address: int = None) -> dict:
        global own_address

        msg = {'address': '{:040x}'.format(own_address)}

        for attr in ('decryption_condition', 'phase', 'threshold'):
            val = getattr(self, attr)
            if val is not None:
                msg[attr] = val

        msg['participants'] = {'{:040x}'.format(p.eth_address): p.to_state_message() for p in self.participants}

        for attr in ('alt_generator', 'encryption_key', 'alt_generator_part', 'encryption_key_part'):
            val = getattr(self, attr)
            if val is not None:
                msg[attr] = '{0[0]:064x}{0[1]:064x}'.format(val)

        vpts = self.verification_points
        if vpts is not None:
            msg['verification_points'] = tuple('{0[0]:064x}{0[1]:064x}'.format(pt) for pt in vpts)

        return msg


class ECDKGParticipant(db.Base):
    ecdkg_id = db.Column(db.Integer, db.ForeignKey('ecdkg.id'))
    ecdkg = db.relationship('ECDKG', back_populates='participants')
    eth_address = db.Column(db.EthAddress, index=True)

    alt_generator_part = db.Column(db.CurvePoint)
    encryption_key_part = db.Column(db.CurvePoint)
    decryption_key_part = db.Column(db.PrivateValue)
    verification_points = db.Column(db.CurvePointTuple)
    secret_share1 = db.Column(db.PrivateValue)
    secret_share2 = db.Column(db.PrivateValue)
    __table_args__ = (db.UniqueConstraint('ecdkg_id', 'eth_address'),)


    def to_state_message(self, address: int = None) -> dict:
        msg = {}

        for attr in ('alt_generator_part', 'encryption_key_part', 'verification_points'):
            val = getattr(self, attr)
            if val is not None:
                msg[attr] = '{0[0]:064x}{0[1]:064x}'.format(val)

        return msg


    def update_with_ecdkg_state_message(self, state: 'ECDKG state'):
        if 'alt_generator_part' in state:
            altgenpt = tuple(int(state['alt_generator_part'][i:i+64], 16) for i in (0, 64))
            if getattr(self, 'alt_generator_part') not in (None, altgenpt):
                logging.error('changing participant alt generator part!')
            self.alt_generator_part = altgenpt

        if 'encryption_key_part' in state:
            enc_key_part = tuple(int(state['encryption_key_part'][i:i+64], 16) for i in (0, 64))
            if getattr(self, 'encryption_key_part') not in (None, enc_key_part):
                logging.error('changing encryption key part!')
            self.encryption_key_part = enc_key_part

        if 'verification_points' in state:
            vpts = tuple(tuple(int(ptstr[i:i+64], 16) for i in (0, 64)) for ptstr in state['verification_points'])
            self.verification_points = vpts
            assert(tuple('{0[0]:064x}{0[1]:064x}'.format(pt) for pt in vpts) == tuple(state['verification_points']))
