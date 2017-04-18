import asyncio
import collections
import enum
import functools
import itertools
import logging
import math

import bitcoin

from . import db, util, networking


COMS_TIMEOUT = 10
THRESHOLD_FACTOR = .5
# NOTE: As soon as I end the python shell session that I created this in
#       and the RAM for that session gets reused, the scalar used to produce
#       this point probably won't come into existence again.
# TODO: reroll this point in dark ritual ala Zcash zkSNARK toxic waste thing
#       ... not that this parameter creates _much_ more security for this
#       protocol, but it's applicable and could be hilarious if you don't
#       believe the above note.
G2 = (0xb25b5ea8b8b230e5574fec0182e809e3455701323968c602ab56b458d0ba96bf,
      0x13edfe75e1c88e030eda220ffc74802144aec67c4e51cb49699d4401c122e19c)
util.validate_curve_point(G2)

secret_share_futures = collections.OrderedDict()
encryption_key_part_futures = collections.OrderedDict()


def random_polynomial(order: int) -> tuple:
    return tuple(util.random_private_value() for _ in range(order))


def eval_polynomial(poly: tuple, x: int) -> int:
    return sum(c * pow(x, k, bitcoin.N) for k, c in enumerate(poly)) % bitcoin.N


def generate_public_shares(poly1, poly2):
    if len(poly1) != len(poly2):
        raise ValueError('polynomial lengths must match ({} != {})'.format(len(poly1), len(poly2)))

    return (bitcoin.fast_add(bitcoin.fast_multiply(bitcoin.G, a), bitcoin.fast_multiply(G2, b)) for a, b in zip(poly1, poly2))


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
    encryption_key = db.Column(db.CurvePoint)
    decryption_key = db.Column(db.PrivateValue)
    participants = db.relationship('ECDKGParticipant', back_populates='ecdkg')

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
            ecdkg_obj = cls(decryption_condition=decryption_condition)
            db.Session.add(ecdkg_obj)
            db.Session.commit()

        return ecdkg_obj


    async def update_participants(self):
        state_futs = {}
        states = {}
        for addr, cinfo in networking.channels.items():
            state_futs[addr] = networking.make_jsonrpc_call(cinfo, 'get_ecdkg_state', self.decryption_condition)

        await asyncio.wait(state_futs.values(), timeout=COMS_TIMEOUT)

        for addr, state_fut in state_futs.items():
            if state_fut.done():
                try:
                    result = state_fut.result()
                except e:
                    logging.error(e)
                else:
                    states[addr] = result

        for addr, state in states.items():
            participant = self.get_or_create_participant_by_address(addr)
            participant.update_with_ecdkg_state_message(state)
            # TODO: make and handle complaints for bad state updates?


    async def handle_uninitialized_phase(self):
        await self.update_participants()
        # everyone should on agree on participants
        self.threshold = math.ceil(THRESHOLD_FACTOR * (len(self.participants)+1))

        spoly1 = random_polynomial(self.threshold)
        spoly2 = random_polynomial(self.threshold)

        self.secret_poly1 = spoly1
        self.secret_poly2 = spoly2

        self.verification_points = tuple(bitcoin.fast_add(bitcoin.fast_multiply(bitcoin.G, a), bitcoin.fast_multiply(G2, b)) for a, b in zip(spoly1, spoly2))

        self.phase = ECDKGPhase.key_distribution
        db.Session.commit()


    async def handle_key_distribution_phase(self):
        for participant in self.participants:
            address = participant.eth_address
            if address in networking.channels:
                cinfo = networking.channels[address]
                share1 = eval_polynomial(self.secret_poly1, address)
                share2 = eval_polynomial(self.secret_poly2, address)

                networking.make_jsonrpc_call(cinfo, 'receive_secret_shares',
                    self.decryption_condition,
                    '{:064x}'.format(share1),
                    '{:064x}'.format(share2),
                    is_notification = True)

        self.phase = ECDKGPhase.key_verification
        db.Session.commit()


    async def handle_key_verification_phase(self):
        global own_address

        await self.update_participants()
        await asyncio.wait([secret_share_futures[sfid] for sfid in ((self.id, p.eth_address) for p in self.participants) if sfid in secret_share_futures], timeout=COMS_TIMEOUT)

        for participant in self.participants:
            address = participant.eth_address
            share1 = participant.secret_share1
            share2 = participant.secret_share2
            if share1 is not None and share2 is not None:
                vlhs = bitcoin.fast_add(bitcoin.fast_multiply(bitcoin.G, share1),
                                        bitcoin.fast_multiply(G2, share2))
                vrhs = functools.reduce(bitcoin.fast_add, (bitcoin.fast_multiply(ps, pow(own_address, k, bitcoin.N)) for k, ps in enumerate(participant.verification_points)))

                if vlhs != vrhs:
                    # TODO: Produce complaints and continue instead of halting here
                    raise ProtocolError('verification of shares failed')
            else:
                raise ProtocolError('missing some shares')

        self.phase = ECDKGPhase.key_check
        db.Session.commit()


    async def handle_key_check_phase(self):
        # TODO: Track complaints and filter qualifying set

        self.phase = ECDKGPhase.key_generation
        db.Session.commit()


    async def handle_key_generation_phase(self):
        self.encryption_key_part = bitcoin.fast_multiply(bitcoin.G, self.secret_poly1[0])

        for participant in self.participants:
            address = participant.eth_address
            if address in networking.channels:
                cinfo = networking.channels[address]
                networking.make_jsonrpc_call(cinfo, 'receive_encryption_key_part',
                    self.decryption_condition,
                    '{0[0]:064x}{0[1]:064x}'.format(self.encryption_key_part),
                    is_notification = True)

        await asyncio.wait([encryption_key_part_futures[sfid] for sfid in ((self.id, p.eth_address) for p in self.participants) if sfid in encryption_key_part_futures], timeout=COMS_TIMEOUT)

        self.encryption_key = functools.reduce(bitcoin.fast_add,
            (p.encryption_key_part for p in self.participants), self.encryption_key_part)

        self.phase = ECDKGPhase.key_publication
        db.Session.commit()


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


    def to_state_message(self) -> dict:
        global own_address

        msg = {'address': '{:040x}'.format(own_address)}

        for attr in ('decryption_condition', 'phase', 'threshold'):
            val = getattr(self, attr)
            if val is not None:
                msg[attr] = val

        msg['participants'] = {'{:040x}'.format(p.eth_address): p.to_state_message() for p in self.participants}

        for attr in ('encryption_key', 'encryption_key_part'):
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

    encryption_key_part = db.Column(db.CurvePoint)
    decryption_key_part = db.Column(db.PrivateValue)
    verification_points = db.Column(db.CurvePointTuple)
    secret_share1 = db.Column(db.PrivateValue)
    secret_share2 = db.Column(db.PrivateValue)
    __table_args__ = (db.UniqueConstraint('ecdkg_id', 'eth_address'),)


    def to_state_message(self, address: int = None) -> dict:
        msg = {}

        for attr in ('encryption_key_part', 'verification_points'):
            val = getattr(self, attr)
            if val is not None:
                msg[attr] = '{0[0]:064x}{0[1]:064x}'.format(val)

        return msg


    def update_with_ecdkg_state_message(self, state: 'ECDKG state'):
        if 'encryption_key_part' in state:
            enc_key_part = tuple(int(state['encryption_key_part'][i:i+64], 16) for i in (0, 64))
            if getattr(self, 'encryption_key_part') not in (None, enc_key_part):
                logging.error('changing encryption key part!')
            self.encryption_key_part = enc_key_part

        if 'verification_points' in state:
            vpts = tuple(tuple(int(ptstr[i:i+64], 16) for i in (0, 64)) for ptstr in state['verification_points'])
            self.verification_points = vpts
            assert(tuple('{0[0]:064x}{0[1]:064x}'.format(pt) for pt in vpts) == tuple(state['verification_points']))
