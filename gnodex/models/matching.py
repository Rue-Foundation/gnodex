import rlp
from rlp.sedes import CountableList, BigEndianInt, raw
from .crypto import Signature, Commitment


class Route(rlp.Serializable):
    fields = [
        ('left_order', BigEndianInt(8)),
        ('left_amount', BigEndianInt(8)),
        ('right_order', BigEndianInt(8)),
    ]


class Matching(rlp.Serializable):
    fields = [
        ('routes', CountableList(Route)),
        ('signed_batch_hash', raw)
    ]


class SignedMatching(rlp.Serializable):
    fields = [
        ('matching', Matching),
        ('signature', Signature)
    ]


class MatchingCollection(rlp.Serializable):
    fields = [
        ('matchings', CountableList(SignedMatching)),
        ('commitment', Commitment),
    ]


class SignedMatchingCollection(rlp.Serializable):
    fields = [
        ('signatures', CountableList(Signature)),
        ('matching_collection', MatchingCollection),
    ]
