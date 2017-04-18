import rlp
from rlp.sedes import CountableList, BigEndianInt, raw
from .crypto import Signature


class Route(rlp.Serializable):
    fields = [
        ('left_order', BigEndianInt(8)),
        ('left_amount', BigEndianInt(8)),
        ('right_order', BigEndianInt(8)),
    ]


class Matching(rlp.Serializable):
    fields = [
        ('routes', CountableList(Route)),
        ('batch_hash', raw)
    ]


class SignedMatching(rlp.Serializable):
    fields = [
        ('matching', Matching),
        ('signatures', CountableList(Signature))
    ]
