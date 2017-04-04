import rlp
from rlp.sedes import CountableList, BigEndianInt, raw
from .order import Order, SignedOrder
from .crypto import Signature


class BatchCommitment(rlp.Serializable):
    fields = [
        ('round', BigEndianInt(8)),
        ('merkle_root', raw),
    ]


class Batch(rlp.Serializable):
    fields = [
        ('orders', CountableList(SignedOrder)),
        ('commitment', BatchCommitment),
    ]


class SignedBatch(rlp.Serializable):
    fields = [
        ('signatures', CountableList(Signature)),
        ('batch', Batch)
    ]
