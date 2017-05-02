import rlp
from rlp.sedes import CountableList
from .order import SignedOrder
from .crypto import Signature, Commitment


class Batch(rlp.Serializable):
    fields = [
        ('orders', CountableList(SignedOrder)),
        ('commitment', Commitment),
    ]


class SignedBatch(rlp.Serializable):
    fields = [
        ('signatures', CountableList(Signature)),
        ('batch', Batch)
    ]
