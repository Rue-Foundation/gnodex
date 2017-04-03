import rlp
from rlp.sedes import CountableList, BigEndianInt, raw
from .order import Order
from .crypto import Signature

class Batch(rlp.Serializable):
    fields = [
        ('round', BigEndianInt(8)),
        ('orders', CountableList(Order)),
    ]

class SignedBatch(rlp.Serializable):
    fields = [
        ('signatures', CountableList(Signature)),
        ('batch', Batch)
    ]
