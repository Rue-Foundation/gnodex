import rlp
from rlp.sedes import CountableList, BigEndianInt
from .order import Order

class Batch(rlp.Serializable):
    fields = [
        ('round', BigEndianInt(8)),
        ('orders', CountableList(Order)),
    ]
