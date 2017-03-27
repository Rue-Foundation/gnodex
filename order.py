import rlp
from rlp.sedes import raw, CountableList, BigEndianInt

class Order(rlp.Serializable):
    fields = [
        ('buyToken', raw),
        ('buyAmount', BigEndianInt(8)),
        ('sellToken', raw),
        ('sellAmount', BigEndianInt(8)),
    ]


class Batch(rlp.Serializable):
    fields = [
        ('orders', CountableList(Order)),
    ]
