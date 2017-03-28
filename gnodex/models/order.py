import rlp
from rlp.sedes import raw, BigEndianInt

class Order(rlp.Serializable):
    fields = [
        ('buyToken', raw),
        ('buyAmount', BigEndianInt(8)),
        ('sellToken', raw),
        ('sellAmount', BigEndianInt(8)),
    ]
