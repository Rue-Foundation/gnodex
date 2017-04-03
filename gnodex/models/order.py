import rlp
from rlp.sedes import raw, BigEndianInt


class Order(rlp.Serializable):
    fields = [
        ('buy_token', raw),
        ('buy_amount', BigEndianInt(8)),
        ('sell_token', raw),
        ('sell_amount', BigEndianInt(8)),
    ]
