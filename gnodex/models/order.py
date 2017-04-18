import rlp
from rlp.sedes import raw, BigEndianInt


# TODO: Add security fields
class Order(rlp.Serializable):
    fields = [
        ('id', BigEndianInt(8)),
        ('buy_token', raw),
        ('buy_amount', BigEndianInt(8)),
        ('sell_token', raw),
        ('sell_amount', BigEndianInt(8)),
    ]


class SignedOrder(rlp.Serializable):
    fields = [
        ('order', Order),
        ('signature', raw),
    ]
