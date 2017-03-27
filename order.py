import rlp
from rlp.sedes import raw, CountableList

class Order(rlp.Serializable):
    fields = [
        ('raw', raw),
    ]


class Batch(rlp.Serializable):
    fields = [
        ('orders', CountableList(Order)),
    ]
