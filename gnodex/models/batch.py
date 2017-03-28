import rlp
from rlp.sedes import CountableList
from .order import Order

class Batch(rlp.Serializable):
    fields = [
        ('orders', CountableList(Order)),
    ]
