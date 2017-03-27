import rlp
from rlp.sedes import raw

class Order(rlp.Serializable):
    fields =[
        ('raw', raw),
    ]
