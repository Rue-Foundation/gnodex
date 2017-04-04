import rlp
from rlp.sedes import raw, CountableList

class ChainLink(rlp.Serializable):
    fields = [
        ('value', raw),
        ('side', raw)
    ]

class Chain(rlp.Serializable):
    fields = [
        ('links', CountableList(ChainLink))
    ]
