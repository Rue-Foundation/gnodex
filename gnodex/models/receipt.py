import rlp
from rlp.sedes import raw, BigEndianInt

class Receipt(rlp.Serializable):
    fields = [
        ('round', BigEndianInt(8)),
        ('orderDigest', raw),
    ]

class SignedReceipt(rlp.Serializable):
    fields = [
        ('receipt', Receipt),
        ('signature', raw),
    ]
