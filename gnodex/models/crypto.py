import rlp
from rlp.sedes import raw, BigEndianInt


class Signature(rlp.Serializable):
    fields = [
        ('owner_id', raw),
        ('signature', raw),
    ]


class Commitment(rlp.Serializable):
    fields = [
        ('round', BigEndianInt(8)),
        ('merkle_root', raw),
    ]