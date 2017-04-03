import rlp
from rlp.sedes import raw


class Signature(rlp.Serializable):
    fields = [
        ('owner_id', raw),
        ('signature', raw),
    ]
