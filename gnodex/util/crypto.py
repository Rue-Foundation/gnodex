import rlp
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_v1_5
from Cryptodome.Hash import SHA256


def sha256_utf8(data):
    return SHA256.new(str(data).encode('UTF-8'))


def sign(pkcs, data):
    data_signature = pkcs.sign(sha256_utf8(data))
    return data_signature


def sign_rlp(pkcs, data):
    return sign(pkcs, rlp.encode(data))
