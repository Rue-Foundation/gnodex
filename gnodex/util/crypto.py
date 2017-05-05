import bitcoin
import rlp
import sha3
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from ..ecdkg import util

def load_public_cert_key(cert_file_path):
    with open(cert_file_path, 'rb') as cert_file:
        cert = x509.load_pem_x509_certificate(
            data=cert_file.read(),
            backend=default_backend())
        return cert.public_key()


def load_private_key(key_file_path):
    with open(key_file_path, 'rb') as key_file:
        return serialization.load_pem_private_key(
            data=key_file.read(),
            password=None,
            backend=default_backend())


def load_public_key(key_file_path):
    with open(key_file_path, 'rb') as key_file:
        return serialization.load_pem_public_key(
            data=key_file.read(),
            backend=default_backend())


def sha256_utf8(data):
    digest = hashes.Hash(algorithm=hashes.SHA256(), backend=default_backend())
    digest.update(str(data).encode('UTF-8'))
    return digest.finalize()


def sign(private_key, message):
    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256())


def sign_rlp(private_key, message):
    return sign(private_key, rlp.encode(message))


def verify(public_key, message, signature):
    return public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256())


def encrypt(message: bytes, enckey: (int, int)) -> bytes:
    # This is an implementation of ECIES
    # https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme
    util.validate_curve_point(enckey)
    r = util.random_private_value()
    R = bitcoin.fast_multiply(bitcoin.G, r)
    S = bitcoin.fast_multiply(enckey, r)
    kEkM = sha3.keccak_256(S[0].to_bytes(32, byteorder='big')).digest()
    kE, kM = kEkM[0:16], kEkM[16:32]

    # Use CTR mode to do encryption 256 bits at a time
    # https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CTR
    num_trunc_bytes = (32 - len(message)) % 32
    iv = util.random.randrange(2**256).to_bytes(32, byteorder='big')
    num_chunks = len(message) // 32 + (1 if num_trunc_bytes > 0 else 0)
    c = b''.join((
            int.from_bytes(message[32*i:32*(i+1)].ljust(32, b'\0'), 'big') ^
            int.from_bytes(sha3.keccak_256(iv + i.to_bytes(32, 'big') + kE).digest(), 'big')
        ).to_bytes(32, byteorder='big') for i in range(num_chunks))


    # Quote from http://keccak.noekeon.org/:
    # Unlike SHA-1 and SHA-2, Keccak does not have the length-extension weakness,
    # hence does not need the HMAC nested construction. Instead, MAC computation
    # can be performed by simply prepending the message with the key.
    d = sha3.keccak_256(kM + message).digest()
    return (b''.join(x.to_bytes(32, byteorder='big') for x in R) + # 64 byte ephemeral key
            bytes((num_trunc_bytes,)) + # 1 byte truncation descriptor
            iv + # 32 byte initialization vector
            c + # arbitrary length 32 byte aligned enciphered message
            d) # 32 byte message authentication code (MAC)


def decrypt(ciphertext: bytes, deckey: int, foo=False) -> bytes:
    util.validate_private_value(deckey)
    R = tuple(int.from_bytes(ciphertext[i:i+32], byteorder='big') for i in (0, 32))
    util.validate_curve_point(R)
    S = bitcoin.fast_multiply(R, deckey)
    num_trunc_bytes = ord(ciphertext[64:65])
    iv = ciphertext[65:97]
    c = ciphertext[97:-32]

    if len(c) % 32 != 0:
        raise ValueError('enciphered message not properly aligned')

    kEkM = sha3.keccak_256(S[0].to_bytes(32, byteorder='big')).digest()
    kE, kM = kEkM[0:16], kEkM[16:32]

    num_chunks = len(c) // 32
    message = b''.join((
            int.from_bytes(c[32*i:32*(i+1)], 'big') ^
            int.from_bytes(sha3.keccak_256(iv + i.to_bytes(32, 'big') + kE).digest(), 'big')
        ).to_bytes(32, byteorder='big') for i in range(num_chunks))

    if num_trunc_bytes > 0:
        message, padding = message[:-num_trunc_bytes], message[-num_trunc_bytes:]

        if padding != b'\0' * num_trunc_bytes:
            raise ValueError('invalid padding')

    d = ciphertext[-32:]
    if d != sha3.keccak_256(kM + message).digest():
        raise ValueError('message authentication code does not match')

    if foo:
        return int.from_bytes(sha3.keccak_256(message).digest(), 'big')

    return message
