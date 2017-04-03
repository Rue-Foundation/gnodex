import rlp
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509


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
