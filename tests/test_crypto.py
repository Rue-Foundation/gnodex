import os
import bitcoin
from gnodex.ecdkg import util
from gnodex.util import crypto


def test_can_decrypt_encrypted_random_messages():
    for _ in range(100):
        message = os.urandom(util.random.randrange(1, 100))
        deckey = util.random_private_value()
        enckey = bitcoin.fast_multiply(bitcoin.G, deckey)
        assert(message == crypto.decrypt(
            crypto.encrypt(message, enckey),
            deckey))
