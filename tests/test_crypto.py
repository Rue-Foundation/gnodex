import os
import bitcoin
from gnodex.ecdkg import util
from gnodex.util import crypto


def test_can_decrypt_encrypted_random_messages(chain):
    ies, _ = chain.provider.get_or_deploy_contract('IntegratedEncryptionScheme')
    for _ in range(100):
        message = os.urandom(util.random.randrange(1, 100))
        deckey = util.random_private_value()
        enckey = bitcoin.fast_multiply(bitcoin.G, deckey)
        ciphertext = crypto.encrypt(message, enckey)
        assert message == crypto.decrypt(ciphertext, deckey)
        assert crypto.decrypt(ciphertext, deckey, foo=True) == ies.call().decrypt(ciphertext, deckey)
