import bitcoin

from jsonrpc.dispatcher import Dispatcher

from . import ecdkg, util, db


class ProtocolError(Exception): pass


def create_dispatcher(address: int = None):
    dispatcher = Dispatcher()

    dispatcher['echo'] = lambda value: value


    @dispatcher.add_method
    def get_encryption_key(decryption_condition):
        decryption_condition = util.normalize_decryption_condition(decryption_condition)
        ecdkg_obj = db.Session.query(ecdkg.ECDKG).filter(ecdkg.ECDKG.decryption_condition == decryption_condition).scalar()
        if ecdkg_obj is None:
            raise ProtocolError('ECDKG protocol has not begun for decryption_condition')

        enckey = ecdkg_obj.public_key
        if enckey is None:
            raise ProtocolError('ECDKG public key has not been determined yet')

        return '{0[0]:064x}{0[1]:064x}'.format(enckey)


    @dispatcher.add_method
    def start_ecdkg(decryption_condition):
        decryption_condition = util.normalize_decryption_condition(decryption_condition)
        ecdkg_obj = (db.Session
            .query(ecdkg.ECDKG)
            .filter(ecdkg.ECDKG.decryption_condition == decryption_condition)
            .scalar())

        if ecdkg_obj is None:
            ecdkg_obj = ecdkg.ECDKG(decryption_condition=decryption_condition,
                                    alt_generator_part=bitcoin.fast_multiply(bitcoin.G, util.random_private_value()))
            db.Session.add(ecdkg_obj)
            db.Session.commit()


    @dispatcher.add_method
    def get_alt_generator_part(decryption_condition):
        decryption_condition = util.normalize_decryption_condition(decryption_condition)
        res = (db.Session
            .query(ecdkg.ECDKG.alt_generator_part)
            .filter(ecdkg.ECDKG.decryption_condition == decryption_condition)
            .scalar())

        if res is None:
            raise ProtocolError('ECDKG protocol has not begun for decryption_condition')

        return '{0[0]:064x}{0[1]:064x}'.format(res)


    if address is not None:
        @dispatcher.add_method
        def receive_share(share):
            print('got', share, 'from', address)

    return dispatcher
